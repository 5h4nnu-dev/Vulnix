/**
 * Regression tests for the deterministic-mode improvements:
 *   - static-page detection skips the injection battery (huge request savings),
 *   - reflection-sink guards prevent classic XSS false positives
 *     (JSON echoes, HTML comments, quoted attributes, non-executable tokens),
 *   - error-based SQLi requires the payload fragment to appear near the error,
 *   - client-side open redirect requires the user value to reach an external
 *     redirect sink,
 *   - per-scan request budget stops runaway scans.
 */

const http = require('http');

jest.mock('../database', () => {
    const run = jest.fn();
    const insertVulnRun = jest.fn();
    return {
        db: { prepare: () => ({ run: jest.fn(), get: jest.fn(), all: jest.fn(() => []) }), pragma: jest.fn(), exec: jest.fn() },
        stmts: {
            insertScan: { run },
            getScan: { get: jest.fn() },
            listScans: { all: jest.fn(() => []) },
            countScans: { get: jest.fn(() => ({ count: 0 })) },
            updateScanProgress: { run },
            updateScanStatus: { run },
            updateScanRunning: { run },
            completeScan: { run },
            failScan: { run },
            deleteScan: { run },
            insertVuln: { run: insertVulnRun },
            getVulns: { all: jest.fn(() => []) },
            updateVulnAi: { run },
            insertEvent: { run },
            getEvents: { all: jest.fn(() => []) },
            insertAiPayload: { run },
            getAiPayloads: { all: jest.fn(() => []) },
            insertPiTest: { run },
            getPiTests: { all: jest.fn(() => []) },
            insertAgentStep: { run },
            getAgentSteps: { all: jest.fn(() => []) },
            statsSummary: { get: jest.fn(() => ({})) },
            topVulnTypes: { all: jest.fn(() => []) },
            recentScans: { all: jest.fn(() => []) },
            recentVulns: { all: jest.fn(() => []) },
        },
    };
});

const { stmts } = require('../database');
const scanner = require('../scanner');
const { runRecon, classifyContentType, extractFormParams } = require('../recon');

jest.setTimeout(30000);

function textResponse(body, status = 200, contentType = null) {
    return {
        status,
        headers: { get: (name) => (name === 'content-type' ? contentType : null) },
        text: async () => body,
    };
}

function found(type) {
    return stmts.insertVuln.run.mock.calls.map((c) => c[0]).find((v) => v.type === type);
}

function startServer(handler) {
    return new Promise((resolve) => {
        const server = http.createServer(handler);
        server.listen(0, '127.0.0.1', () => {
            const port = server.address().port;
            resolve({
                server,
                port,
                url: `http://127.0.0.1:${port}`,
                requests: 0,
                close: () => new Promise((r) => server.close(r)),
            });
        });
    });
}

const STATIC_BODY = `<!DOCTYPE html><html><head><title>Static Corp</title></head><body>
<h1>Static marketing page</h1><p>Nothing dynamic happens here.</p>
</body></html>`;

describe('reflection-sink guards', () => {
    const origFetch = global.fetch;
    afterEach(() => { global.fetch = origFetch; stmts.insertVuln.run.mockClear(); });

    it('hasExecutableXssToken accepts only HTML-executable payloads', () => {
        expect(scanner.hasExecutableXssToken('<script>alert(1)</script>')).toBe(true);
        expect(scanner.hasExecutableXssToken('<img src=x onerror=alert(1)>')).toBe(true);
        expect(scanner.hasExecutableXssToken("'> <svg/onload=alert(1)>")).toBe(true);
        expect(scanner.hasExecutableXssToken('<b>bold text</b>')).toBe(false);
        expect(scanner.hasExecutableXssToken('just some words')).toBe(false);
    });

    it('isInsideHtmlComment detects comment-internal reflection', () => {
        const body = '<html><body><!-- TODO: <script>alert(1)</script> --><p>ok</p></body></html>';
        expect(scanner.isInsideHtmlComment(body, body.indexOf('<script>'))).toBe(true);
        expect(scanner.isInsideHtmlComment('<p>Hello <script>x</script></p>', '<p>Hello <script>x</script></p>'.indexOf('<script>'))).toBe(false);
    });

    it('isInsideQuotedAttribute detects inert attribute reflection', () => {
        const inAttr = '<input value="<script>alert(1)</script>">';
        const idx = inAttr.indexOf('<script>');
        expect(scanner.isInsideQuotedAttribute(inAttr, idx, '<script>alert(1)</script>')).toBe(true);
        // A payload that contains the quote can break out → not inert.
        expect(scanner.isInsideQuotedAttribute(inAttr, idx, '"><script>alert(1)</script>')).toBe(false);
        // Plain element-content reflection is not inside an attribute.
        expect(scanner.isInsideQuotedAttribute('<body><p>Hi <script>x</script>', '<body><p>Hi <script>x</script>'.indexOf('<script>'), '<script>x</script>')).toBe(false);
        // Regression: an unpaired apostrophe in prose must not be mistaken for
        // an open attribute quote (this used to suppress genuine XSS).
        const prose = "<html><body>It's a fine day <script>alert(1)</script></body></html>";
        expect(scanner.isInsideQuotedAttribute(prose, prose.indexOf('<script>'), '<script>alert(1)</script>')).toBe(false);
    });

    it('does not flag XSS when the payload is only reflected in JSON', async () => {
        global.fetch = jest.fn(async () => textResponse('{"echo":"<script>alert(1)</script>"}', 200, 'application/json'));
        await scanner.checkXss('t-json', 'http://target.test/?q=1', ['<script>alert(1)</script>']);
        expect(stmts.insertVuln.run).not.toHaveBeenCalled();
    });

    it('does not flag XSS reflected inside an HTML comment', async () => {
        global.fetch = jest.fn(async () => textResponse('<html><body><!-- <script>alert(1)</script> --></body></html>'));
        await scanner.checkXss('t-comment', 'http://target.test/?q=1', ['<script>alert(1)</script>']);
        expect(stmts.insertVuln.run).not.toHaveBeenCalled();
    });

    it('does not flag XSS reflected inside a quoted attribute without breakout', async () => {
        global.fetch = jest.fn(async () => textResponse('<input type="text" value="<script>alert(1)</script>">'));
        await scanner.checkXss('t-attr', 'http://target.test/?q=1', ['<script>alert(1)</script>']);
        expect(stmts.insertVuln.run).not.toHaveBeenCalled();
    });

    it('does not flag non-executable HTML text reflection', async () => {
        global.fetch = jest.fn(async () => textResponse('<html><body><b>hello</b></body></html>'));
        await scanner.checkXss('t-text', 'http://target.test/?q=1', ['<b>hello</b>']);
        expect(stmts.insertVuln.run).not.toHaveBeenCalled();
    });

    it('flags a genuine executable sink reflection', async () => {
        global.fetch = jest.fn(async () => textResponse('<html><body>Hello <script>alert(1)</script></body></html>'));
        await scanner.checkXss('t-real', 'http://target.test/?q=1', ['<script>alert(1)</script>']);
        const f = found('xss');
        expect(f).toBeDefined();
        expect(f.severity).toBe('high');
    });

    it('flags XSS when prose before the sink contains an apostrophe', async () => {
        global.fetch = jest.fn(async () => textResponse("<html><body>It's a search result <script>alert(1)</script></body></html>"));
        await scanner.checkXss('t-apostrophe', 'http://target.test/?q=1', ['<script>alert(1)</script>']);
        expect(found('xss')).toBeDefined();
    });
});

describe('error-based SQLi requires echoed payload', () => {
    const origFetch = global.fetch;
    afterEach(() => { global.fetch = origFetch; stmts.insertVuln.run.mockClear(); });

    it('does not flag an SQL error that does not echo the payload', async () => {
        global.fetch = jest.fn(async () => textResponse('generic sql syntax error near nothing injected'));
        await scanner.checkSqlInjection('t-noecho', 'http://target.test/?id=1', 5, ["'"], { baselineBody: '<html><body>search results page</body></html>' });
        expect(stmts.insertVuln.run).not.toHaveBeenCalled();
    });

    it('flags an SQL error that echoes the payload fragment', async () => {
        global.fetch = jest.fn(async () => textResponse("You have an error in your SQL syntax near '' at line 1"));
        await scanner.checkSqlInjection('t-echo', 'http://target.test/?id=1', 5, ["'"], { baselineBody: '<html><body>search results page</body></html>' });
        const f = found('sql_injection');
        expect(f).toBeDefined();
        expect(f.severity).toBe('critical');
    });
});

describe('client-side open redirect', () => {
    const origFetch = global.fetch;
    afterEach(() => { global.fetch = origFetch; stmts.insertVuln.run.mockClear(); });

    it('extractRedirectSinks parses meta-refresh and location sinks', () => {
        const body = '<meta http-equiv="refresh" content="0; url=//evil.com">' +
            '<script>window.location = "/local"; window.location.href = "https://evil.com/x";</script>';
        const sinks = scanner.extractRedirectSinks(body);
        expect(sinks).toContain('//evil.com');
        expect(sinks).toContain('/local');
        expect(sinks).toContain('https://evil.com/x');
    });

    it('flags a client-side redirect that reflects the user payload', async () => {
        global.fetch = jest.fn(async () => textResponse('<meta http-equiv="refresh" content="0; url=//evil.com">'));
        await scanner.checkOpenRedirect('t-redir-pos', 'http://target.test/?next=1');
        const f = found('open_redirect');
        expect(f).toBeDefined();
        expect(f.severity).toBe('medium');
    });

    it('does not flag client-side redirects that ignore the parameter', async () => {
        global.fetch = jest.fn(async () => textResponse('<html><script>window.location = "/login"</script></html>'));
        await scanner.checkOpenRedirect('t-redir-neg', 'http://target.test/?next=1');
        expect(stmts.insertVuln.run).not.toHaveBeenCalled();
    });
});

describe('recon', () => {
    it('classifyContentType maps content types to renderability', () => {
        expect(classifyContentType('text/html; charset=utf-8')).toBe('html');
        expect(classifyContentType('application/json')).toBe('json');
        expect(classifyContentType('application/javascript')).toBe('js');
        expect(classifyContentType('')).toBe('unknown');
        expect(classifyContentType(null)).toBe('unknown');
    });

    it('extractFormParams discovers input names', () => {
        const params = extractFormParams('<form action="/search?sort=new"><input name="q"><select name="category"></select><textarea name="bio"></textarea></form>');
        expect(params).toContain('q');
        expect(params).toContain('category');
        expect(params).toContain('bio');
        expect(params).toContain('sort');
    });

    it('runRecon marks a form-bearing page as dynamic', async () => {
        const srv = await startServer((req, res) => {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<html><body><form action="/search"><input name="q"><input name="page"></form></body></html>');
        });
        try {
            const r = await runRecon(srv.url, (u, o) => fetch(u, o));
            expect(r.reachable).toBe(true);
            expect(r.dynamic).toBe(true);
            expect(r.formParams).toEqual(expect.arrayContaining(['q', 'page']));
        } finally {
            await srv.close();
        }
    });
});

describe('deterministic scan of a static page', () => {
    it('skips injection checks and finishes in a bounded number of requests', async () => {
        const srv = await startServer((req, res) => {
            srv.requests += 1;
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(STATIC_BODY);
        });
        stmts.insertVuln.run.mockClear();
        stmts.updateScanProgress.run.mockClear();
        try {
            const options = {
                useAi: false,
                checkHeaders: true,
                checkCors: true,
                checkSqlInjection: true,
                checkXss: true,
                checkOpenRedirect: true,
                checkCommandInjection: true,
                checkPathTraversal: true,
                checkSsrf: true,
                checkPromptInjection: true,
                checkHttpMethods: true,
                checkSensitiveFiles: true,
                checkRateLimit: false,
            };
            await scanner.runDeterministic('static-1', srv.url, options, []);

            // Baseline(1) + timing(3) + recon(1) + headers(1) + methods(5) +
            // sensitive-file probes(18) — no injection battery, no CORS, no
            // rate-limit blast. Well under the ~700+ requests the old
            // guess-list behaviour could burn on a page with no params.
            expect(srv.requests).toBeLessThan(40);

            // The header gaps are legitimate hardening findings, but there
            // must be ZERO vulnerability-kind findings and zero injection
            // results of any kind on a static page.
            const recorded = stmts.insertVuln.run.mock.calls.map((c) => c[0]);
            expect(recorded.every((v) => v.kind === 'hardening')).toBe(true);
            const injectionTypes = ['sql_injection', 'xss', 'open_redirect', 'command_injection', 'path_traversal', 'ssrf', 'prompt_injection', 'cors_misconfiguration', 'rate_limit_bypass', 'sensitive_file_disclosure'];
            expect(recorded.filter((v) => injectionTypes.includes(v.type))).toHaveLength(0);

            // Injection stages must not have been completed.
            const progressCalls = stmts.updateScanProgress.run.mock.calls.map((c) => c[0]);
            const allStages = progressCalls.flatMap((p) => JSON.parse(p.stages_completed || '[]'));
            for (const stage of ['sql_injection', 'xss', 'command_injection', 'path_traversal', 'ssrf', 'prompt_injection']) {
                expect(allStages).not.toContain(stage);
            }
        } finally {
            await srv.close();
        }
    });

    it('per-scan request budget stops a runaway scan', async () => {
        const srv = await startServer((req, res) => {
            srv.requests += 1;
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(STATIC_BODY);
        });
        stmts.completeScan.run.mockClear();
        try {
            await scanner.runScan('budget-1', srv.url, {
                mode: 'deterministic',
                useAi: false,
                maxRequests: 8,
                checkHeaders: true,
                checkCors: true,
                checkSqlInjection: true,
                checkXss: true,
                checkOpenRedirect: true,
                checkCommandInjection: true,
                checkPathTraversal: true,
                checkSsrf: true,
                checkPromptInjection: true,
                checkHttpMethods: true,
                checkRateLimit: true,
                checkSensitiveFiles: true,
            });

            // The budget (8) is honored: the scan finishes and the server saw
            // at most ~9 requests — not the ~35 it would have made otherwise.
            expect(srv.requests).toBeLessThanOrEqual(9);
            expect(stmts.completeScan.run).toHaveBeenCalled();
        } finally {
            await srv.close();
        }
    });
});