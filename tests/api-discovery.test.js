/**
 * Regression tests for same-origin API endpoint discovery + probing:
 *   - pure discovery helpers (path heuristics, URL mining, script srcs),
 *   - discoverEndpoints over a real HTTP server (page + JS bundles),
 *   - error-based SQLi detection on a discovered endpoint,
 *   - POST authentication-bypass probing on login endpoints,
 *   - no false positives on healthy JSON endpoints (reflection = event only),
 *   - SPA client-route guard and timeout diagnostics,
 *   - full deterministic-scan integration against a Juice-Shop-like fixture.
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
const {
    runRecon, discoverEndpoints, isApiPath, scoreEndpoint,
    extractSameOriginUrls, extractApiPathTokens, extractScriptSrcs,
} = require('../recon');

jest.setTimeout(30000);

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

describe('discovery heuristics (pure helpers)', () => {
    it('isApiPath accepts API/input surfaces and rejects assets', () => {
        for (const ok of ['/rest/products/search', '/api/Products', '/graphql', '/v2/users', '/search', '/login', '/rest/user/login']) {
            expect(isApiPath(ok)).toBe(true);
        }
        for (const no of ['/main.js', '/app.min.js', '/logo.png', '/css/app.css', '/assets/img/x.png', '/images/juice.jpg', '/']) {
            expect(isApiPath(no)).toBe(false);
        }
    });

    it('scoreEndpoint ranks interactive surfaces above admin/noise paths', () => {
        expect(scoreEndpoint('/rest/products/search')).toBeGreaterThan(scoreEndpoint('/rest/admin'));
        expect(scoreEndpoint('/rest/user/login')).toBeGreaterThan(scoreEndpoint('/rest/user/whoami'));
    });

    it('extractSameOriginUrls resolves, dedupes and drops cross-origin URLs', () => {
        const body = [
            'fetch("https://example.com/rest/a")',          // same origin (absolute)
            "fetch('/rest/b')",                              // relative
            'x = `//example.com/rest/c`',                    // protocol-relative same host
            'href="https://evil.example/rest/d"',            // cross origin → dropped
            'fetch("https://other.com/api/x")',              // cross origin → dropped
            'plain http://example.com/rest/e',               // absolute bare
        ].join('\n');
        const urls = extractSameOriginUrls(body, 'https://example.com/');
        expect(urls).toEqual(expect.arrayContaining([
            'https://example.com/rest/a',
            'https://example.com/rest/b',
            'https://example.com/rest/c',
            'http://example.com/rest/e',
        ]));
        expect(urls.some((u) => u.includes('evil.example'))).toBe(false);
        expect(urls.some((u) => u.includes('other.com'))).toBe(false);
    });

    it('extractApiPathTokens captures paths inside JS template literals', () => {
        const body = 'const u = `${this.hostServer}/rest/products/search?q=${e}`;' +
            'get(`/api/Challenges/?key=nftMintChallenge`);';
        const tokens = extractApiPathTokens(body, 'https://example.com/');
        const search = tokens.find((t) => t.pathname === '/rest/products/search');
        expect(search).toBeDefined();
        expect(search.params).toContain('q');
        expect(tokens.some((t) => t.pathname === '/api/Challenges/')).toBe(true);
    });

    it('extractScriptSrcs collects same-origin bundles only', () => {
        const body = '<script src="main.js"></script><script src="/polyfills.js"></script>' +
            '<script src="https://cdn.example/lib.js"></script>';
        const urls = extractScriptSrcs(body, 'https://example.com/app');
        expect(urls).toEqual(expect.arrayContaining([
            'https://example.com/main.js',
            'https://example.com/polyfills.js',
        ]));
        expect(urls.some((u) => u.includes('cdn.example'))).toBe(false);
    });
});

describe('discoverEndpoints over a real server', () => {
    it('mines the page and same-origin JS bundle for API paths', async () => {
        const index = '<html><head><script src="main.js"></script></head>' +
            '<body><script>fetch(\'/rest/user/login\');</script>' +
            '<img src="/logo.png"><link href="/css/app.css"></body></html>';
        const srv = await startServer((req, res) => {
            srv.requests += 1;
            if (req.url === '/main.js') {
                res.writeHead(200, { 'Content-Type': 'application/javascript' });
                res.end('const host=""; fetch(`${host}/api/Products`); fetch(`${host}/rest/products/search?q=`);');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(index);
        });
        try {
            const res = await discoverEndpoints(srv.url + '/', index, (u, o, t) => fetch(u, o), { maxScripts: 2 });
            const paths = res.endpoints.map((e) => e.path);
            expect(paths).toContain('/rest/user/login');   // from page inline JS
            expect(paths).toContain('/api/Products');      // from bundle
            expect(paths).toContain('/rest/products/search'); // from bundle template
            expect(paths.some((p) => p.includes('logo.png') || p.includes('app.css'))).toBe(false);
            expect(res.scripts).toBe(1);
        } finally {
            await srv.close();
        }
    });

    it('runRecon returns endpoints only when discovery is opted in', async () => {
        const body = '<html><body><script>fetch(\'/rest/products/search?q=\')</script></body></html>';
        const srv = await startServer((req, res) => {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(body);
        });
        try {
            const basic = await runRecon(srv.url, (u, o) => fetch(u, o));
            expect(basic.endpoints).toBeUndefined(); // backward-compatible default
            const withDiscovery = await runRecon(srv.url, (u, o) => fetch(u, o), { discover: true });
            expect(withDiscovery.endpoints).toEqual(expect.arrayContaining([
                expect.objectContaining({ path: '/rest/products/search', params: ['q'] }),
            ]));
        } finally {
            await srv.close();
        }
    });
});

describe('checkApiEndpoints', () => {
    beforeEach(() => { stmts.insertVuln.run.mockClear(); });
    afterEach(() => { stmts.insertEvent.run.mockClear(); });

    const juiceIndex = '<!doctype html><html><body><app-root></app-root>' +
        '<script src="main.js"></script><script>fetch(\'/rest/products/search?q=\')</script></body></html>';

    it('detects error-based SQLi on a discovered API endpoint', async () => {
        const srv = await startServer((req, res) => {
            srv.requests += 1;
            const u = new URL(req.url, srv.url);
            if (u.pathname === '/rest/products/search') {
                const q = u.searchParams.get('q') || '';
                if (q.includes('"')) {
                    res.writeHead(500, { 'Content-Type': 'text/html' });
                    res.end(`<title>Error: SQLITE_ERROR: unrecognized token: ""')%') AND deletedAt IS NULL</title>`);
                    return;
                }
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end('{"status":"success","data":[]}');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(juiceIndex);
        });
        try {
            const reconData = {
                endpoints: [{ path: '/rest/products/search', params: ['q'] }],
                base: { status: 200, bodyHash: scanner.simpleHash(juiceIndex) },
            };
            await scanner.checkApiEndpoints('api-sqli', srv.url, 5, reconData, {});
            const f = found('sql_injection');
            expect(f).toBeDefined();
            expect(f.severity).toBe('critical');
            expect(f.affected_endpoint).toContain('/rest/products/search');
            expect(f.payload).toContain('"\'');
        } finally {
            await srv.close();
        }
    });

    it('detects SQLi authentication bypass on a login endpoint (POST)', async () => {
        const srv = await startServer((req, res) => {
            srv.requests += 1;
            if (req.method === 'POST' && req.url === '/rest/user/login') {
                let raw = '';
                req.on('data', (c) => { raw += c; });
                req.on('end', () => {
                    let email = '';
                    try { email = JSON.parse(raw).email || ''; } catch { /* ignore */ }
                    if (email === "admin'--") {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end('{"authentication":{"token":"bypass-token"},"bid":2}');
                    } else {
                        res.writeHead(401, { 'Content-Type': 'application/json' });
                        res.end('{"error":"Invalid email or password."}');
                    }
                });
                return;
            }
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end('{"error":"Not found"}');
        });
        try {
            const reconData = { endpoints: [{ path: '/rest/user/login', params: [] }], base: null };
            await scanner.checkApiEndpoints('api-auth', srv.url, 5, reconData, {});
            const f = found('sql_injection');
            expect(f).toBeDefined();
            expect(f.title).toMatch(/Authentication Bypass/i);
            expect(f.severity).toBe('critical');
            // Baseline was refused, bypass accepted → behavioral evidence recorded.
            expect(f.evidence).toContain('HTTP 401');
            expect(f.evidence).toContain('HTTP 200');
        } finally {
            await srv.close();
        }
    });

    it('does not flag a healthy JSON endpoint; reflection is an event only', async () => {
        const srv = await startServer((req, res) => {
            srv.requests += 1;
            const u = new URL(req.url, srv.url);
            if (u.pathname === '/api/Items') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ query: u.searchParams.get('q') || '', data: [] }));
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(juiceIndex);
        });
        try {
            const reconData = {
                endpoints: [{ path: '/api/Items', params: [] }],
                base: { status: 200, bodyHash: scanner.simpleHash(juiceIndex) },
            };
            await scanner.checkApiEndpoints('api-clean', srv.url, 5, reconData, {});
            expect(stmts.insertVuln.run.mock.calls.length).toBe(0);
            const reflectionEvents = stmts.insertEvent.run.mock.calls
                .map((c) => c[0])
                .filter((e) => e.title === 'Input Reflection Detected');
            expect(reflectionEvents.length).toBeGreaterThan(0);
        } finally {
            await srv.close();
        }
    });

    it('skips SPA client routes that return the index page', async () => {
        const srv = await startServer((req, res) => {
            srv.requests += 1;
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(juiceIndex);
        });
        try {
            const reconData = {
                endpoints: [{ path: '/search', params: [] }],
                base: { status: 200, bodyHash: scanner.simpleHash(juiceIndex) },
            };
            const before = srv.requests;
            await scanner.checkApiEndpoints('api-spa', srv.url, 5, reconData, {});
            // Baseline GET (1) + the skip decision — no probe battery.
            expect(srv.requests - before).toBeLessThanOrEqual(2);
            expect(stmts.insertVuln.run.mock.calls.length).toBe(0);
        } finally {
            await srv.close();
        }
    });

    it('reports unreachable endpoints as diagnostics instead of silently skipping', async () => {
        const origFetch = global.fetch;
        global.fetch = jest.fn(async () => null); // connection failure / timeout
        try {
            const reconData = { endpoints: [{ path: '/rest/products/search', params: ['q'] }], base: null };
            await scanner.checkApiEndpoints('api-timeout', 'http://target.test', 5, reconData, {});
            const events = stmts.insertEvent.run.mock.calls.map((c) => c[0]);
            expect(events.some((e) => e.title === 'API Endpoint Unreachable')).toBe(true);
            expect(stmts.insertVuln.run.mock.calls.length).toBe(0);
        } finally {
            global.fetch = origFetch;
        }
    });
});

describe('full deterministic scan of a Juice-Shop-like target', () => {
    it('surfaces the SQLi hidden on a discovered API endpoint', async () => {
        const index = '<!doctype html><html><head><title>OWASP Juice Shop</title>' +
            '<script src="main.js"></script></head><body><app-root></app-root></body></html>';
        const srv = await startServer((req, res) => {
            srv.requests += 1;
            if (req.url === '/main.js') {
                res.writeHead(200, { 'Content-Type': 'application/javascript' });
                res.end('const h=""; fetch(`${h}/rest/products/search?q=`); fetch(`${h}/rest/user/login`);');
                return;
            }
            const u = new URL(req.url, srv.url);
            if (u.pathname === '/rest/products/search') {
                const q = u.searchParams.get('q') || '';
                if (q.includes("\"')")) {
                    res.writeHead(500, { 'Content-Type': 'text/html' });
                    res.end('<title>Error: SQLITE_ERROR: unrecognized token: ""\')\'</title>');
                    return;
                }
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end('{"status":"success","data":[{"id":9,"name":"O-Saft"}]}');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(index);
        });
        stmts.insertVuln.run.mockClear();
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
            await scanner.runDeterministic('api-e2e', srv.url, options, []);

            const f = found('sql_injection');
            expect(f).toBeDefined();
            expect(f.affected_endpoint).toContain('/rest/products/search');

            // No finding may target the made-up /rest/user/login (the fixture
            // refuses it without a bypass signal — see the POST auth-bypass test).
            const sqliFindings = stmts.insertVuln.run.mock.calls
                .map((c) => c[0])
                .filter((v) => v.type === 'sql_injection');
            expect(sqliFindings.every((v) => v.affected_endpoint.includes('/rest/products/search'))).toBe(true);
        } finally {
            await srv.close();
        }
    });
});