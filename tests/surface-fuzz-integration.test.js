/**
 * End-to-end regression for discovered-surface fuzzing:
 *
 * The root page has NO parameters, NO forms and NO scripts — only a link to a
 * vulnerable endpoint (`/product.php?id=1`). The single-URL injection battery
 * is therefore skipped entirely, so detection is only possible if the crawler
 * discovers the link and the type-appropriate surface fuzzer tests it.
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

jest.setTimeout(30000);

function found(type) {
    return stmts.insertVuln.run.mock.calls.map((c) => c[0]).find((v) => v.type === type);
}

describe('discovered-surface fuzzing e2e', () => {
    it('detects SQLi on a linked endpoint the root scan cannot reach', async () => {
        const index = '<!DOCTYPE html><html><head><title>Shop</title></head><body>' +
            '<h1>Welcome</h1><a href="/product.php?id=1">Featured product</a>' +
            '</body></html>';

        const server = http.createServer((req, res) => {
            const u = new URL(req.url, 'http://127.0.0.1');
            if (u.pathname === '/product.php') {
                const id = u.searchParams.get('id') || '';
                if (id.includes("'")) {
                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(`<html><body>SQL syntax error near '${id}' at line 1</body></html>`);
                    return;
                }
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(`<html><body>Product #${id}</body></html>`);
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(index);
        });

        await new Promise((r) => server.listen(0, '127.0.0.1', r));
        const url = `http://127.0.0.1:${server.address().port}`;

        stmts.insertVuln.run.mockClear();
        try {
            await scanner.runDeterministic('surface-e2e', url, {
                useAi: false,
                checkHeaders: false,
                checkCors: false,
                checkSqlInjection: true,
                checkXss: true,
                checkOpenRedirect: true,
                checkCommandInjection: true,
                checkPathTraversal: true,
                checkSsrf: true,
                checkPromptInjection: false,
                checkHttpMethods: false,
                checkSensitiveFiles: false,
                checkRateLimit: false,
            }, []);

            const f = found('sql_injection');
            expect(f).toBeDefined();
            expect(f.affected_endpoint).toContain('/product.php');
            expect(f.affected_endpoint).toContain('id=');
        } finally {
            await new Promise((r) => server.close(r));
        }
    });

    it('does not fuzz a navigation-only link with no parameters', async () => {
        const index = '<!DOCTYPE html><html><head><title>Site</title></head><body>' +
            '<a href="/about">About</a></body></html>';
        let aboutHits = 0;

        const server = http.createServer((req, res) => {
            const u = new URL(req.url, 'http://127.0.0.1');
            if (u.pathname === '/about') {
                aboutHits += 1;
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end('<html><body>About us</body></html>');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(index);
        });

        await new Promise((r) => server.listen(0, '127.0.0.1', r));
        const url = `http://127.0.0.1:${server.address().port}`;

        stmts.insertVuln.run.mockClear();
        try {
            await scanner.runDeterministic('surface-e2e-noop', url, {
                useAi: false,
                checkHeaders: false,
                checkCors: false,
                checkSqlInjection: true,
                checkXss: true,
                checkOpenRedirect: true,
                checkCommandInjection: true,
                checkPathTraversal: true,
                checkSsrf: true,
                checkPromptInjection: false,
                checkHttpMethods: false,
                checkSensitiveFiles: false,
                checkRateLimit: false,
            }, []);

            // The parameterless link must never be turned into an injection
            // target: no payload request is ever sent to /about.
            expect(aboutHits).toBe(0);
            expect(found('sql_injection')).toBeUndefined();
            expect(found('xss')).toBeUndefined();
        } finally {
            await new Promise((r) => server.close(r));
        }
    });

    it('fuzzes a discovered POST form through the request body (POST-only SQLi field)', async () => {
        const index = '<!DOCTYPE html><html><head><title>Blog</title></head><body>' +
            '<form action="/comment" method="post"><input name="text"><input name="author"></form>' +
            '</body></html>';
        let postHits = 0;

        const server = http.createServer((req, res) => {
            const u = new URL(req.url, 'http://127.0.0.1');
            if (u.pathname === '/comment') {
                if (req.method !== 'POST') {
                    res.writeHead(405, { 'Content-Type': 'text/plain' });
                    res.end('method not allowed');
                    return;
                }
                postHits += 1;
                let raw = '';
                req.on('data', (c) => { raw += c; });
                req.on('end', () => {
                    const text = new URLSearchParams(raw).get('text') || '';
                    if (text.includes("'")) {
                        res.writeHead(200, { 'Content-Type': 'text/html' });
                        res.end(`<html><body>SQL syntax error near '${text}' at line 1</body></html>`);
                    } else {
                        res.writeHead(200, { 'Content-Type': 'text/html' });
                        res.end('<html><body>Comment posted</body></html>');
                    }
                });
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(index);
        });

        await new Promise((r) => server.listen(0, '127.0.0.1', r));
        const url = `http://127.0.0.1:${server.address().port}`;

        stmts.insertVuln.run.mockClear();
        try {
            await scanner.runDeterministic('surface-post-e2e', url, {
                useAi: false,
                checkHeaders: false,
                checkCors: false,
                checkSqlInjection: true,
                checkXss: true,
                checkOpenRedirect: false,
                checkCommandInjection: false,
                checkPathTraversal: false,
                checkSsrf: false,
                checkPromptInjection: false,
                checkHttpMethods: false,
                checkSensitiveFiles: false,
                checkRateLimit: false,
            }, []);

            const f = found('sql_injection');
            expect(f).toBeDefined();
            expect(f.affected_endpoint).toContain('/comment');
            // The injection was delivered in the body, not the query string.
            expect(postHits).toBeGreaterThan(0);
        } finally {
            await new Promise((r) => server.close(r));
        }
    });

    it('records a finding only once when the root battery and the surface pass overlap', async () => {
        const index = '<!DOCTYPE html><html><head><title>Artists</title></head><body>' +
            '<a href="/artists.php?artist=1">Artists</a></body></html>';

        const server = http.createServer((req, res) => {
            const u = new URL(req.url, 'http://127.0.0.1');
            if (u.pathname === '/artists.php') {
                const artist = u.searchParams.get('artist') || '';
                if (artist.includes("'")) {
                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(`<html><body>SQL syntax error near '${artist}' at line 1</body></html>`);
                    return;
                }
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(index);
        });

        await new Promise((r) => server.listen(0, '127.0.0.1', r));
        const target = `http://127.0.0.1:${server.address().port}/artists.php?artist=1`;

        stmts.insertVuln.run.mockClear();
        try {
            // runScan (not runDeterministic) activates the per-scan dedupe guard.
            await scanner.runScan('dedupe-1', target, {
                mode: 'deterministic',
                useAi: false,
                checkHeaders: false,
                checkCors: false,
                checkSqlInjection: true,
                checkXss: false,
                checkOpenRedirect: false,
                checkCommandInjection: false,
                checkPathTraversal: false,
                checkSsrf: false,
                checkPromptInjection: false,
                checkHttpMethods: false,
                checkSensitiveFiles: false,
                checkRateLimit: false,
            });

            const sqli = stmts.insertVuln.run.mock.calls
                .map((c) => c[0])
                .filter((v) => v.type === 'sql_injection');
            // The self-referential link makes the root battery and the surface
            // pass test the exact same endpoint+payload; the duplicate is
            // suppressed.
            expect(sqli).toHaveLength(1);
        } finally {
            await new Promise((r) => server.close(r));
        }
    });
});
