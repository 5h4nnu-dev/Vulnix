/**
 * Tests for recursive same-origin crawling and bounded common-path probing in
 * `recon.js`:
 *   - depth semantics: depth 1 keeps the original single-page behaviour,
 *   - depth 2 follows links discovered on the target page,
 *   - the visited set caps how many pages are fetched,
 *   - common-path probing discovers unlinked routes (e.g. /login) and honours
 *     the probe cap,
 *   - `runRecon` only surfaces the extra data when discovery is opted in.
 */

const http = require('http');
const { runRecon, crawlEndpoints, probeCommonPaths } = require('../recon');

function startServer(handler) {
    return new Promise((resolve) => {
        const server = http.createServer((req, res) => {
            server.requests = (server.requests || 0) + 1;
            handler(req, res);
        });
        server.listen(0, '127.0.0.1', () => {
            const port = server.address().port;
            resolve({
                server,
                url: `http://127.0.0.1:${port}`,
                get requests() { return server.requests || 0; },
                close: () => new Promise((r) => server.close(r)),
            });
        });
    });
}

function routes(req, res) {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/login') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body><form action="/login" method="post"><input name="user"><input name="pass"></form></body></html>');
        return;
    }
    if (u.pathname === '/api') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
        return;
    }
    if (u.pathname === '/page2') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body><a href="/rest/products/search?q=x">api</a>' +
            '<form action="/submit"><input name="q"></form></body></html>');
        return;
    }
    if (u.pathname === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body><a href="/page2">next</a></body></html>');
        return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body>page</body></html>');
}

const INDEX = '<a href="/page2">next</a>';

describe('crawlEndpoints (recursive BFS)', () => {
    it('depth 1 performs no extra fetches and returns nothing to merge', async () => {
        const srv = await startServer(routes);
        try {
            const before = srv.requests;
            const r = await crawlEndpoints(srv.url, INDEX, (u, o) => fetch(u, o), { maxDepth: 1 });
            expect(srv.requests).toBe(before);
            expect(r.endpoints).toEqual([]);
            expect(r.links).toEqual([]);
            expect(r.forms).toEqual([]);
        } finally {
            await srv.close();
        }
    });

    it('depth 2 follows links and discovers endpoints, links and forms', async () => {
        const srv = await startServer(routes);
        try {
            const r = await crawlEndpoints(srv.url, INDEX, (u, o) => fetch(u, o), { maxDepth: 2, maxVisited: 5 });
            expect(r.endpoints.map((e) => e.path)).toContain('/rest/products/search');
            expect(r.forms.map((f) => f.path)).toContain('/submit');
            expect(r.links.map((l) => l.path)).toContain('/rest/products/search');
        } finally {
            await srv.close();
        }
    });

    it('never visits more pages than maxVisited', async () => {
        const srv = await startServer((req, res) => {
            const u = new URL(req.url, 'http://x');
            if (u.pathname === '/') {
                const farm = Array.from({ length: 20 }, (_, i) => `<a href="/p${i}">x</a>`).join('');
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(farm);
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<a href="/deep">d</a>');
        });
        try {
            await crawlEndpoints(srv.url, INDEX, (u, o) => fetch(u, o), { maxDepth: 9, maxVisited: 3 });
            expect(srv.requests).toBeLessThanOrEqual(3);
        } finally {
            await srv.close();
        }
    });
});

describe('probeCommonPaths', () => {
    it('discovers unlinked routes and their forms', async () => {
        const srv = await startServer(routes);
        try {
            const r = await probeCommonPaths(srv.url, (u, o) => fetch(u, o), { commonPaths: ['/login', '/api'] });
            const paths = r.endpoints.map((e) => e.path);
            expect(paths).toContain('/login');
            expect(paths).toContain('/api');
            expect(r.endpoints.find((e) => e.path === '/login').source).toBe('probe');
        } finally {
            await srv.close();
        }
    });

    it('honours the probe cap', async () => {
        const srv = await startServer(routes);
        try {
            const before = srv.requests;
            await probeCommonPaths(srv.url, (u, o) => fetch(u, o), {
                commonPaths: ['/login', '/signin', '/api'], maxProbesPerEndpoint: 1,
            });
            expect(srv.requests - before).toBe(1);
        } finally {
            await srv.close();
        }
    });
});

describe('runRecon crawl/probe integration', () => {
    it('depth 1 (default) leaves the extra crawl off', async () => {
        const srv = await startServer(routes);
        try {
            const r = await runRecon(srv.url, (u, o) => fetch(u, o), { discover: true, maxDepth: 1 });
            expect(r.endpoints.map((e) => e.path)).not.toContain('/rest/products/search');
            expect(r.forms.map((f) => f.path)).not.toContain('/submit');
        } finally {
            await srv.close();
        }
    });

    it('depth 2 merges crawled endpoints/links/forms', async () => {
        const srv = await startServer(routes);
        try {
            const r = await runRecon(srv.url, (u, o) => fetch(u, o), { discover: true, maxDepth: 2, maxVisited: 5 });
            expect(r.endpoints.map((e) => e.path)).toContain('/rest/products/search');
            expect(r.forms.map((f) => f.path)).toContain('/submit');
        } finally {
            await srv.close();
        }
    });

    it('probeCommon surfaces unlinked routes when enabled', async () => {
        const srv = await startServer(routes);
        try {
            const r = await runRecon(srv.url, (u, o) => fetch(u, o), {
                discover: true, maxDepth: 1, probeCommon: true, commonPaths: ['/login'],
            });
            expect(r.endpoints.map((e) => e.path)).toContain('/login');
        } finally {
            await srv.close();
        }
    });

    it('does not attach discovery data unless opted in', async () => {
        const srv = await startServer(routes);
        try {
            const r = await runRecon(srv.url, (u, o) => fetch(u, o));
            expect(r.endpoints).toBeUndefined();
            expect(r.links).toBeUndefined();
        } finally {
            await srv.close();
        }
    });
});
