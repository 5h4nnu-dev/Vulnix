/**
 * Tests for the attack-surface discovery + type-appropriate fuzzing module.
 *
 *   - cheerio parsing of links / forms / scripts (same-origin, assets dropped),
 *   - surface building/dedup from endpoints + links + forms,
 *   - the classifier that keeps each vulnerability class on surfaces that can
 *     actually carry it (e.g. no SQL injection on a parameterless href tag),
 *   - runSurfaceFuzzing dispatch: only the matched detectors run, with both the
 *     fixed and AI payload sets, respecting the SPA/unreachable guards.
 */

const http = require('http');

const {
    parseHtml,
    buildSurfaces,
    classifySurface,
    surfaceProbeUrl,
    surfaceBaseRequest,
    runSurfaceFuzzing,
} = require('../surfaces');

const simpleHash = (str) => {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const chr = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + chr;
        hash |= 0;
    }
    return hash.toString(16);
};

// ── cheerio extraction ───────────────────────────────────────────────────────

describe('parseHtml (cheerio)', () => {
    it('extracts same-origin links with query params and drops assets/cross-origin', () => {
        const html = '<html><body>' +
            '<a href="/artists.php?artist=1">Artists</a>' +
            '<a href="/about">About</a>' +
            '<a href="/css/app.css">css</a>' +
            '<a href="https://evil.example/x">evil</a>' +
            '<iframe src="/widget?id=2"></iframe>' +
            '</body></html>';
        const { links } = parseHtml(html, 'http://target.test/');

        const hrefs = links.map((l) => l.path);
        expect(hrefs).toContain('/artists.php');
        expect(hrefs).toContain('/about');
        expect(hrefs).toContain('/widget');
        expect(hrefs).not.toContain('/css/app.css'); // static asset dropped
        expect(hrefs).not.toContain('/x');           // cross-origin dropped

        const artists = links.find((l) => l.path === '/artists.php');
        expect(artists.params).toEqual(['artist']);
    });

    it('extracts form actions, methods and field names', () => {
        const html = '<form action="/search?sort=new" method="POST">' +
            '<input name="q"><select name="category"></select>' +
            '<textarea name="bio"></textarea></form>';
        const { forms } = parseHtml(html, 'http://target.test/');
        expect(forms).toHaveLength(1);
        expect(forms[0].method).toBe('post');
        expect(forms[0].path).toBe('/search');
        expect(forms[0].params).toEqual(expect.arrayContaining(['q', 'category', 'bio', 'sort']));
    });

    it('collects same-origin scripts only', () => {
        const html = '<script src="main.js"></script><script src="https://cdn.example/lib.js"></script>';
        const { scripts } = parseHtml(html, 'http://target.test/app');
        expect(scripts).toEqual(['http://target.test/main.js']);
    });
});

// ── surface building ─────────────────────────────────────────────────────────

describe('buildSurfaces', () => {
    it('merges endpoints, links and forms and dedupes by path', () => {
        const reconData = {
            endpoints: [{ path: '/rest/products/search', params: ['q'], source: 'js' }],
            links: [
                { url: 'http://target.test/artists.php?artist=1', path: '/artists.php', params: ['artist'] },
                { url: 'http://target.test/artists.php?artist=2', path: '/artists.php', params: ['artist'] },
            ],
            forms: [{ url: 'http://target.test/search', path: '/search', method: 'post', params: ['q'] }],
        };
        const surfaces = buildSurfaces(reconData, 'http://target.test/');
        const byPath = Object.fromEntries(surfaces.map((s) => [s.path, s]));

        expect(Object.keys(byPath)).toEqual(expect.arrayContaining(['/rest/products/search', '/artists.php', '/search']));
        expect(surfaces.filter((s) => s.path === '/artists.php')).toHaveLength(1); // deduped
        expect(byPath['/search'].kind).toBe('form');
        expect(byPath['/rest/products/search'].kind).toBe('api');
    });

    it('drops static assets and cross-origin paths', () => {
        const surfaces = buildSurfaces({
            links: [
                { url: 'http://target.test/logo.png', path: '/logo.png', params: [] },
                { url: 'http://other.test/page?id=1', path: '/page', params: ['id'] },
            ],
        }, 'http://target.test/');
        expect(surfaces).toHaveLength(0);
    });
});

// ── type-appropriate classification ──────────────────────────────────────────

describe('classifySurface keeps each class on surfaces that can carry it', () => {
    it('does NOT test SQL injection (or anything) on a parameterless href tag', () => {
        const { types } = classifySurface({ path: '/about', params: [], kind: 'link' });
        expect(types).toEqual([]);
    });

    it('tests generic SQLi + XSS on a plain parameterised link', () => {
        const { types } = classifySurface({ path: '/x', params: ['q'], kind: 'link' }, { renderable: true });
        expect(types).toContain('sql_injection');
        expect(types).toContain('xss');
        // No specialised classes for an unrelated param name.
        expect(types).not.toContain('path_traversal');
        expect(types).not.toContain('command_injection');
        expect(types).not.toContain('ssrf');
        expect(types).not.toContain('open_redirect');
    });

    it('maps file-ish params to traversal, cmd-ish to command injection, url-ish to SSRF/redirect', () => {
        expect(classifySurface({ path: '/v', params: ['file'], kind: 'link' }).types).toContain('path_traversal');
        expect(classifySurface({ path: '/v', params: ['cmd'], kind: 'link' }).types).toContain('command_injection');
        const urlTypes = classifySurface({ path: '/v', params: ['url'], kind: 'link' }).types;
        expect(urlTypes).toContain('ssrf');
        expect(urlTypes).toContain('open_redirect');
    });

    it('drops XSS when the response is not HTML-renderable', () => {
        const { types } = classifySurface({ path: '/api', params: ['q'], kind: 'api' }, { renderable: false });
        expect(types).toContain('sql_injection');
        expect(types).not.toContain('xss');
    });
});

describe('surfaceProbeUrl', () => {
    it('ensures every discovered parameter is present in the probe URL', () => {
        const u = surfaceProbeUrl({ url: 'http://target.test/search', params: ['q', 'page'] });
        expect(u).toContain('q=1');
        expect(u).toContain('page=1');
    });
});

describe('surfaceBaseRequest', () => {
    it('builds a GET-with-query baseline for link surfaces', () => {
        const req = surfaceBaseRequest({ url: 'http://target.test/search', params: ['q'] }, 'UA');
        expect(req.init.method).toBe('GET');
        expect(req.url).toContain('q=1');
    });

    it('builds a urlencoded POST body baseline for form surfaces', () => {
        const req = surfaceBaseRequest(
            { url: 'http://target.test/login', method: 'post', params: ['user', 'pass'] }, 'UA');
        expect(req.init.method).toBe('POST');
        expect(req.url).toBe('http://target.test/login');
        expect(req.init.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
        expect(req.init.body).toContain('user=1');
        expect(req.init.body).toContain('pass=1');
    });
});

// ── fuzzing dispatch ─────────────────────────────────────────────────────────

function textResponse(body, status = 200, contentType = 'text/html') {
    return {
        status,
        headers: { get: (name) => (name === 'content-type' ? contentType : null) },
        text: async () => body,
    };
}

function makeDeps({ responses = {}, config = { scanner: { scanDiscovery: { maxSurfaces: 12 } } } } = {}) {
    const calls = { events: [], detectors: {}, fetches: [] };
    const deps = {
        config,
        UA: 'TestAgent',
        addEvent: (...args) => calls.events.push(args),
        simpleHash,
        isSoft404: () => false,
        scanCancelled: () => false,
        scanBudgetExhausted: () => false,
        fetchSafe: async (u, init) => {
            calls.fetches.push({ url: u, init });
            const key = new URL(u).pathname;
            if (key in responses) return responses[key];
            return textResponse('<html><body>ok</body></html>');
        },
        detectors: {},
    };
    for (const type of ['sql_injection', 'xss', 'open_redirect', 'command_injection', 'path_traversal', 'ssrf']) {
        deps.detectors[type] = (...args) => { calls.detectors[type] = calls.detectors[type] || []; calls.detectors[type].push(args); };
    }
    return { deps, calls };
}

describe('runSurfaceFuzzing', () => {
    const base = { status: 200, bodyHash: simpleHash('DIFFERENT-INDEX'), bodyLength: 15 };

    it('does not run any detector on a parameterless link (the href-tag rule)', async () => {
        const { deps, calls } = makeDeps();
        await runSurfaceFuzzing({
            scanId: 's1', url: 'http://target.test/', reconData: { base, links: [{ url: 'http://target.test/about', path: '/about', params: [] }] },
            ai: {}, deps,
        });
        expect(Object.keys(calls.detectors)).toHaveLength(0);
    });

    it('runs only the matched detectors, passing fixed + AI payloads', async () => {
        const { deps, calls } = makeDeps();
        const ai = { sql_injection: ['AI-SQL'], xss: ['AI-XSS'], path_traversal: ['AI-PT'] };
        await runSurfaceFuzzing({
            scanId: 's2', url: 'http://target.test/',
            reconData: { base, links: [{ url: 'http://target.test/artists.php?artist=1', path: '/artists.php', params: ['artist'] }] },
            ai, deps,
        });
        expect(calls.detectors.sql_injection).toHaveLength(1);
        expect(calls.detectors.xss).toHaveLength(1);
        // `artist` is not a traversal/cmdi/ssrf param — those must not run.
        expect(calls.detectors.path_traversal).toBeUndefined();
        expect(calls.detectors.command_injection).toBeUndefined();
        expect(calls.detectors.ssrf).toBeUndefined();

        const [url, payloads] = calls.detectors.sql_injection[0];
        expect(url).toContain('artist=1');
        expect(payloads).toContain('AI-SQL');
        expect(calls.detectors.xss[0][1]).toContain('AI-XSS');
    });

    it('routes a file param to the traversal detector only', async () => {
        const { deps, calls } = makeDeps();
        await runSurfaceFuzzing({
            scanId: 's3', url: 'http://target.test/',
            reconData: { base, links: [{ url: 'http://target.test/view?file=a.txt', path: '/view', params: ['file'] }] },
            ai: {}, deps,
        });
        expect(calls.detectors.path_traversal).toHaveLength(1);
        expect(calls.detectors.command_injection).toBeUndefined();
        expect(calls.detectors.ssrf).toBeUndefined();
    });

    it('skips SPA client routes that return the shared index page', async () => {
        const index = '<html><body><app-root></app-root></body></html>';
        const { deps, calls } = makeDeps({ responses: { '/search': textResponse(index, 200, 'text/html') } });
        await runSurfaceFuzzing({
            scanId: 's4', url: 'http://target.test/',
            reconData: { base: { status: 200, bodyHash: simpleHash(index), bodyLength: index.length }, links: [{ url: 'http://target.test/search?q=1', path: '/search', params: ['q'] }] },
            ai: {}, deps,
        });
        expect(Object.keys(calls.detectors)).toHaveLength(0);
        const skipped = calls.events.map((e) => e[3]);
        expect(skipped).toContain('Client-Side Route Skipped');
    });

    it('reports unreachable surfaces as diagnostics and does not run detectors', async () => {
        const { deps, calls } = makeDeps();
        deps.fetchSafe = async () => null;
        await runSurfaceFuzzing({
            scanId: 's5', url: 'http://target.test/',
            reconData: { base, links: [{ url: 'http://target.test/artists.php?artist=1', path: '/artists.php', params: ['artist'] }] },
            ai: {}, deps,
        });
        expect(Object.keys(calls.detectors)).toHaveLength(0);
        expect(calls.events.map((e) => e[3])).toContain('Surface Unreachable');
    });

    it('drops the XSS detector when the surface is not HTML-renderable (XML)', async () => {
        const { deps, calls } = makeDeps({
            responses: { '/feed': textResponse('<rss><item/></rss>', 200, 'application/xml') },
        });
        await runSurfaceFuzzing({
            scanId: 's6', url: 'http://target.test/',
            reconData: { base, links: [{ url: 'http://target.test/feed?q=1', path: '/feed', params: ['q'] }] },
            ai: {}, deps,
        });
        // SQLi still applies; XSS cannot execute in application/xml.
        expect(calls.detectors.sql_injection).toHaveLength(1);
        expect(calls.detectors.xss).toBeUndefined();
    });

    it('passes GET injection context to detectors for link surfaces', async () => {
        const { deps, calls } = makeDeps();
        await runSurfaceFuzzing({
            scanId: 's7', url: 'http://target.test/',
            reconData: { base, links: [{ url: 'http://target.test/v?a=1', path: '/v', params: ['a'] }] },
            ai: {}, deps,
        });
        const opts = calls.detectors.sql_injection[0][2];
        expect(opts.inject.method).toBe('get');
        expect(opts.inject.paramCandidates).toEqual(['a']);
    });

    it('fetches a POST form baseline as a urlencoded POST and passes POST inject context', async () => {
        const { deps, calls } = makeDeps();
        await runSurfaceFuzzing({
            scanId: 's8', url: 'http://target.test/',
            reconData: { base, forms: [{ url: 'http://target.test/login', path: '/login', method: 'post', params: ['user', 'pass'] }] },
            ai: {}, deps,
        });
        const baseline = calls.fetches.find((f) => f.url.endsWith('/login'));
        expect(baseline).toBeDefined();
        expect(baseline.init.method).toBe('POST');
        expect(baseline.init.body).toContain('user=1');

        const opts = calls.detectors.sql_injection[0][2];
        expect(opts.inject.method).toBe('post');
        expect(opts.inject.formFields).toEqual({ user: '1', pass: '1' });
        expect(opts.inject.paramCandidates).toEqual(['user', 'pass']);
        // XSS still applies (HTML baseline) in addition to SQLi.
        expect(calls.detectors.xss).toHaveLength(1);
    });
});

// ── recon integration: cheerio surfaces flow through runRecon ────────────────

describe('runRecon discover exposes cheerio links/forms', () => {
    it('attaches links and forms when discovery is opted in', async () => {
        const { runRecon } = require('../recon');
        const body = '<html><body><a href="/artists.php?artist=1">Artists</a>' +
            '<form action="/search"><input name="q"></form></body></html>';
        const server = http.createServer((req, res) => {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(body);
        });
        await new Promise((r) => server.listen(0, '127.0.0.1', r));
        const url = `http://127.0.0.1:${server.address().port}`;
        try {
            const r = await runRecon(url, (u, o) => fetch(u, o), { discover: true });
            expect(r.links.map((l) => l.path)).toContain('/artists.php');
            expect(r.links.find((l) => l.path === '/artists.php').params).toEqual(['artist']);
            expect(r.forms.map((f) => f.path)).toContain('/search');
            expect(r.forms[0].params).toContain('q');
        } finally {
            await new Promise((r) => server.close(r));
        }
    });
});
