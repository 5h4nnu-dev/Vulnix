/**
 * The agent's `crawl` tool now shares the deterministic scanner's cheerio
 * parser (surfaces.parseHtml) instead of an ad-hoc regex, so both engines see
 * the same same-origin, non-asset links and form fields.
 */

const http = require('http');

const { execute } = require('../agent/tools');

jest.setTimeout(15000);

describe('agent crawl tool (cheerio)', () => {
    it('discovers same-origin links and form fields, dropping assets/cross-origin', async () => {
        const html = '<!doctype html><html><body>' +
            '<a href="/artists.php?artist=1">Artists</a>' +
            '<link rel="stylesheet" href="/css/app.css">' +
            '<a href="https://evil.example/x">evil</a>' +
            '<form action="/search"><input name="q"><input name="category"></form>' +
            '</body></html>';

        const server = http.createServer((req, res) => {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
        });
        await new Promise((r) => server.listen(0, '127.0.0.1', r));
        const url = `http://127.0.0.1:${server.address().port}`;

        const discovered = [];
        const state = {
            targetUrl: `${url}/`,
            memory: {
                incrementRequests: () => {},
                addDiscovered: (links) => { discovered.push(...links); },
            },
        };

        try {
            const out = await execute('crawl', { path: '/' }, state);
            expect(out.ok).toBe(true);
            expect(out.links).toContain(`${url}/artists.php?artist=1`);
            expect(out.links).toContain(`${url}/search`);
            expect(out.links.some((l) => l.includes('app.css'))).toBe(false);
            expect(out.links.some((l) => l.includes('evil.example'))).toBe(false);
            expect(out.parameters).toEqual(expect.arrayContaining(['artist', 'q', 'category']));
            expect(discovered.length).toBeGreaterThan(0);
        } finally {
            await new Promise((r) => server.close(r));
        }
    });
});
