/**
 * Reconnaissance layer for the deterministic scanner.
 *
 * One cheap GET against the target page that produces a rich context object
 * used by `scanner.js` to:
 *   - skip injection checks entirely on static pages (params/forms absent),
 *   - reuse headers/body instead of re-fetching per check,
 *   - type the parameter-name guess lists per vulnerability class.
 *
 * Pure helper functions are exported so the gate logic can be unit-tested.
 * `runRecon` takes the fetch function as an argument so the scanner can hand
 * over its budget/cancellation-aware `fetchSafe` (no fetch happens out-of-band).
 */

const { parseHtml } = require('./surfaces');

const UA = 'SecureProbe/2.0';

function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const chr = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + chr;
        hash |= 0;
    }
    return hash.toString(16);
}

function extractFingerprint(body) {
    const keywords = [];
    const lower = String(body || '').toLowerCase();
    if (lower.includes('not found')) keywords.push('not_found');
    if (lower.includes('page not found')) keywords.push('page_not_found');
    if (lower.includes('404')) keywords.push('404');
    if (lower.includes('does not exist')) keywords.push('does_not_exist');
    if (lower.includes('error')) keywords.push('error');
    if (lower.includes('cannot find')) keywords.push('cannot_find');
    return keywords;
}

/** Map a Content-Type header to a coarse renderability class. */
function classifyContentType(contentType) {
    const ct = String(contentType || '').toLowerCase();
    if (!ct) return 'unknown';
    if (/text\/html|application\/xhtml\+xml/.test(ct)) return 'html';
    if (/application\/json|\+json/.test(ct)) return 'json';
    if (/javascript|ecmascript/.test(ct)) return 'js';
    if (/xml/.test(ct)) return 'xml';
    if (/text\/plain/.test(ct)) return 'text';
    return 'other';
}

/**
 * Collect parameter names from `<input>`, `<select>`, `<textarea>`, `<button>`
 * and `<form>` elements found in a page body. Zero extra requests — the body
 * is already in hand.
 */
function extractFormParams(body) {
    const params = new Set();
    const matchAll = (re) => {
        if (!body) return [];
        const out = [];
        const re2 = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
        let m;
        while ((m = re2.exec(body)) !== null) out.push(m);
        return out;
    };

    for (const m of matchAll(/<(?:input|select|textarea|button)[^>]*name\s*=\s*["']([^"']+)["']/gi)) {
        params.add(m[1]);
    }
    for (const m of matchAll(/<form[^>]*>/gi)) {
        // A form without a name on its inputs still takes at least one param.
        const action = m[0].match(/action\s*=\s*["']([^"']*)["']/i);
        if (action && action[1]) {
            const actionUrl = action[1];
            const qIdx = actionUrl.indexOf('?');
            if (qIdx !== -1) {
                for (const pair of actionUrl.slice(qIdx + 1).split('&')) {
                    const key = pair.split('=')[0];
                    if (key) params.add(decodeURIComponent(key));
                }
            }
        }
        // Any form with contained fields is a dynamic surface even if the
        // name attributes were missed.
        params.add('__form__');
    }
    return Array.from(params);
}

/** Cheap technology fingerprint from headers + body (mirrors scanner.js). */
function fingerprintTech(headers = {}, body = '') {
    const techs = [];
    const h = headers || {};
    if (h['x-powered-by']) techs.push(h['x-powered-by']);
    if (h['server']) techs.push(h['server']);
    if (h['x-aspnet-version']) techs.push('ASP.NET ' + h['x-aspnet-version']);
    if (h['x-drupal-cache']) techs.push('Drupal');
    if (h['x-generator']) techs.push(h['x-generator']);

    const lower = String(body || '').toLowerCase();
    if (lower.includes('wp-content') || lower.includes('wp-includes')) techs.push('WordPress');
    if (lower.includes('joomla')) techs.push('Joomla');
    if (lower.includes('drupal')) techs.push('Drupal');
    if (lower.includes('next-head') || lower.includes('_next/')) techs.push('Next.js');
    if (lower.includes('__nuxt') || lower.includes('_nuxt/')) techs.push('Nuxt.js');
    if (body.includes('ng-app') || body.includes('ng-controller')) techs.push('AngularJS');
    if (lower.includes('laravel')) techs.push('Laravel');
    return techs;
}

/**
 * One GET against the target URL; returns a context object (or
 * `{ reachable: false }` when the fetch fails).
 *
 * When `opts.discover` is true the recon pass also mines the page and up to
 * `opts.maxScripts` same-origin JS bundles for API path candidates (see
 * `discoverEndpoints`). The result then carries `endpoints` (sorted by
 * priority) and `discoveredScripts`. Every extra fetch goes through the same
 * `fetchFn`, so budget/cancellation stay in force during discovery.
 */
async function runRecon(url, fetchFn = global.fetch, opts = {}) {
    const resp = await fetchFn(url, { method: 'GET', headers: { 'User-Agent': UA } }, 15000);
    if (!resp) return { reachable: false };

    let body = '';
    try { body = await resp.text(); } catch { /* ignore */ }

    const headers = {};
    if (resp.headers && typeof resp.headers.forEach === 'function') {
        resp.headers.forEach((v, k) => { headers[k] = v; });
    }
    const contentType = resp.headers && typeof resp.headers.get === 'function'
        ? (resp.headers.get('content-type') || '')
        : (headers['content-type'] || '');

    let params = [];
    try { params = Array.from(new URL(url).searchParams.keys()); } catch { /* ignore */ }

    const formParams = extractFormParams(body);
    // A script tag alone does not make an otherwise static document an input
    // surface. Conversely JSON/API responses can be dynamic without HTML.
    const hasInputMarkup = /<(?:form|input|select|textarea)\b|\bonclick\s*=|\bonchange\s*=/i.test(body);
    const looksLikeApi = /(?:^|\/)(?:api|graphql|rest|rpc)(?:\/|$)/i.test(new URL(url).pathname);
    const isJson = /(?:application\/json|\+json)/i.test(contentType);
    const dynamic = params.length > 0 || formParams.length > 0 || hasInputMarkup || isJson || looksLikeApi;

    const result = {
        reachable: true,
        status: resp.status,
        headers,
        body,
        bodyLength: body.length,
        contentType,
        contentTypeClass: classifyContentType(contentType),
        params,
        formParams,
        dynamic,
        tech: fingerprintTech(headers, body),
        base: {
            status: resp.status,
            bodyLength: body.length,
            bodyHash: simpleHash(body),
            keywords: extractFingerprint(body),
        },
    };

    if (opts && opts.discover) {
        const discovery = await discoverEndpoints(url, body, fetchFn, opts);
        result.endpoints = discovery.endpoints;
        result.discoveredScripts = discovery.scripts;
        // Structural surfaces (cheerio): links carrying parameters and forms.
        // These feed the type-appropriate surface fuzzer in scanner.js.
        result.links = discovery.links;
        result.forms = discovery.forms;

        // Recursive crawl to discover endpoints on same-origin secondary pages
        try {
            const crawlOpts = {
                maxDepth: opts.maxDepth,
                maxVisited: opts.maxVisited,
                maxScripts: opts.maxScripts,
                ...opts.crawl
            };
            const crawled = await crawlEndpoints(url, body, fetchFn, crawlOpts);
            if (Array.isArray(crawled.endpoints)) {
                const all = new Map();
                (result.endpoints || []).forEach(e => { const k = (e.path||'').toString(); if (k) all.set(k, e); });
                crawled.endpoints.forEach(e => { const k = (e.path||'').toString(); if (!all.has(k)) all.set(k, e); });
                result.endpoints = Array.from(all.values());
            }
            if (Array.isArray(crawled.links)) result.links = result.links ? result.links.concat(crawled.links) : crawled.links;
            if (Array.isArray(crawled.forms)) result.forms = result.forms ? result.forms.concat(crawled.forms) : crawled.forms;
            if (crawled.scripts) result.discoveredScripts = result.discoveredScripts ? result.discoveredScripts.concat(crawled.scripts) : crawled.scripts;
        } catch { /* ignore */ }

        // Bounded common-path probing
        try {
            if (opts.probeCommon) {
                const probed = await probeCommonPaths(url, fetchFn, opts);
                if (Array.isArray(probed.endpoints)) {
                    const all = new Map();
                    (result.endpoints || []).forEach(e => { const k = (e.path||'').toString(); if (k) all.set(k, e); });
                    probed.endpoints.forEach(e => { const k = (e.path||'').toString(); if (!all.has(k)) all.set(k, e); });
                    result.endpoints = Array.from(all.values());
                }
            }
        } catch { /* ignore */ }
    }

    return result;
}

// ── API endpoint discovery ───────────────────────────────────────────────────
// SPA + JSON-API apps (Juice Shop is the canonical example) process almost all
// user input on same-origin API paths that a single-page parameter fuzz can
// never reach. These helpers mine the page HTML and the app's own JS bundles
// for such paths, so the scanner can probe the real attack surface.

// Static assets are not input surfaces.
const STATIC_ASSET_RE = /\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|map|pdf|zip|gz|mp4|webm|mp3|wav|min\.js)$/i;

// Paths that supply content in asset-style directories are not endpoints.
const ASSET_DIR_RE = /(^|\/)(?:img|image|images|css|fonts?|assets|static|dist)(\/|$)/i;

// Words that mark a path as an interactive/API surface worth probing.
const ENDPOINT_WORD_RE = /(?:login|register|signin|signup|logout|authenticate|auth|session|basket|cart|checkout|orders?|addresses?|payments?|profile|users?|products?|reviews?|feedback|search|recycle|tracking|delivery|rewards?|complaints?|wallets?|returns?)/i;

/** Heuristic: is this pathname a candidate API/input endpoint? */
function isApiPath(pathname) {
    if (!pathname) return false;
    const p = String(pathname).split('?')[0];
    if (STATIC_ASSET_RE.test(p)) return false;
    if (ASSET_DIR_RE.test(p)) return false;
    if (/^\/(?:rest|api|graphql|v\d+)(?:\/|$)/i.test(p)) return true;
    return ENDPOINT_WORD_RE.test(p);
}

/** Priority score for sorting discovered candidates (higher = probe first). */
function scoreEndpoint(pathname) {
    const p = String(pathname || '').toLowerCase();
    let s = 0;
    if (/(?:search|query|login|register|signin|signup|authenticate|logout|feedback|reviews?|basket|checkout|orders?|addresses?|complaints?|recycle|tracking|payments?|wallets?|products?|users?)/.test(p)) s += 2;
    if (/(?:import|export|admin|config|debug|metrics|health|whoami|save|change|reset|continue|image-captcha|memories|rewards?|web3|country|deluxe|chat|repeat)/.test(p)) s -= 1;
    if (p.endsWith('/')) s -= 1;
    return s;
}

/** Same-origin URLs referenced by the page/JS: quoted, attribute or bare. */
function extractSameOriginUrls(body, baseUrl) {
    if (!body) return [];
    let base;
    try { base = new URL(baseUrl); } catch { return []; }
    const urls = new Set();
    const push = (raw) => {
        if (!raw) return;
        const cleaned = String(raw).trim().replace(/[,;)]+$/g, '');
        if (!cleaned) return;
        let resolved;
        try { resolved = new URL(cleaned, base); } catch { return; }
        if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return;
        if (resolved.hostname !== base.hostname) return;
        if (resolved.port !== base.port) return;
        urls.add(resolved.toString());
    };
    // Absolute / protocol-relative URLs (quoted or bare).
    for (const m of body.matchAll(/([a-z][a-z0-9+.-]*:\/\/[^"'`\s<>)]+)/gi)) push(m[1]);
    // Relative paths in quotes, attributes or after whitespace.
    for (const m of body.matchAll(/(?:["'`]|\s|=)(\/(?:[^"'`\s<>)\]]*))/gi)) push(m[1]);
    return Array.from(urls);
}

/**
 * Direct capture of /rest|api|graphql|v* paths — including inside JS template
 * literals such as `${host}/rest/products/search?q=...` where the path is not
 * adjacent to a quote.
 */
function extractApiPathTokens(body, baseUrl) {
    if (!body) return [];
    let base;
    try { base = new URL(baseUrl); } catch { return []; }
    const tokens = [];
    const seen = new Set();
    for (const m of body.matchAll(/\/(?:rest|api|graphql|v\d+)\/[A-Za-z0-9_\-./~]+(?:\?[A-Za-z0-9_\-=&.~%]*)?/gi)) {
        let parsed;
        try { parsed = new URL(m[0], base); } catch { continue; }
        if (parsed.hostname !== base.hostname) continue;
        const key = parsed.pathname + parsed.search;
        if (seen.has(key)) continue;
        seen.add(key);
        tokens.push({ pathname: parsed.pathname, params: Array.from(parsed.searchParams.keys()) });
    }
    return tokens;
}

/** Same-origin `<script src>` URLs referenced by the page. */
function extractScriptSrcs(body, baseUrl) {
    if (!body) return [];
    let base;
    try { base = new URL(baseUrl); } catch { return []; }
    const out = [];
    const seen = new Set();
    for (const m of body.matchAll(/<script[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
        let url;
        try { url = new URL(m[1], base); } catch { continue; }
        if (url.hostname !== base.hostname || url.port !== base.port) continue;
        const key = url.toString();
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(key);
    }
    return out;
}

/**
 * Mine page HTML + same-origin JS bundles for API endpoint candidates.
 * `fetchFn` must be budget/cancellation aware (the scanner passes fetchSafe) so
 * discovery can never run away with the request budget.
 */
async function discoverEndpoints(baseUrl, body, fetchFn = global.fetch, opts = {}) {
    const maxScripts = opts.maxScripts != null ? opts.maxScripts : 3;

    const map = new Map(); // pathname -> { params: Set, source }
    const add = (pathname, params, source) => {
        if (!isApiPath(pathname)) return;
        if (!map.has(pathname)) map.set(pathname, { params: new Set(), source });
        for (const p of params || []) map.get(pathname).params.add(p);
    };
    const mine = (text, source) => {
        for (const u of extractSameOriginUrls(text, baseUrl)) {
            let parsed;
            try { parsed = new URL(u); } catch { continue; }
            add(parsed.pathname, Array.from(parsed.searchParams.keys()), source);
        }
        for (const tok of extractApiPathTokens(text, baseUrl)) {
            add(tok.pathname, tok.params, source);
        }
    };

    let scripts = 0;
    mine(String(body || ''), baseUrl);

    // Structural mining with cheerio (in addition to the regex pass above):
    // link/area/iframe hrefs and form actions become API candidates when they
    // look like input surfaces, and are always reported as `links`/`forms` so
    // the surface fuzzer can test their parameters.
    const parsed = parseHtml(body, baseUrl);
    for (const link of parsed.links) {
        add(link.path, link.params, 'html');
    }
    for (const form of parsed.forms) {
        add(form.path, form.params, 'html');
    }

    for (const scriptUrl of extractScriptSrcs(body, baseUrl).slice(0, maxScripts)) {
        const resp = await fetchFn(scriptUrl, { method: 'GET', headers: { 'User-Agent': UA } }, 10000);
        if (!resp) continue;
        scripts += 1;
        const text = await resp.text().catch(() => '');
        mine(text, scriptUrl);
    }

    const endpoints = Array.from(map.entries())
        .map(([path, info]) => ({ path, params: Array.from(info.params), source: info.source }))
        .sort((a, b) => scoreEndpoint(b.path) - scoreEndpoint(a.path));

    return { endpoints, scripts, links: parsed.links, forms: parsed.forms };
}

async function crawlEndpoints(baseUrl, startBody, fetchFn = global.fetch, opts = {}) {
    const maxDepth = opts.maxDepth != null ? opts.maxDepth : 1;
    const maxVisited = opts.maxVisited != null ? opts.maxVisited : 30;
    if (maxDepth < 1) return { endpoints: [], links: [], forms: [], scripts: 0 };
    const base = new URL(baseUrl);
    const visited = new Set([base.toString()]);
    const queue = [];
    try {
        const dom = parseHtml(startBody, baseUrl);
        for (const link of dom.links || []) {
            try {
                const u = new URL(link.url);
                if (u.hostname === base.hostname && u.port === base.port) {
                    if (!visited.has(u.toString())) {
                        visited.add(u.toString());
                        queue.push({ url: u.toString(), depth: 1 });
                    }
                }
            } catch { /* ignore */ }
        }
    } catch { /* ignore */ }
    const endpointsMap = new Map();
    const links = [];
    const forms = [];
    let scripts = 0;
    while (queue.length > 0 && visited.size <= maxVisited) {
        const item = queue.shift();
        // `maxDepth: 1` means fetch pages linked directly from the root. The
        // former >= check skipped every queued page at the default depth.
        if (!item || item.depth > maxDepth) continue;
        try {
            const resp = await fetchFn(item.url, { method: 'GET', headers: { 'User-Agent': UA } }, 10000);
            if (!resp) continue;
            const body = await resp.text().catch(() => '');
            const dom = parseHtml(body, item.url);
            for (const link of dom.links || []) links.push(link);
            for (const form of dom.forms || []) forms.push(form);
            const disc = await discoverEndpoints(item.url, body, fetchFn, { maxScripts: opts.maxScripts || 0 });
            for (const e of disc.endpoints || []) {
                if (!endpointsMap.has(e.path)) endpointsMap.set(e.path, e);
            }
            scripts += disc.scripts || 0;
            for (const link of dom.links || []) {
                try {
                    const u = new URL(link.url);
                    if (u.hostname === base.hostname && u.port === base.port) {
                        const key = u.toString();
                        if (!visited.has(key)) {
                            visited.add(key);
                            if (visited.size > maxVisited) break;
                            queue.push({ url: key, depth: item.depth + 1 });
                        }
                    }
                } catch { /* ignore */ }
            }
            if (visited.size > maxVisited) break;
        } catch { /* ignore */ }
    }
    return { endpoints: Array.from(endpointsMap.values()), links, forms, scripts };
}

async function probeCommonPaths(baseUrl, fetchFn = global.fetch, opts = {}) {
    const commonPaths = opts.commonPaths || ['/login', '/signin', '/register', '/api'];
    const max = opts.maxProbesPerEndpoint != null ? opts.maxProbesPerEndpoint : 4;
    const endpointsMap = new Map();
    let base;
    try { base = new URL(baseUrl); } catch { return { endpoints: [] }; }
    const toProbe = commonPaths.slice(0, max);
    for (const p of toProbe) {
        try {
            const url = new URL(p, base);
            if (url.hostname !== base.hostname || url.port !== base.port) continue;
            const resp = await fetchFn(url.toString(), { method: 'GET', headers: { 'User-Agent': UA } }, 8000);
            if (!resp) continue;
            const body = await resp.text().catch(() => '');
            const dom = parseHtml(body, url.toString());
            const path = url.pathname;
            if (!endpointsMap.has(path)) endpointsMap.set(path, { path, params: [], source: 'probe' });
            for (const link of dom.links || []) {
                if (!endpointsMap.has(link.path)) endpointsMap.set(link.path, { path: link.path, params: link.params, source: 'probe' });
            }
            for (const form of dom.forms || []) {
                if (!endpointsMap.has(form.path)) endpointsMap.set(form.path, { path: form.path, params: form.params, source: 'probe' });
            }
        } catch { /* ignore */ }
    }
    return { endpoints: Array.from(endpointsMap.values()) };
}

module.exports = {
    runRecon,
    classifyContentType,
    extractFormParams,
    fingerprintTech,
    simpleHash,
    extractFingerprint,
    isApiPath,
    scoreEndpoint,
    extractSameOriginUrls,
    extractApiPathTokens,
    extractScriptSrcs,
    discoverEndpoints,
    crawlEndpoints,
    probeCommonPaths,
};
