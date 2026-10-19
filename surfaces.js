/**
 * Attack-surface discovery + type-appropriate fuzzing.
 *
 * The deterministic scanner historically tested only the single target URL.
 * Real apps expose far more input on *discovered* surfaces: navigation links
 * carrying query parameters (`artists.php?artist=1`), HTML forms (their action
 * plus field names) and same-origin API paths. This module turns the recon
 * output into a structural list of those surfaces, then runs the *existing*
 * detectors against each one with the fixed payload sets **and** the AI-written
 * payloads — without re-implementing any detection logic here.
 *
 * Kept separate from scanner.js/recon.js so neither file grows unbounded. The
 * module depends only on cheerio and the shared xss-guards helpers, and never
 * requires the scanner, so there is no circular import: scanner.js injects its
 * detector functions via `deps`.
 *
 * "Type-appropriate" testing is the core rule: every vulnerability class is
 * only fired at the surfaces that can actually carry it. A plain navigation
 * link with no parameters is *not* an injection surface, so it is skipped
 * entirely (there is nothing to put a payload into). Specialised classes
 * (path traversal, command injection, SSRF, open redirect) are gated on
 * parameter-name hints, while the two generic classes (SQL injection and
 * reflected XSS) run on any real parameter and rely on the detectors' own
 * evidence gates (error echo, executable sink, …) to avoid false positives.
 * GET surfaces are fuzzed through the query string; discovered POST forms are
 * fuzzed through a urlencoded request body.
 */

const cheerio = require('cheerio');
const { isRenderableHtml } = require('./xss-guards');

// Static assets are never input surfaces.
const STATIC_ASSET_RE = /\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|map|pdf|zip|gz|mp4|webm|mp3|wav|min\.js)$/i;

// Parameter-name hints that map a surface to a specialised vulnerability class.
// These are deliberately conservative: the classes they gate (traversal, command
// injection, SSRF, open redirect) are only meaningful when the parameter name
// suggests the corresponding sink. SQLi/XSS are handled as generic classes.
const PARAM_HINTS = {
    path_traversal: /(?:^|_)(?:file|filename|filepath|path|page|template|include|doc|document|download|dir|directory|folder|load|read|src|source|cat|newsad|adfile|bannerfile)(?:$|_)/i,
    command_injection: /(?:^|_)(?:cmd|exec|command|ping|host|hostname|ip|addr|address|process|run|system|shell|arg|args|func|function)(?:$|_)/i,
    ssrf: /(?:^|_)(?:url|uri|dest|destination|redirect|next|target|src|source|image|img|feed|webhook|callback|proxy|fetch|domain|host|site)(?:$|_)/i,
    open_redirect: /(?:^|_)(?:redirect|redirect_uri|redirect_url|url|next|target|dest|destination|return|returnurl|return_to|returnto|goto|continue|redir|link|out|jump)(?:$|_)/i,
};

// Stable ordering so callers/tests get deterministic results.
const TYPE_ORDER = ['sql_injection', 'xss', 'open_redirect', 'command_injection', 'path_traversal', 'ssrf'];

/**
 * Parse an HTML body with cheerio and extract same-origin, non-asset links,
 * forms (action + field names) and scripts. Zero extra requests — the body is
 * already in hand during recon.
 */
function parseHtml(html, baseUrl) {
    const out = { links: [], forms: [], scripts: [] };
    if (!html) return out;

    let base;
    try { base = new URL(baseUrl); } catch { return out; }

    let $;
    try { $ = cheerio.load(html); } catch { return out; }

    const sameOrigin = (raw) => {
        if (!raw) return null;
        let u;
        try { u = new URL(String(raw).trim(), base); } catch { return null; }
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
        if (u.hostname !== base.hostname || u.port !== base.port) return null;
        return u;
    };

    const seenLinks = new Set();
    $('a[href], area[href], iframe[src], frame[src]').each((_, el) => {
        const raw = $(el).attr('href') || $(el).attr('src');
        const u = sameOrigin(raw);
        if (!u) return;
        if (STATIC_ASSET_RE.test(u.pathname)) return;
        const key = u.pathname + u.search;
        if (seenLinks.has(key)) return;
        seenLinks.add(key);
        out.links.push({
            url: u.toString(),
            path: u.pathname,
            params: Array.from(u.searchParams.keys()),
            tag: (el.tagName || '').toLowerCase(),
        });
    });

    const seenScripts = new Set();
    $('script[src]').each((_, el) => {
        const u = sameOrigin($(el).attr('src'));
        if (!u) return;
        const key = u.toString();
        if (seenScripts.has(key)) return;
        seenScripts.add(key);
        out.scripts.push(key);
    });

    const seenForms = new Set();
    $('form').each((_, el) => {
        const $f = $(el);
        const rawAction = $f.attr('action') || base.pathname || '/';
        const u = sameOrigin(rawAction);
        if (!u) return;
        const method = String($f.attr('method') || 'get').toLowerCase() === 'post' ? 'post' : 'get';
        const params = [];
        const probeParams = [];
        const values = {};
        $f.find('input[name], select[name], textarea[name], button[name]').each((__, field) => {
            const name = $(field).attr('name');
            if (!name) return;
            if (!params.includes(name)) params.push(name);

            const tag = String(field.tagName || '').toLowerCase();
            const $field = $(field);
            let value = $field.attr('value') || '';
            let type = String($field.attr('type') || 'text').toLowerCase();
            if (tag === 'textarea') value = $field.text();
            if (tag === 'select') {
                const $selected = $field.find('option[selected]').first();
                const $option = $selected.length ? $selected : $field.find('option').first();
                value = $option.attr('value') ?? $option.text();
            }
            if ((type === 'checkbox' || type === 'radio') && !$field.is('[checked]')) return;
            if ((type === 'checkbox' || type === 'radio') && !value) value = 'on';
            values[name] = value;

            const frameworkState = /^__(?:VIEWSTATE|VIEWSTATEGENERATOR|VIEWSTATEENCRYPTED|EVENTVALIDATION|EVENTTARGET|EVENTARGUMENT)$/i.test(name);
            const nonInputControl = tag === 'button' || /^(?:submit|button|reset|image|hidden)$/i.test(type);
            if (!frameworkState && !nonInputControl && !probeParams.includes(name)) probeParams.push(name);
        });
        for (const p of u.searchParams.keys()) if (!params.includes(p)) params.push(p);
        const key = method + ' ' + u.pathname;
        if (seenForms.has(key)) return;
        seenForms.add(key);
        out.forms.push({ url: u.toString(), path: u.pathname, method, params, probeParams, values });
    });

    return out;
}

/**
 * Turn recon output (API endpoints + cheerio links + forms) into a deduped list
 * of surface objects: `{ url, path, method, params, kind }`.
 */
function buildSurfaces(reconData, baseUrl) {
    const surfaces = [];
    const index = new Map();

    let base;
    try { base = new URL(baseUrl); } catch { base = null; }

    const resolve = (raw) => {
        if (!raw || !base) return null;
        let u;
        try { u = new URL(raw, base); } catch { return null; }
        if (u.hostname !== base.hostname || u.port !== base.port) return null;
        return u;
    };

    const addSurface = (s) => {
        const key = (s.method || 'get') + ' ' + s.path;
        const existing = index.get(key);
        if (existing) {
            for (const p of s.params) if (!existing.params.includes(p)) existing.params.push(p);
            for (const p of (s.probeParams || [])) if (!existing.probeParams.includes(p)) existing.probeParams.push(p);
            existing.formFields = { ...(existing.formFields || {}), ...(s.formFields || {}) };
            const rank = { api: 3, form: 2, link: 1 };
            if ((rank[s.kind] || 0) > (rank[existing.kind] || 0)) existing.kind = s.kind;
            return;
        }
        index.set(key, s);
        surfaces.push(s);
    };

    for (const ep of (reconData.endpoints || [])) {
        const u = resolve(ep.path);
        if (!u || STATIC_ASSET_RE.test(u.pathname)) continue;
        addSurface({ url: u.toString(), path: u.pathname, method: 'get', params: [...(ep.params || [])], probeParams: [...(ep.params || [])], formFields: {}, kind: 'api', source: ep.source });
    }
    for (const link of (reconData.links || [])) {
        const u = resolve(link.url || link.path);
        if (!u || STATIC_ASSET_RE.test(u.pathname)) continue;
        addSurface({ url: u.toString(), path: u.pathname, method: 'get', params: [...(link.params || [])], probeParams: [...(link.params || [])], formFields: {}, kind: 'link' });
    }
    for (const form of (reconData.forms || [])) {
        const u = resolve(form.url || form.path);
        if (!u || STATIC_ASSET_RE.test(u.pathname)) continue;
        addSurface({ url: u.toString(), path: u.pathname, method: (form.method || 'get').toLowerCase(), params: [...(form.params || [])], probeParams: [...(form.probeParams || [])], formFields: { ...(form.values || {}) }, kind: 'form' });
    }

    return surfaces;
}

/**
 * Decide which vulnerability classes are worth testing on a surface.
 * Returns `{ types: string[], reason: string }`.
 *
 * A surface with no parameters has nothing to inject → no types (the "you do
 * not run SQL injection against an href tag" rule). Otherwise SQLi + reflected
 * XSS are the generic baseline (unless the response is not HTML-renderable, in
 * which case XSS cannot execute and is dropped), and the specialised classes
 * are added only when a parameter name hints at their sink.
 */
function classifySurface(surface, ctx = {}) {
    const params = Array.isArray(surface && surface.probeParams) ? surface.probeParams
        : Array.isArray(surface && surface.params) ? surface.params : [];
    if (params.length === 0) {
        return { types: [], reason: 'no-injectable-params' };
    }

    const types = new Set(['sql_injection']);
    if (ctx.renderable !== false) types.add('xss');

    for (const name of params) {
        for (const [type, re] of Object.entries(PARAM_HINTS)) {
            if (re.test(name)) types.add(type);
        }
    }

    return {
        types: TYPE_ORDER.filter((t) => types.has(t)),
        reason: 'param-hints',
    };
}

/** Build the probe URL used by the detectors: ensure every param is present. */
function surfaceProbeUrl(surface) {
    const u = new URL(surface.url);
    for (const p of (surface.params || [])) {
        if (!u.searchParams.has(p)) u.searchParams.set(p, '1');
    }
    return u.toString();
}

/**
 * Build the benign baseline request for a surface. GET surfaces carry their
 * parameters in the query; POST surfaces send them as a urlencoded body (their
 * parameters are not in the URL at all, so the detector is told the candidate
 * list explicitly, see runSurfaceFuzzing).
 */
function surfaceBaseRequest(surface, ua) {
    const method = (surface.method || 'get').toLowerCase();
    if (method === 'post') {
        const fields = { ...(surface.formFields || {}) };
        if (Object.keys(fields).length === 0) {
            for (const p of (surface.probeParams || surface.params || [])) fields[p] = '1';
        }
        return {
            url: surface.url,
            init: {
                method: 'POST',
                headers: { 'User-Agent': ua, 'Content-Type': 'application/x-www-form-urlencoded', ...(surface.requestHeaders || {}) },
                body: new URLSearchParams(fields).toString(),
            },
        };
    }
    return {
        url: surfaceProbeUrl(surface),
        init: { method: 'GET', headers: { 'User-Agent': ua } },
    };
}

/** Priority score so the most injectable surfaces are fuzzed first. */
function surfaceScore(surface) {
    let s = 0;
    if (surface.params && surface.params.length) s += 4;
    if (surface.kind === 'api') s += 2;
    if (surface.kind === 'form') s += 1;
    if (/\.(?:php|asp|aspx|jsp|jspx|cgi|pl|do|action)(?:\/|$)/i.test(surface.path)) s += 2;
    if (/(?:search|query|login|register|user|product|item|order|artist|category|file|path|url|redirect|id)/i.test((surface.params || []).join('&'))) s += 1;
    return s;
}

/**
 * Fuzz every discovered surface with the type-appropriate detector set.
 *
 * `deps` is injected by scanner.js to avoid a circular import:
 *   { fetchSafe, addEvent, simpleHash, isSoft404, config,
 *     scanCancelled, scanBudgetExhausted, detectors, UA }
 *
 * `detectors` maps a vulnerability type to `(url, aiPayloads, opts) => Promise`,
 * where the scanner has already bound scanId/baseline into each closure.
 */
async function runSurfaceFuzzing(opts) {
    const { scanId, url, reconData, ai = {}, deps } = opts;
    const {
        fetchSafe, addEvent, simpleHash, isSoft404, config,
        scanCancelled, scanBudgetExhausted, detectors, UA = 'SecureProbe/2.0',
    } = deps;

    const discovered = buildSurfaces(reconData || {}, url);
    if (discovered.length === 0) return { tested: 0, surfaces: 0 };

    const maxSurfaces = (config && config.scanner && config.scanner.scanDiscovery && config.scanner.scanDiscovery.maxSurfaces) || 12;
    const selected = discovered
        .slice()
        .sort((a, b) => surfaceScore(b) - surfaceScore(a))
        .slice(0, maxSurfaces);

    addEvent(scanId, 'surface_fuzz', 'info', 'Fuzzing Discovered Surfaces',
        `Matched ${selected.length} of ${discovered.length} discovered surface(s) to type-appropriate fixed + AI payload sets.`, {});

    const rootHash = reconData && reconData.base ? reconData.base.bodyHash : null;
    const rootStatus = reconData && reconData.base ? reconData.base.status : null;
    const baseline = reconData && reconData.base ? reconData.base : null;

    let tested = 0;
    for (const surface of selected) {
        if (scanCancelled() || scanBudgetExhausted()) break;

        let probeParams = surface.probeParams || surface.params;
        // Hidden framework state and submit buttons preserve form state but
        // are not useful fuzz inputs. Skip forms with no user-controlled field.
        if (!probeParams.length) continue;

        const method = (surface.method || 'get').toLowerCase();
        if (method === 'post') {
            // ASP.NET WebForms and similar frameworks require the real hidden
            // state and session cookie returned by a preceding GET. Replaying
            // placeholder values causes every POST probe to be rejected before
            // the vulnerable field is processed.
            const bootstrap = await fetchSafe(surface.url, { method: 'GET', headers: { 'User-Agent': UA } }, 8000);
            if (!bootstrap) {
                addEvent(scanId, 'surface_fuzz', 'warning', 'Form Bootstrap Failed',
                    `GET ${surface.path} failed; its POST inputs were not tested.`, { severity: 'info' });
                continue;
            }
            const bootstrapBody = await bootstrap.text().catch(() => '');
            const forms = parseHtml(bootstrapBody, surface.url).forms;
            const form = forms.find((candidate) => candidate.method === 'post' && candidate.path === surface.path);
            if (form) {
                surface.params = [...new Set([...surface.params, ...form.params])];
                surface.probeParams = [...new Set([...surface.probeParams, ...form.probeParams])];
                surface.formFields = { ...(surface.formFields || {}), ...form.values };
                probeParams = surface.probeParams;
            }
            let cookieLines = [];
            try {
                cookieLines = typeof bootstrap.headers.getSetCookie === 'function'
                    ? bootstrap.headers.getSetCookie()
                    : [bootstrap.headers.get('set-cookie')].filter(Boolean);
            } catch { /* no cookie header */ }
            const cookies = cookieLines.map((line) => String(line).split(';')[0]).filter(Boolean);
            if (cookies.length) surface.requestHeaders = { ...(surface.requestHeaders || {}), Cookie: cookies.join('; ') };
        }

        // Baseline request uses the surface's own method (GET query vs POST
        // body) so the response we classify and the detector's requests match.
        const baseReq = surfaceBaseRequest(surface, UA);
        const resp = await fetchSafe(baseReq.url, baseReq.init, 8000);
        if (!resp) {
            addEvent(scanId, 'surface_fuzz', 'warning', 'Surface Unreachable',
                `${(surface.method || 'get').toUpperCase()} ${surface.path} failed (timeout or connection error) — not tested.`, { severity: 'info' });
            continue;
        }
        let body = '';
        try { body = await resp.text(); } catch { /* ignore */ }

        // Same SPA client-route guard the API prober uses: an identical index
        // page means client-side navigation, not a server-side surface.
        if (rootHash && rootStatus != null && resp.status === rootStatus && simpleHash(body) === rootHash) {
            addEvent(scanId, 'surface_fuzz', 'info', 'Client-Side Route Skipped',
                `${surface.path} returns the SPA index page — no server surface to test.`, {});
            continue;
        }
        if (isSoft404(body, resp.status, baseline)) continue;

        const ct = resp.headers.get('content-type') || '';
        const renderable = isRenderableHtml(ct);
        const { types } = classifySurface(surface, { renderable });
        if (types.length === 0) continue;

        const inject = {
            method,
            formFields: method === 'post'
                ? { ...(surface.formFields || {}) }
                : undefined,
            headers: method === 'post' ? surface.requestHeaders : undefined,
            paramCandidates: probeParams,
        };

        tested += 1;
        for (const type of types) {
            if (scanCancelled() || scanBudgetExhausted()) return { tested, surfaces: selected.length };
            const detector = detectors[type];
            if (!detector) continue;
            const aiPayloads = Array.isArray(ai[type]) ? ai[type] : [];
            try {
                await detector(baseReq.url, aiPayloads, { baselineBody: body, inject });
            } catch (err) {
                addEvent(scanId, 'surface_fuzz', 'warning', `${type} check failed on surface`,
                    `${surface.path}: ${String((err && err.message) || err)}`, { severity: 'info' });
            }
        }
    }

    return { tested, surfaces: selected.length };
}

module.exports = {
    parseHtml,
    buildSurfaces,
    classifySurface,
    surfaceProbeUrl,
    surfaceBaseRequest,
    surfaceScore,
    runSurfaceFuzzing,
    PARAM_HINTS,
    TYPE_ORDER,
    STATIC_ASSET_RE,
};
