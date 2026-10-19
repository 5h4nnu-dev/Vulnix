/** Small per-scan, origin-scoped cookie jar for ordinary web form workflows. */
function cookieLines(headers) {
    if (!headers) return [];
    if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
    const raw = headers.get && headers.get('set-cookie');
    if (!raw) return [];
    // A comma in an Expires date is not followed by a cookie-name=value pair.
    return raw.split(/,(?=\s*[^;,=\s]+=[^;,]*)/g);
}

function applyCookies(url, headers, jar) {
    if (!(jar instanceof Map)) return headers;
    let origin;
    try { origin = new URL(url).origin; } catch { return headers; }
    const values = jar.get(origin);
    if (!values || values.size === 0) return headers;
    const parsed = new URL(url);
    const pathMatches = (requestPath, cookiePath) => requestPath === cookiePath ||
        (requestPath.startsWith(cookiePath) && (cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/'));
    const cookieHeader = [...values.entries()]
        .filter(([, cookie]) => (!cookie.secure || parsed.protocol === 'https:') &&
            pathMatches(parsed.pathname, cookie.path) && (!cookie.expiresAt || cookie.expiresAt > Date.now()))
        .map(([name, cookie]) => `${name}=${cookie.value}`)
        .join('; ');
    if (!cookieHeader) return headers;
    const existingKey = Object.keys(headers).find((key) => key.toLowerCase() === 'cookie');
    return { ...headers, Cookie: existingKey ? `${headers[existingKey]}; ${cookieHeader}` : cookieHeader };
}

function captureCookies(url, responseHeaders, jar) {
    if (!(jar instanceof Map)) return;
    let origin;
    let parsed;
    try { parsed = new URL(url); origin = parsed.origin; } catch { return; }
    const values = jar.get(origin) || new Map();
    for (const line of cookieLines(responseHeaders)) {
        const first = String(line).split(';', 1)[0];
        const splitAt = first.indexOf('=');
        if (splitAt <= 0) continue;
        const name = first.slice(0, splitAt).trim();
        const value = first.slice(splitAt + 1).trim();
        const attrs = String(line).split(';').slice(1).map((attr) => attr.trim());
        const pathAttr = attrs.find((attr) => /^path=/i.test(attr));
        const defaultPath = parsed.pathname.slice(0, parsed.pathname.lastIndexOf('/') + 1) || '/';
        const path = pathAttr ? pathAttr.slice(pathAttr.indexOf('=') + 1) : defaultPath;
        const key = `${name};${path}`;
        if (/max-age\s*=\s*0/i.test(line)) values.delete(key);
        else {
            const maxAgeAttr = attrs.find((attr) => /^max-age=/i.test(attr));
            const expiresAttr = attrs.find((attr) => /^expires=/i.test(attr));
            const maxAge = maxAgeAttr ? Number(maxAgeAttr.slice(maxAgeAttr.indexOf('=') + 1)) : null;
            const expiresAt = Number.isFinite(maxAge)
                ? Date.now() + Math.max(0, maxAge) * 1000
                : (expiresAttr ? Date.parse(expiresAttr.slice(expiresAttr.indexOf('=') + 1)) : null);
            values.set(key, { value, path, secure: attrs.some((attr) => /^secure$/i.test(attr)), expiresAt: Number.isFinite(expiresAt) ? expiresAt : null });
        }
    }
    if (values.size) jar.set(origin, values);
    else jar.delete(origin);
}

module.exports = { applyCookies, captureCookies };
