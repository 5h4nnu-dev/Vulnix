/**
 * Agent policy — scope and safety enforcement.
 *
 * Every action the model requests passes through validateAction() before the
 * harness executes it. This is the hard boundary; the model cannot bypass it.
 */

const config = require('../config');

const DESTRUCTIVE_METHODS = ['PUT', 'DELETE', 'PATCH'];
const ALLOWED_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS', ...DESTRUCTIVE_METHODS];

// Hosts that must never be contacted by the scanner (cloud metadata, etc.).
const BLOCKED_HOSTS = ['169.254.169.254', 'metadata.google.internal', 'metadata.google'];

/**
 * True when a hostname is a private / loopback / link-local address.
 * @param {string} hostname
 * @returns {boolean}
 */
function isInternalHost(hostname) {
    if (!hostname) return true;
    const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');

    if (host === 'localhost' || host.endsWith('.localhost')) return true;
    if (host === '::1') return true;

    // IPv4 private / loopback / link-local / metadata ranges
    const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (v4) {
        const [a, b] = v4.slice(1).map(Number);
        if (a === 10) return true;
        if (a === 127) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 168) return true;
        if (a === 169 && b === 254) return true; // link-local + metadata
        if (a === 0) return true;
    }

    // IPv6 unique-local / link-local
    if (/^fe80:/i.test(host) || /^fc00:/i.test(host) || /^fd[0-9a-f]{2}:/i.test(host)) return true;

    return false;
}

/**
 * Check whether a URL is within the authorized scope.
 * @param {string} url
 * @param {string} targetUrl - the original scan target (always in scope)
 * @returns {{ allowed: boolean, reason?: string, host?: string }}
 */
function checkScope(url, targetUrl) {
    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        return { allowed: false, reason: 'invalid URL' };
    }

    if (!/^https?:$/.test(parsed.protocol)) {
        return { allowed: false, reason: `blocked protocol: ${parsed.protocol}` };
    }

    const host = parsed.hostname.toLowerCase();

    if (BLOCKED_HOSTS.includes(host)) {
        return { allowed: false, reason: 'cloud metadata endpoint blocked' };
    }
    if (isInternalHost(host) && !config.security.allowInternalIps) {
        // Allow the original target even if it is localhost (local testing).
        let sameAsTarget = false;
        try { sameAsTarget = new URL(targetUrl).hostname.toLowerCase() === host; } catch { /* ignore */ }
        if (!sameAsTarget) {
            return { allowed: false, reason: 'internal/private address blocked' };
        }
    }

    const allow = config.security.authorizedTargets;
    if (allow.length > 0) {
        const inScope = allow.some((entry) => host === entry.toLowerCase() || host.endsWith('.' + entry.toLowerCase()));
        if (!inScope) return { allowed: false, reason: `host not in AUTHORIZED_TARGETS: ${host}` };
    }

    return { allowed: true, host };
}

/**
 * Validate a model-requested action against policy.
 * @param {string} name - tool name
 * @param {object} args
 * @param {object} ctx - { targetUrl, requestCount }
 * @returns {{ allowed: boolean, reason?: string, url?: string }}
 */
function validateAction(name, args, ctx = {}) {
    const a = args || {};

    if (a.method && !ALLOWED_METHODS.includes(String(a.method).toUpperCase())) {
        return { allowed: false, reason: `method not allowed: ${a.method}` };
    }
    if (
        a.method &&
        DESTRUCTIVE_METHODS.includes(String(a.method).toUpperCase()) &&
        !config.agent.allowDestructive
    ) {
        return { allowed: false, reason: `destructive method disabled: ${a.method} (set AGENT_ALLOW_DESTRUCTIVE=true)` };
    }

    if (name === 'http_request' || name === 'test_parameter') {
        const url = name === 'http_request' ? a.url : a.endpoint;
        if (!url) return { allowed: false, reason: 'missing url' };
        const scope = checkScope(url, ctx.targetUrl);
        if (!scope.allowed) return { allowed: false, reason: scope.reason };
        return { allowed: true, url };
    }

    if (name === 'crawl') {
        const path = a.path || '/';
        let url;
        try {
            url = new URL(path, ctx.targetUrl).toString();
        } catch {
            return { allowed: false, reason: 'invalid crawl path' };
        }
        const scope = checkScope(url, ctx.targetUrl);
        if (!scope.allowed) return { allowed: false, reason: scope.reason };
        return { allowed: true, url };
    }

    return { allowed: true };
}

module.exports = {
    isInternalHost,
    checkScope,
    validateAction,
    ALLOWED_METHODS,
    DESTRUCTIVE_METHODS,
};
