/**
 * Secret redaction.
 *
 * Target data (headers, bodies) is sent to the model for analysis. This module
 * scrubs the most common credential shapes before anything leaves the host so
 * we never feed live secrets into a model context.
 */

const REDACT = '[REDACTED]';

// Header names whose values should always be scrubbed.
const SENSITIVE_HEADERS = [
    'authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'x-auth-token',
    'proxy-authorization',
    'x-csrf-token',
    'x-xsrf-token',
];

// Value patterns that look like secrets regardless of key names.
const SECRET_PATTERNS = [
    // JWT
    /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    // OpenAI keys
    /\bsk-[A-Za-z0-9]{20,}\b/g,
    // AWS access key id
    /\bAKIA[0-9A-Z]{16}\b/g,
    // Bearer tokens
    /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi,
    // Basic auth
    /\bBasic\s+[A-Za-z0-9+/=]{12,}/gi,
    // PEM private keys
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    // Long hex secrets assigned to a variable
    /\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)\b\s*[:=]\s*["']?([^\s"',;]{6,})["']?/gi,
];

/**
 * Redact a plain string.
 * @param {string} input
 * @returns {string}
 */
function redactString(input) {
    if (typeof input !== 'string' || input.length === 0) return input;
    let out = input;
    for (const pattern of SECRET_PATTERNS) {
        out = out.replace(pattern, (match, group) => {
            // For the assignment-style pattern keep the key, scrub the value.
            if (group && /password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key/i.test(group)) {
                const eqIndex = match.search(/[:=]/);
                if (eqIndex !== -1) {
                    return match.slice(0, eqIndex + 1) + ' ' + REDACT;
                }
            }
            return REDACT;
        });
    }
    return out;
}

/**
 * Redact header values by header name.
 * @param {object|Array} headers - plain object or [[key, value]] pairs
 * @returns {object}
 */
function redactHeaders(headers) {
    const out = {};
    if (!headers) return out;

    const entries = Array.isArray(headers)
        ? headers
        : Object.entries(headers);

    for (const [key, value] of entries) {
        const lower = String(key).toLowerCase();
        out[key] = SENSITIVE_HEADERS.includes(lower) ? REDACT : redactString(String(value));
    }
    return out;
}

/**
 * Cap a body to a maximum length and redact secrets. Very large bodies are
 * truncated so we don't blow up the model context window.
 * @param {string} body
 * @param {number} maxLen
 * @returns {string}
 */
function redactBody(body, maxLen = 4000) {
    if (typeof body !== 'string') return '';
    const redacted = redactString(body);
    if (redacted.length <= maxLen) return redacted;
    return redacted.slice(0, maxLen) + `\n...[truncated ${redacted.length - maxLen} chars]`;
}

/** Recursively scrub secret-like values before agent observations reach an LLM. */
function redactObject(value, key = '') {
    if (/(?:authorization|cookie|token|secret|password|passwd|api[_-]?key|csrf|xsrf|viewstate|eventvalidation)/i.test(key)) {
        return REDACT;
    }
    if (typeof value === 'string') return redactString(value);
    if (Array.isArray(value)) return value.map((item) => redactObject(item));
    if (value && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactObject(v, k)]));
    }
    return value;
}

module.exports = {
    REDACT,
    redactString,
    redactHeaders,
    redactBody,
    redactObject,
    SENSITIVE_HEADERS,
};
