/**
 * Prompt-injection guard.
 *
 * Two responsibilities:
 *   1. Detect prompt-injection attempts inside UNTRUSTED target content
 *      (responses, headers, HTML) that is about to be shown to the model.
 *   2. Validate model OUTPUT so the harness never executes anything the model
 *      "asked" for beyond the strict, inert schemas we expect.
 *
 * Target content is NEVER treated as instructions. The model is told the same
 * via llm/prompts.js; this module is the enforcement layer.
 */

// ── Injection detection ──────────────────────────────────────────────────────

const INJECTION_PATTERNS = [
    // Classic instruction override
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)/i,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)/i,
    /forget\s+(all\s+)?(previous|prior|above|your)\s+(instructions|prompts|rules)/i,
    // Role / persona hijack
    /\byou\s+are\s+now\b/i,
    /\bact\s+as\s+(a|an|the)\b/i,
    /\bnew\s+(system\s+)?(instructions|prompt|rules)\b/i,
    // Fake system turns
    /^\s*(system|assistant|developer)\s*:/im,
    /<\|?(system|im_start|im_end|endoftext)\|?>/i,
    /\[\/?INST\]/i,
    // Tool / action smuggling
    /\b(tool_call|function_call|tool_calls)\b/i,
    /"action"\s*:\s*"[a-z_]+"/i,
    // System prompt exfiltration
    /(reveal|print|show|repeat|output)\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions|rules)/i,
    // Canary exfiltration via markdown image
    /!\[[^\]]*\]\(\s*https?:\/\/[^)]+\)/i,
    // Direct references to our harness internals
    /\b(vulnix|secureprobe|neosec)\b.*\b(ignore|instruction|prompt)\b/i,
];

/**
 * Scan untrusted text for prompt-injection indicators.
 * @param {string} text
 * @returns {{ flagged: boolean, matches: string[], score: number }}
 */
function detectInjection(text) {
    if (typeof text !== 'string' || text.length === 0) {
        return { flagged: false, matches: [], score: 0 };
    }

    const matches = [];
    for (const pattern of INJECTION_PATTERNS) {
        const m = text.match(pattern);
        if (m) matches.push(m[0].slice(0, 160));
    }

    return {
        flagged: matches.length > 0,
        matches,
        score: matches.length,
    };
}

/**
 * Wrap untrusted target content in explicit data delimiters so the model can
 * distinguish data from instructions. Any delimiter sequences inside the
 * content are neutralized first to prevent delimiter escape.
 * @param {string} content
 * @param {string} label
 * @returns {string}
 */
function isolate(content, label = 'UNTRUSTED_TARGET_DATA') {
    const text = typeof content === 'string' ? content : JSON.stringify(content);
    // Neutralize attempted delimiter breaks inside the payload.
    const safe = text
        .replace(/<<<[^>]*>>>/g, '[delimiter-removed]')
        .replace(/```/g, '``\u200b`');
    return `<<<${label}>>>\n${safe}\n<<<END_${label}>>>`;
}

/**
 * Run isolation + detection in one step. Returns the wrapped content and the
 * detection verdict so callers can log an event.
 * @param {string} content
 * @param {string} label
 * @returns {{ content: string, detection: object }}
 */
function guardContent(content, label) {
    const detection = detectInjection(content);
    return { content: isolate(content, label), detection };
}

// ── Output validation ────────────────────────────────────────────────────────

// Instructions the model is never allowed to place into output schemas.
const DANGEROUS_OUTPUT_PATTERNS = [
    /require\s*\(/i,
    /child_process/i,
    /\bexec\s*\(/i,
    /\bspawn\s*\(/i,
    /\beval\s*\(/i,
    /process\.env/i,
    /\bfs\.(read|write|unlink|rm)/i,
    /\brm\s+-rf\b/i,
    /\bcurl\s+http/i,
    /\bwget\s+http/i,
    /\/etc\/passwd\s*\)/i, // shell command reading passwd (payloads use quotes)
    /writeFile|readFileSync|unlinkSync/i,
    /<<<END_/i,
];

/**
 * Check a model-produced string for content that should never be executed by
 * the harness. Payload *data* (SQLi/XSS strings) is fine; control-flow is not.
 * @param {string} text
 * @returns {{ safe: boolean, reason?: string }}
 */
function isSafeOutput(text) {
    if (typeof text !== 'string') return { safe: true };
    for (const pattern of DANGEROUS_OUTPUT_PATTERNS) {
        if (pattern.test(text)) {
            return { safe: false, reason: `blocked pattern: ${pattern}` };
        }
    }
    return { safe: true };
}

/**
 * Extract a JSON object from a model response that may include prose or code
 * fences. Returns null when nothing parseable is found.
 * @param {string} text
 * @returns {object|null}
 */
function extractJson(text) {
    if (typeof text !== 'string') return null;
    const trimmed = text.trim();

    // Direct parse
    try {
        return JSON.parse(trimmed);
    } catch { /* continue */ }

    // Fenced ```json ... ```
    const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (fence) {
        try { return JSON.parse(fence[1].trim()); } catch { /* continue */ }
    }

    // First {...} balanced block
    const first = trimmed.indexOf('{');
    const last = trimmed.lastIndexOf('}');
    if (first !== -1 && last > first) {
        try { return JSON.parse(trimmed.slice(first, last + 1)); } catch { /* continue */ }
    }

    return null;
}

/**
 * Validate and normalize an array of AI-generated payloads.
 * Enforces the schema, caps the count, dedupes, and rejects unsafe entries.
 *
 * @param {any} raw - parsed model output ({ payloads: [...] })
 * @param {object} opts
 * @param {number} opts.max - maximum payloads to keep
 * @param {string[]} opts.exclude - existing payload strings to dedupe against
 * @returns {{ payloads: object[], rejected: object[] }}
 */
function validatePayloads(raw, opts = {}) {
    const max = Number.isFinite(opts.max) ? opts.max : 12;
    const exclude = new Set(opts.exclude || []);
    const list = raw && Array.isArray(raw.payloads) ? raw.payloads : [];
    const seen = new Set();
    const payloads = [];
    const rejected = [];

    for (const item of list) {
        if (!item || typeof item !== 'object') continue;

        const payload = typeof item.payload === 'string' ? item.payload.trim() : '';
        if (!payload) {
            rejected.push({ item, reason: 'empty payload' });
            continue;
        }
        if (payload.length > 2000) {
            rejected.push({ item, reason: 'payload too long' });
            continue;
        }
        const key = payload.toLowerCase();
        if (seen.has(key) || exclude.has(key)) {
            rejected.push({ item, reason: 'duplicate' });
            continue;
        }
        const safety = isSafeOutput(payload);
        if (!safety.safe) {
            rejected.push({ item, reason: safety.reason });
            continue;
        }

        seen.add(key);
        payloads.push({
            payload,
            type: typeof item.type === 'string' && item.type ? item.type : 'ai_generated',
            rationale: typeof item.rationale === 'string' ? item.rationale.slice(0, 500) : '',
            expected_behavior: typeof item.expected_behavior === 'string' ? item.expected_behavior.slice(0, 500) : '',
            detection: typeof item.detection === 'string' ? item.detection : 'error',
            target_param: typeof item.target_param === 'string' ? item.target_param : null,
            source: 'ai',
        });

        if (payloads.length >= max) break;
    }

    return { payloads, rejected };
}

module.exports = {
    INJECTION_PATTERNS,
    detectInjection,
    isolate,
    guardContent,
    isSafeOutput,
    extractJson,
    validatePayloads,
};
