/**
 * LLM client — provider abstraction.
 *
 * Supports:
 *   - ollama            (local, default — data never leaves the host)
 *   - openai            (any OpenAI-compatible /chat/completions endpoint)
 *
 * Exposes a single `chat(messages, opts)` shape regardless of provider.
 * Uses the Node 18+ global fetch; no SDKs required.
 */

const config = require('../config');
const { pickModel } = require('./models');
const { extractJson } = require('./guard');

let _resolvedModel = null;

// ── Low-level HTTP ───────────────────────────────────────────────────────────

async function httpJson(url, options = {}, timeoutMs = 60000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const resp = await fetch(url, { ...options, signal: controller.signal });
        const text = await resp.text();
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch { json = null; }
        return { ok: resp.ok, status: resp.status, json, text };
    } catch (err) {
        return { ok: false, status: 0, json: null, text: String(err && err.message ? err.message : err) };
    } finally {
        clearTimeout(timer);
    }
}

// ── Provider helpers ─────────────────────────────────────────────────────────

function isOllama() {
    return config.llm.provider !== 'openai';
}

async function listModels() {
    if (isOllama()) {
        const res = await httpJson(`${config.llm.ollamaHost}/api/tags`, { method: 'GET' }, 10000);
        if (!res.ok || !res.json) return [];
        return (res.json.models || []).map((m) => m.name).filter(Boolean);
    }
    const headers = {};
    if (config.llm.openaiApiKey) headers.Authorization = `Bearer ${config.llm.openaiApiKey}`;
    const res = await httpJson(`${config.llm.openaiBaseUrl}/v1/models`, { method: 'GET', headers }, 10000);
    if (!res.ok || !res.json) return [];
    return (res.json.data || []).map((m) => m.id).filter(Boolean);
}

async function health() {
    const models = await listModels();
    const reachable = models.length > 0;
    return {
        reachable,
        provider: config.llm.provider,
        endpoint: isOllama() ? config.llm.ollamaHost : config.llm.openaiBaseUrl,
        models,
        model: reachable ? await resolveModel(models) : null,
    };
}

/**
 * Resolve the model to use. Prefers explicit config, then the first model the
 * provider reports (ranked by llm/models.js).
 */
async function resolveModel(knownModels) {
    if (config.llm.model) return config.llm.model;
    if (_resolvedModel) return _resolvedModel;
    const models = knownModels || (await listModels());
    _resolvedModel = pickModel(models);
    return _resolvedModel;
}

function resetModelCache() {
    _resolvedModel = null;
}

// ── Chat ─────────────────────────────────────────────────────────────────────

function normalizeOpenAiToolCalls(toolCalls) {
    if (!Array.isArray(toolCalls)) return [];
    const out = [];
    for (const tc of toolCalls) {
        const fn = tc.function || {};
        let args = fn.arguments;
        if (typeof args === 'string') {
            try { args = JSON.parse(args); } catch { args = {}; }
        }
        out.push({ id: tc.id || `call_${out.length}`, name: fn.name, args: args || {} });
    }
    return out;
}

function normalizeOllamaToolCalls(toolCalls) {
    if (!Array.isArray(toolCalls)) return [];
    return toolCalls.map((tc, i) => {
        const fn = tc.function || {};
        let args = fn.arguments;
        if (typeof args === 'string') {
            try { args = JSON.parse(args); } catch { args = {}; }
        }
        return { id: tc.id || `call_${i}`, name: fn.name, args: args || {} };
    });
}

/**
 * Send a chat completion request.
 *
 * @param {Array<{role:string, content:string}>} messages
 * @param {object} [opts]
 * @param {boolean} [opts.json]       - request strict JSON output
 * @param {number}  [opts.temperature]
 * @param {number}  [opts.maxTokens]
 * @param {number}  [opts.timeoutMs]
 * @param {string}  [opts.model]
 * @returns {Promise<{content:string, toolCalls:Array, model:string, provider:string, usage:object}>}
 */
async function chat(messages, opts = {}) {
    const temperature = opts.temperature ?? config.llm.temperature;
    const timeoutMs = opts.timeoutMs ?? config.llm.timeoutMs;
    const model = opts.model || (await resolveModel());

    if (!model) {
        throw new Error('No LLM model available (provider returned no models). Set LLM_MODEL or start Ollama.');
    }

    if (isOllama()) {
        const body = {
            model,
            messages,
            stream: false,
            options: { temperature },
        };
        if (opts.json) body.format = 'json';
        if (Number.isFinite(opts.maxTokens)) body.options.num_predict = opts.maxTokens;

        const res = await httpJson(`${config.llm.ollamaHost}/api/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        }, timeoutMs);

        if (!res.ok || !res.json) {
            throw new Error(`Ollama chat failed (${res.status}): ${res.text?.slice(0, 300) || 'no response'}`);
        }

        const message = res.json.message || {};
        return {
            content: message.content || '',
            toolCalls: normalizeOllamaToolCalls(message.tool_calls),
            model,
            provider: 'ollama',
            usage: res.json.eval_count ? { completion_tokens: res.json.eval_count } : {},
        };
    }

    // OpenAI-compatible
    const body = {
        model,
        messages,
        temperature,
    };
    if (Number.isFinite(opts.maxTokens)) body.max_tokens = opts.maxTokens;
    if (opts.json) body.response_format = { type: 'json_object' };

    const headers = { 'Content-Type': 'application/json' };
    if (config.llm.openaiApiKey) headers.Authorization = `Bearer ${config.llm.openaiApiKey}`;

    const res = await httpJson(`${config.llm.openaiBaseUrl}/v1/chat/completions`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
    }, timeoutMs);

    if (!res.ok || !res.json) {
        throw new Error(`OpenAI chat failed (${res.status}): ${res.text?.slice(0, 300) || 'no response'}`);
    }

    const choice = (res.json.choices || [])[0] || {};
    const message = choice.message || {};
    return {
        content: message.content || '',
        toolCalls: normalizeOpenAiToolCalls(message.tool_calls),
        model,
        provider: 'openai',
        usage: res.json.usage || {},
    };
}

/**
 * Convenience wrapper that requests JSON and parses it, retrying once with a
 * stricter instruction when parsing fails.
 *
 * @param {Array} messages
 * @param {object} opts
 * @returns {Promise<{data:object|null, raw:string, model:string, error?:string}>}
 */
async function chatJson(messages, opts = {}) {
    const first = await chat(messages, { ...opts, json: true });
    let data = extractJson(first.content);
    if (data) return { data, raw: first.content, model: first.model };

    const retryMessages = [
        ...messages,
        { role: 'user', content: 'Your previous response was not valid JSON. Respond with ONLY a single valid JSON object and nothing else.' },
    ];
    const second = await chat(retryMessages, { ...opts, json: true, temperature: 0 });
    data = extractJson(second.content);
    return {
        data,
        raw: second.content,
        model: second.model,
        error: data ? undefined : 'invalid JSON after retry',
    };
}

module.exports = {
    chat,
    chatJson,
    health,
    listModels,
    resolveModel,
    resetModelCache,
    isOllama,
    _httpJson: httpJson,
};
