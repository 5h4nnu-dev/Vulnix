/**
 * Vulnix Configuration
 *
 * Zero-dependency configuration layer. Reads a local `.env` file (if present)
 * and then environment variables. Everything has a safe default so the tool
 * keeps working exactly as before when no AI is configured.
 */

const fs = require('fs');
const path = require('path');

// ── Tiny .env loader (no dotenv dependency) ─────────────────────────────────

function loadDotEnv() {
    const envPath = path.join(__dirname, '.env');
    let content;
    try {
        content = fs.readFileSync(envPath, 'utf8');
    } catch {
        return;
    }

    for (const rawLine of content.split('\n')) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;

        const eq = line.indexOf('=');
        if (eq === -1) continue;

        const key = line.slice(0, eq).trim();
        if (!key) continue;

        let value = line.slice(eq + 1).trim();
        if (
            (value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))
        ) {
            value = value.slice(1, -1);
        }

        // Real environment always wins over .env
        if (!(key in process.env)) process.env[key] = value;
    }
}

loadDotEnv();

// ── Coercion helpers ─────────────────────────────────────────────────────────

function toBool(value, fallback) {
    if (value === undefined || value === null || value === '') return fallback;
    return /^(1|true|yes|on)$/i.test(String(value).trim());
}

function toInt(value, fallback) {
    const n = parseInt(value, 10);
    return Number.isFinite(n) ? n : fallback;
}

function toFloat(value, fallback) {
    const n = parseFloat(value);
    return Number.isFinite(n) ? n : fallback;
}

function toList(value) {
    if (!value) return [];
    return String(value)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
}

// ── Exported config ──────────────────────────────────────────────────────────

const config = {
    // Server
    host: process.env.SERVER_HOST || '127.0.0.1',
    port: toInt(process.env.PORT, 5000),
    apiToken: process.env.VULNIX_API_TOKEN || '',

    // LLM provider
    llm: {
        enabled: toBool(process.env.LLM_ENABLED, false),
        provider: (process.env.LLM_PROVIDER || 'ollama').toLowerCase(),
        ollamaHost: (process.env.OLLAMA_HOST || 'http://localhost:11434').replace(/\/+$/, ''),
        openaiBaseUrl: (process.env.OPENAI_BASE_URL || 'https://api.openai.com').replace(/\/+$/, ''),
        openaiApiKey: process.env.OPENAI_API_KEY || '',
        model: process.env.LLM_MODEL || '',
        temperature: toFloat(process.env.LLM_TEMPERATURE, 0.2),
        timeoutMs: toInt(process.env.LLM_TIMEOUT_MS, 60000),
        maxPayloads: toInt(process.env.LLM_MAX_PAYLOADS, 12),
        concurrency: toInt(process.env.LLM_CONCURRENCY, 2),
    },

    // Autonomous agent
    agent: {
        maxSteps: toInt(process.env.AGENT_MAX_STEPS, 25),
        maxRequests: toInt(process.env.AGENT_MAX_REQUESTS, 200),
        maxSeconds: toInt(process.env.AGENT_MAX_SECONDS, 600),
        allowDestructive: toBool(process.env.AGENT_ALLOW_DESTRUCTIVE, false),
    },

    // Deterministic scanner (never used by the LLM/agent layer — these limits
    // only bound the non-AI engine so a scan cannot run unbounded).
    scanner: {
        maxRequests: toInt(process.env.SCAN_MAX_REQUESTS, 400),
        maxSeconds: toInt(process.env.SCAN_MAX_SECONDS, 120),
        skipStaticInjection: toBool(process.env.SCAN_SKIP_STATIC_INJECTION, true),
        rateLimitSamples: toInt(process.env.SCAN_RATE_LIMIT_SAMPLES, 4),
        // Same-origin API endpoint discovery + probing (SPAs / JSON APIs).
        // The page and up to `maxScripts` JS bundles are mined for candidates;
        // the top `maxEndpoints` are probed with a bounded battery.
        scanDiscovery: {
            maxScripts: toInt(process.env.SCAN_DISCOVERY_SCRIPTS, 3),
            maxEndpoints: toInt(process.env.SCAN_DISCOVERY_ENDPOINTS, 8),
            maxProbesPerEndpoint: toInt(process.env.SCAN_DISCOVERY_PROBES, 4),
            postProbe: toBool(process.env.SCAN_DISCOVERY_POST, true),
            maxDepth: toInt(process.env.SCAN_DISCOVERY_DEPTH, 1),
            maxVisited: toInt(process.env.SCAN_DISCOVERY_VISITED, 30),
            probeCommon: toBool(process.env.SCAN_DISCOVERY_PROBE_COMMON, false),
            commonPaths: (process.env.SCAN_DISCOVERY_COMMON_PATHS || '/login,/signin,/register,/logout,/admin,/api,/api/v1,/api/v2,/api/users,/api/auth').split(',').map(p => p.trim()).filter(Boolean),
            // Type-appropriate fuzzing of every discovered input surface
            // (parameterised links, forms, API paths) with the fixed + AI
            // payload sets. Runs last so it consumes leftover budget only.
            fuzzSurfaces: toBool(process.env.SCAN_FUZZ_SURFACES, true),
            maxSurfaces: toInt(process.env.SCAN_DISCOVERY_SURFACES, 12),
        },
    },

    // Safety / authorization
    security: {
        authorizedTargets: toList(process.env.AUTHORIZED_TARGETS),
        requireAuthorization: toBool(process.env.REQUIRE_AUTHORIZATION, true),
        allowInternalIps: toBool(process.env.ALLOW_INTERNAL_IPS, false),
    },
};

/**
 * Whether the AI layer can be considered available. Individual calls still
 * perform a live health check; this is only the static configuration gate.
 */
config.llmConfigured = () => config.llm.enabled;

module.exports = config;
