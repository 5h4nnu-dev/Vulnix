/**
 * SecureProbe Payload Engine — Central Registry
 *
 * Modular payload database for authorized security testing.
 * Each module provides categorized payloads with descriptions and expected behavior.
 *
 * Usage:
 *   const { getPayloadsForVuln, mapPayloadsToScanResults, getAllPayloads } = require('./payloads');
 */

const xss = require('./xss');
const sqlInjection = require('./sql-injection');
const openRedirect = require('./open-redirect');
const cors = require('./cors');
const commandInjection = require('./command-injection');
const pathTraversal = require('./path-traversal');
const ssrf = require('./ssrf');
const csrf = require('./csrf');
const headerInjection = require('./header-injection');

// ── Registry ─────────────────────────────────────────────────────────────────

/**
 * Map from vulnerability type (as stored in DB) → payload module
 * Supports both exact match and fuzzy/related mapping
 */
const VULN_TYPE_MAP = {
    // Direct module keys
    xss,
    sql_injection: sqlInjection,
    open_redirect: openRedirect,
    cors_misconfiguration: cors,
    command_injection: commandInjection,
    path_traversal: pathTraversal,
    ssrf,
    csrf,
    header_injection: headerInjection,

    // Aliases — map scanner vuln types to related payload modules
    missing_security_header: headerInjection,
    weak_security_header: headerInjection,
    info_disclosure: headerInjection,
    http_method_abuse: headerInjection,
    rate_limit_bypass: csrf, // rate limit bypass enables CSRF/brute-force
    sensitive_file_disclosure: pathTraversal,
};

/**
 * All registered modules (deduplicated)
 */
const ALL_MODULES = [
    xss,
    sqlInjection,
    openRedirect,
    cors,
    commandInjection,
    pathTraversal,
    ssrf,
    csrf,
    headerInjection,
];

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Get the full payload set for a specific vulnerability type.
 *
 * @param {string} vulnType - The vulnerability type key (e.g., "xss", "sql_injection")
 * @returns {object|null} Payload module with { vulnerability, name, description, payloads[] }
 */
function getPayloadsForVuln(vulnType) {
    const mod = VULN_TYPE_MAP[vulnType];
    return mod ? { ...mod } : null;
}

/**
 * Get payloads filtered by category type.
 *
 * @param {string} vulnType - Vulnerability type key
 * @param {string} payloadType - Payload category (e.g., "basic", "advanced", "filter_bypass")
 * @returns {object[]|null} Array of matching payloads
 */
function getPayloadsByType(vulnType, payloadType) {
    const mod = VULN_TYPE_MAP[vulnType];
    if (!mod) return null;
    return mod.payloads.filter((p) => p.type === payloadType);
}

/**
 * Map detected vulnerabilities to relevant payloads, dynamically filtered by context.
 * Takes scan results and returns enriched payload suggestions.
 *
 * @param {object[]} vulnerabilities - Array of vulnerability objects from scan results
 * @returns {object[]} Array of payload sets, one per unique vulnerability type detected
 */
function mapPayloadsToScanResults(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) return [];

    // Group detected vulns by type
    const detectedTypes = new Map();
    for (const v of vulnerabilities) {
        if (!detectedTypes.has(v.type)) {
            detectedTypes.set(v.type, []);
        }
        detectedTypes.get(v.type).push(v);
    }

    const results = [];

    for (const [type, vulns] of detectedTypes) {
        const mod = VULN_TYPE_MAP[type];
        if (!mod) continue;

        // Determine injection context from the detected vulns
        const contexts = detectContexts(vulns);

        // Prioritize payloads: always include basic + advanced, then relevant contexts
        let relevantPayloads = mod.payloads.filter((p) => {
            if (p.type === 'basic' || p.type === 'advanced' || p.type === 'filter_bypass') return true;
            // Include context-specific payloads that match detected context
            if (contexts.length === 0) return true; // If no context detected, include all
            return contexts.some((ctx) => p.type === ctx || p.type.includes(ctx));
        });

        results.push({
            vulnerability: mod.vulnerability,
            name: mod.name,
            description: mod.description,
            detected_instances: vulns.length,
            detected_endpoints: vulns.map((v) => v.affected_endpoint),
            detected_severity: vulns.map((v) => v.severity),
            total_payloads: relevantPayloads.length,
            payloads: relevantPayloads,
        });
    }

    // Sort by severity: critical types first
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    results.sort((a, b) => {
        const aMax = Math.min(...a.detected_severity.map((s) => severityOrder[s] ?? 5));
        const bMax = Math.min(...b.detected_severity.map((s) => severityOrder[s] ?? 5));
        return aMax - bMax;
    });

    return results;
}

/**
 * Detect injection contexts from vulnerability details.
 * @param {object[]} vulns
 * @returns {string[]} Array of context strings like "context_url", "context_header"
 */
function detectContexts(vulns) {
    const contexts = new Set();

    for (const v of vulns) {
        const endpoint = (v.affected_endpoint || '').toLowerCase();
        const payload = (v.payload || '').toLowerCase();

        // URL parameter context
        if (endpoint.includes('?') || endpoint.includes('&')) {
            contexts.add('context_url');
        }
        // Header context
        if (payload.includes('header') || payload.includes('origin') || payload.includes('cookie')) {
            contexts.add('context_header');
        }
        // JSON context
        if (payload.includes('{') || payload.includes('json')) {
            contexts.add('context_json');
        }
        // HTML context (default for XSS)
        if (v.type === 'xss') {
            contexts.add('context_html');
        }
    }

    return Array.from(contexts);
}

/**
 * Get all payloads across all modules.
 *
 * @returns {object[]} Array of all payload modules
 */
function getAllPayloads() {
    return ALL_MODULES.map((mod) => ({
        vulnerability: mod.vulnerability,
        name: mod.name,
        description: mod.description,
        total_payloads: mod.payloads.length,
        payloads: mod.payloads,
    }));
}

/**
 * List all supported vulnerability types.
 *
 * @returns {string[]} Array of vulnerability type keys
 */
function listVulnTypes() {
    return ALL_MODULES.map((m) => m.vulnerability);
}

/**
 * Get payload statistics.
 *
 * @returns {object} Stats object with counts per module and total
 */
function getStats() {
    const modules = ALL_MODULES.map((m) => ({
        vulnerability: m.vulnerability,
        name: m.name,
        count: m.payloads.length,
        types: [...new Set(m.payloads.map((p) => p.type))],
    }));

    return {
        total_modules: modules.length,
        total_payloads: modules.reduce((sum, m) => sum + m.count, 0),
        modules,
    };
}

module.exports = {
    getPayloadsForVuln,
    getPayloadsByType,
    mapPayloadsToScanResults,
    getAllPayloads,
    listVulnTypes,
    getStats,
    // Also export individual modules for direct access
    modules: {
        xss,
        sqlInjection,
        openRedirect,
        cors,
        commandInjection,
        pathTraversal,
        ssrf,
        csrf,
        headerInjection,
    },
};
