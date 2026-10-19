/**
 * Tool catalogue exposed to the autonomous agent.
 *
 * The model only ever *requests* a tool by name; agent/tools.js performs the
 * action. This file defines the schema and a compact text rendering used in the
 * system prompt (kept provider-agnostic so it works with JSON-action models).
 */

const TOOLS = {
    http_request: {
        description: 'Send one HTTP request to the target and receive a shortened response. Use this to deliver custom payloads.',
        parameters: {
            method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'], required: false, default: 'GET' },
            url: { type: 'string', required: true, description: 'Absolute URL, must be within scope' },
            headers: { type: 'object', required: false },
            body: { type: 'string', required: false },
        },
    },
    crawl: {
        description: 'Fetch a page and extract links, forms, and query parameters to discover endpoints.',
        parameters: {
            path: { type: 'string', required: false, default: '/' },
            depth: { type: 'integer', required: false, default: 1 },
        },
    },
    fingerprint: {
        description: 'Identify the target technology stack from headers and HTML.',
        parameters: {},
    },
    generate_payloads: {
        description: 'Ask the model to write custom payloads for a vulnerability class and parameter.',
        parameters: {
            vuln_type: { type: 'string', required: true, description: 'sql_injection | xss | command_injection | path_traversal | ssrf | open_redirect | prompt_injection' },
            param: { type: 'string', required: false },
            notes: { type: 'string', required: false },
        },
    },
    test_parameter: {
        description: 'Inject a payload into a parameter and run a deterministic detector for the given vulnerability class.',
        parameters: {
            endpoint: { type: 'string', required: true },
            param: { type: 'string', required: true },
            vuln_type: { type: 'string', required: true },
            method: { type: 'string', enum: ['GET', 'POST'], required: false, default: 'GET' },
            fields: { type: 'object', required: false, description: 'Existing form fields to preserve during POST testing' },
            content_type: { type: 'string', enum: ['application/x-www-form-urlencoded', 'application/json'], required: false },
            payload: { type: 'string', required: false, description: 'Custom payload; omit to use a sensible default' },
        },
    },
    record_finding: {
        description: 'Record a confirmed vulnerability. Only call this after observing real evidence (recent test_parameter returned result.vulnerable===true).',
        parameters: {
            type: { type: 'string', required: true },
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'], required: true },
            title: { type: 'string', required: true },
            description: { type: 'string', required: true },
            endpoint: { type: 'string', required: true },
            payload: { type: 'string', required: false },
            evidence: { type: 'string', required: true },
            remediation: { type: 'string', required: false },
        },
    },
    finish: {
        description: 'Finish the engagement and provide a summary.',
        parameters: { summary: { type: 'string', required: true } },
    },
};

/**
 * Render the tool catalogue as compact text for the system prompt.
 * @returns {string}
 */
function renderCatalog() {
    const lines = [];
    for (const [name, def] of Object.entries(TOOLS)) {
        const params = Object.entries(def.parameters || {})
            .map(([p, meta]) => {
                const req = meta.required ? '' : '?';
                const en = meta.enum ? ` (${meta.enum.join('|')})` : '';
                return `${p}${req}:${meta.type}${en}`;
            })
            .join(', ');
        lines.push(`- ${name}(${params}) — ${def.description}`);
    }
    return lines.join('\n');
}

function isValidTool(name) {
    return Object.prototype.hasOwnProperty.call(TOOLS, name);
}

module.exports = { TOOLS, renderCatalog, isValidTool };
