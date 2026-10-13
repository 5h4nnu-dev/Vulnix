/**
 * AI finding analyst.
 *
 * Enriches a detected vulnerability with a genuine explanation, exploitation
 * path, remediation, and a confidence estimate. Returns nulls on failure so the
 * caller keeps the static text.
 */

const config = require('../config');
const client = require('./client');
const { ANALYST_SYSTEM } = require('./prompts');
const { guardContent } = require('./guard');
const { redactBody } = require('./redact');

/**
 * @param {object} vuln - { type, severity, title, description, affected_endpoint, payload, evidence }
 * @returns {Promise<object|null>}
 */
async function analyze(vuln) {
    if (!config.llm.enabled) return null;

    const context = {
        type: vuln.type,
        severity: vuln.severity,
        title: vuln.title,
        description: vuln.description,
        endpoint: vuln.affected_endpoint,
        payload: vuln.payload || null,
        evidence: vuln.evidence ? redactBody(vuln.evidence, 1500) : null,
    };

    const userMessage = [
        'Analyze this finding and return the required JSON.',
        guardContent(JSON.stringify(context, null, 2), 'UNTRUSTED_TARGET_DATA').content,
    ].join('\n\n');

    try {
        const { data } = await client.chatJson(
            [
                { role: 'system', content: ANALYST_SYSTEM },
                { role: 'user', content: userMessage },
            ],
            { temperature: 0.2 }
        );
        if (!data) return null;

        return {
            aiExplanation: typeof data.explanation === 'string' ? data.explanation : null,
            exploitation: typeof data.exploitation === 'string' ? data.exploitation : null,
            remediation: typeof data.remediation === 'string' ? data.remediation : null,
            confidence: Number.isFinite(Number(data.confidence)) ? Math.max(0, Math.min(1, Number(data.confidence))) : null,
            falsePositiveLikelihood: typeof data.false_positive_likelihood === 'string' ? data.false_positive_likelihood : null,
            severityAdjustment: typeof data.severity_adjustment === 'string' ? data.severity_adjustment : null,
        };
    } catch {
        return null;
    }
}

module.exports = { analyze };
