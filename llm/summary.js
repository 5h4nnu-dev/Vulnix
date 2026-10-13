/**
 * AI executive summary generator for reports.
 */

const config = require('../config');
const client = require('./client');
const { SUMMARY_SYSTEM } = require('./prompts');
const { guardContent } = require('./guard');

/**
 * @param {object} scan - scan row (url, risk_score, risk_level, counts)
 * @param {object[]} vulns - vulnerability rows
 * @returns {Promise<object|null>}
 */
async function generate(scan, vulns) {
    if (!config.llm.enabled) return null;

    const compact = {
        target: scan.url,
        risk_score: scan.risk_score,
        risk_level: scan.risk_level,
        counts: {
            critical: scan.critical_count,
            high: scan.high_count,
            medium: scan.medium_count,
            low: scan.low_count,
            total: scan.vulnerability_count,
        },
        findings: (vulns || []).slice(0, 40).map((v) => ({
            type: v.type,
            severity: v.severity,
            title: v.title,
            endpoint: v.affected_endpoint,
        })),
    };

    const userMessage = [
        'Write the executive summary for this report.',
        guardContent(JSON.stringify(compact, null, 2), 'UNTRUSTED_TARGET_DATA').content,
    ].join('\n\n');

    try {
        const { data } = await client.chatJson(
            [
                { role: 'system', content: SUMMARY_SYSTEM },
                { role: 'user', content: userMessage },
            ],
            { temperature: 0.3 }
        );
        if (!data) return null;
        return {
            summary: typeof data.summary === 'string' ? data.summary : null,
            keyRisks: Array.isArray(data.key_risks) ? data.key_risks.map(String) : [],
            recommendedActions: Array.isArray(data.recommended_actions) ? data.recommended_actions.map(String) : [],
        };
    } catch {
        return null;
    }
}

module.exports = { generate };
