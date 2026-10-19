/**
 * Markdown report generator.
 * Pure function: takes already-loaded rows and returns a Markdown string.
 */

const SEV_EMOJI = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️' };

/**
 * @param {object} scan
 * @param {object[]} vulns
 * @param {object[]} events
 * @param {object} [extras]
 * @param {object[]} [extras.promptInjection]
 * @param {object[]} [extras.agentSteps]
 * @param {object[]} [extras.aiPayloads]
 * @returns {string}
 */
function generate(scan, vulns, events, extras = {}) {
    const promptInjection = extras.promptInjection || [];
    const agentSteps = extras.agentSteps || [];
    const aiPayloads = extras.aiPayloads || [];
    const vulnerabilities = (vulns || []).filter((v) => v.kind !== 'hardening');
    const hardening = (vulns || []).filter((v) => v.kind === 'hardening');

    let md = `# 🛡️ Vulnix Security Report\n\n`;
    md += `**Target URL:** ${scan.url}\n`;
    md += `**Scan ID:** \`${scan.id}\`\n`;
    md += `**Mode:** ${scan.mode || 'deterministic'}${scan.use_ai ? ' (AI-assisted)' : ''}\n`;
    if (scan.llm_model) md += `**Model:** ${scan.llm_model}\n`;
    md += `**Status:** ${scan.status}\n`;
    md += `**Scan Date:** ${scan.created_at}\n`;
    md += `**Completed:** ${scan.completed_at || 'N/A'}\n\n`;
    md += `---\n\n`;

    md += `## 📊 Risk Summary\n\n`;
    md += `| Metric | Value |\n|--------|-------|\n`;
    md += `| **Risk Score** | ${scan.risk_score ?? 0}/100 |\n`;
    md += `| **Risk Level** | ${(scan.risk_level || 'N/A').toUpperCase()} |\n`;
    md += `| **Total Vulnerabilities** | ${scan.vulnerability_count} |\n`;
    md += `| **Hardening Gaps** | ${scan.hardening_count ?? hardening.length} |\n`;
    md += `| Critical | ${scan.critical_count} |\n`;
    md += `| High | ${scan.high_count} |\n`;
    md += `| Medium | ${scan.medium_count} |\n`;
    md += `| Low | ${scan.low_count} |\n`;
    md += `| Prompt-Injection Findings | ${scan.prompt_injection_count ?? promptInjection.filter((t) => t.detected).length} |\n\n`;

    if (scan.executive_summary) {
        md += `## 🧠 Executive Summary\n\n${scan.executive_summary}\n\n`;
    }

    md += `---\n\n`;

    if (vulnerabilities.length > 0) {
        md += `## 🔴 Vulnerabilities Found\n\n`;
        for (let i = 0; i < vulnerabilities.length; i++) {
            const v = vulnerabilities[i];
            md += `### ${i + 1}. ${SEV_EMOJI[v.severity] || '⚪'} ${v.title}\n\n`;
            md += `| Field | Details |\n|-------|--------|\n`;
            md += `| **Severity** | ${String(v.severity).toUpperCase()} |\n`;
            md += `| **Type** | ${v.type} |\n`;
            md += `| **CVSS Score** | ${v.cvss_score ?? 'N/A'} |\n`;
            md += `| **Source** | ${v.source || 'static'} |\n`;
            if (v.confidence != null) md += `| **Confidence** | ${Math.round(v.confidence * 100)}% |\n`;
            md += `| **Affected Endpoint** | \`${v.affected_endpoint}\` |\n`;
            md += `| **Discovered** | ${v.discovered_at} |\n\n`;
            if (v.payload) md += `**Payload Used:**\n\`\`\`\n${v.payload}\n\`\`\`\n\n`;
            md += `**Description:**\n${v.description}\n\n`;
            if (v.ai_rationale) md += `**AI Rationale:**\n${v.ai_rationale}\n\n`;
            if (v.evidence) md += `**Evidence:**\n\`\`\`\n${v.evidence}\n\`\`\`\n\n`;
            if (v.ai_explanation) md += `**Detailed Analysis:**\n${v.ai_explanation}\n\n`;
            if (v.exploitation) md += `**Possible Exploit:**\n${v.exploitation}\n\n`;
            if (v.affected_endpoint) md += `> 🎯 **Affected Endpoint:** \`${v.affected_endpoint}\`\n\n`;
            md += `**Remediation:**\n${v.remediation}\n\n`;
            md += `---\n\n`;
        }
    } else {
        if (scan.status === 'completed') {
            md += `## ✅ No Vulnerabilities Found\n\nThe scan completed without detecting any exploitable vulnerabilities in the tested surfaces. This does not establish that undiscovered or untested areas are vulnerability-free.\n\n`;
        } else {
            md += `## ⚠️ No Findings Recorded\n\nThe scan status is **${scan.status || 'unknown'}**. Coverage was incomplete, so the absence of findings must not be interpreted as evidence that the target is vulnerability-free.\n\n`;
        }
    }

    if (hardening.length > 0) {
        md += `## 🛡️ Hardening Gaps (${hardening.length})\n\n`;
        md += `These are configuration weaknesses that should be addressed but are not exploitable vulnerabilities on their own.\n\n`;
        for (const h of hardening) {
            md += `- **[${String(h.severity).toUpperCase()}] ${h.title}** — ${h.description}\n`;
            if (h.evidence) md += `  - Evidence: \`${h.evidence}\`\n`;
            if (h.remediation) md += `  - Fix: ${h.remediation}\n`;
        }
        md += `\n`;
    }

    if (promptInjection.length > 0) {
        const detected = promptInjection.filter((t) => t.detected);
        md += `## 🧪 Prompt-Injection Tests (${promptInjection.length})\n\n`;
        md += `Detected: **${detected.length}**\n\n`;
        md += `| Endpoint | Technique | Detected |\n|----------|-----------|----------|\n`;
        for (const t of promptInjection) {
            md += `| \`${String(t.endpoint).slice(0, 80)}\` | ${t.technique} | ${t.detected ? '✅' : '—'} |\n`;
        }
        md += `\n`;
    }

    // Discovered Endpoints section
    const discovered = (extras.reconData && (extras.reconData.endpoints || extras.reconData.links || extras.reconData.forms)) || [];
    let endpointsList = null;
    if (extras.reconData && Array.isArray(extras.reconData.endpoints)) {
        endpointsList = extras.reconData.endpoints;
    }
    if ((!endpointsList || endpointsList.length === 0) && Array.isArray(extras.discoveredEndpoints)) {
        endpointsList = extras.discoveredEndpoints;
    }
    if (endpointsList && endpointsList.length > 0) {
        md += `## 🔍 Discovered Endpoints (${endpointsList.length})\n\n`;
        md += `| Path | Method | Kind | Params |\n|------|--------|------|--------|\n`;
        for (const ep of endpointsList) {
            const path = ep.path || ep.endpoint || ep.url || '';
            const method = ep.method || (ep.params && ep.params.length ? 'GET' : 'GET');
            const kind = ep.kind || ep.source || (Array.isArray(ep.params) && ep.params.length ? 'param' : 'static');
            const params = Array.isArray(ep.params) ? ep.params.join(', ') : (ep.params || '');
            md += `| \`${path}\` | ${String(method).toUpperCase()} | ${kind} | ${params} |\n`;
        }
        md += `\n`;
    }

    if (aiPayloads.length > 0) {
        md += `## 🤖 AI-Generated Payloads (${aiPayloads.length})\n\n`;
        for (const p of aiPayloads) {
            md += `- **${p.vuln_type}** (\`${p.payload_type || 'ai'}\`): \`${String(p.payload).slice(0, 200)}\``;
            if (p.rationale) md += ` — ${p.rationale}`;
            md += `\n`;
        }
        md += `\n`;
    }

    if (agentSteps.length > 0) {
        md += `## 🧭 Agent Action Trace (${agentSteps.length} steps)\n\n`;
        md += `| # | Action | Injection Flag |\n|---|--------|----------------|\n`;
        for (const s of agentSteps) {
            md += `| ${s.step_no} | ${s.action} | ${s.injection_flagged ? '⚠️' : '—'} |\n`;
        }
        md += `\n`;
    }

    md += `## 📋 Scan Timeline (${events.length} events)\n\n`;
    md += `| Time | Stage | Type | Title |\n|------|-------|------|-------|\n`;
    for (const e of events) {
        md += `| ${e.timestamp} | ${e.stage} | ${e.event_type} | ${e.title} |\n`;
    }
    md += `\n---\n\n`;
    md += `*Report generated by Vulnix*\n`;
    md += `*⚠️ Disclaimer: Only scan URLs you own or have explicit permission to test.*\n`;

    return md;
}

module.exports = { generate };
