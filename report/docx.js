/**
 * DOCX report generator (Word).
 * Pure-ish function: takes already-loaded rows and returns a Buffer.
 */

const {
    Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell,
    WidthType, AlignmentType, BorderStyle, ShadingType,
} = require('docx');

const SEV_COLOR = {
    critical: 'C00000',
    high: 'E36C0A',
    medium: 'BF9000',
    low: '1F6FB2',
    info: '375623',
};

function txt(text, opts = {}) {
    return new TextRun({ text: String(text ?? ''), ...opts });
}

function para(children, opts = {}) {
    return new Paragraph({ children: Array.isArray(children) ? children : [children], ...opts });
}

function keyValueRow(label, value) {
    return new TableRow({
        children: [
            new TableCell({ width: { size: 28, type: WidthType.PERCENTAGE }, children: [para(txt(label, { bold: true }))] }),
            new TableCell({ width: { size: 72, type: WidthType.PERCENTAGE }, children: [para(txt(value))] }),
        ],
    });
}

function simpleTable(headers, rows) {
    const headerRow = new TableRow({
        tableHeader: true,
        children: headers.map((h) => new TableCell({
            shading: { type: ShadingType.CLEAR, fill: '1F1F1F' },
            children: [para(txt(h, { bold: true, color: 'FFFFFF' }), { alignment: AlignmentType.LEFT })],
        })),
    });
    const bodyRows = rows.map((r) => new TableRow({
        children: r.map((cell) => new TableCell({ children: [para(txt(cell))] })),
    }));
    return new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        borders: {
            top: { style: BorderStyle.SINGLE, size: 1, color: 'CCCCCC' },
            bottom: { style: BorderStyle.SINGLE, size: 1, color: 'CCCCCC' },
            left: { style: BorderStyle.SINGLE, size: 1, color: 'CCCCCC' },
            right: { style: BorderStyle.SINGLE, size: 1, color: 'CCCCCC' },
            insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: 'EEEEEE' },
            insideVertical: { style: BorderStyle.SINGLE, size: 1, color: 'EEEEEE' },
        },
        rows: [headerRow, ...bodyRows],
    });
}

/**
 * @param {object} scan
 * @param {object[]} vulns
 * @param {object[]} events
 * @param {object} [extras]
 * @returns {Promise<Buffer>}
 */
async function generate(scan, vulns, events, extras = {}) {
    const promptInjection = extras.promptInjection || [];
    const agentSteps = extras.agentSteps || [];
    const aiPayloads = extras.aiPayloads || [];
    const vulnerabilities = (vulns || []).filter((v) => v.kind !== 'hardening');
    const hardening = (vulns || []).filter((v) => v.kind === 'hardening');

    const children = [];

    children.push(para(txt('Vulnix Security Report', { bold: true, size: 40 }), { heading: HeadingLevel.TITLE }));
    children.push(para(txt(`Target: ${scan.url}`, { size: 22 })));
    children.push(para(txt(`Scan ID: ${scan.id}`, { size: 20 })));
    children.push(para(txt(`Mode: ${scan.mode || 'deterministic'}${scan.use_ai ? ' (AI-assisted)' : ''}`, { size: 20 })));
    if (scan.llm_model) children.push(para(txt(`Model: ${scan.llm_model}`, { size: 20 })));
    children.push(para(txt(`Status: ${scan.status}`, { size: 20 })));
    children.push(para(txt(`Scan Date: ${scan.created_at}`, { size: 20 })));
    children.push(para(txt(`Completed: ${scan.completed_at || 'N/A'}`, { size: 20 })));

    children.push(para(txt('Risk Summary', { bold: true, size: 28 }), { heading: HeadingLevel.HEADING_1 }));
    children.push(simpleTable(['Metric', 'Value'], [
        ['Risk Score', `${scan.risk_score ?? 0}/100`],
        ['Risk Level', String(scan.risk_level || 'N/A').toUpperCase()],
        ['Total Vulnerabilities', String(scan.vulnerability_count ?? 0)],
        ['Hardening Gaps', String(scan.hardening_count ?? hardening.length)],
        ['Critical', String(scan.critical_count ?? 0)],
        ['High', String(scan.high_count ?? 0)],
        ['Medium', String(scan.medium_count ?? 0)],
        ['Low', String(scan.low_count ?? 0)],
        ['Prompt-Injection Findings', String(scan.prompt_injection_count ?? promptInjection.filter((t) => t.detected).length)],
    ]));

    if (scan.executive_summary) {
        children.push(para(txt('Executive Summary', { bold: true, size: 28 }), { heading: HeadingLevel.HEADING_1 }));
        children.push(para(txt(scan.executive_summary)));
    }

    children.push(para(txt('Vulnerabilities', { bold: true, size: 28 }), { heading: HeadingLevel.HEADING_1 }));

    if (vulnerabilities.length === 0) {
        children.push(para(txt('No exploitable vulnerabilities were detected.')));
    }

    vulnerabilities.forEach((v, i) => {
        children.push(para(
            txt(`${i + 1}. ${v.title}`, { bold: true, size: 24, color: SEV_COLOR[v.severity] || '000000' }),
            { heading: HeadingLevel.HEADING_2 }
        ));
        if (v.affected_endpoint) {
            children.push(para(txt(`Affected Endpoint: ${v.affected_endpoint}`, { bold: true, color: 'C00000' })));
        }
        const rows = [
            ['Severity', String(v.severity).toUpperCase()],
            ['Type', v.type],
            ['CVSS Score', String(v.cvss_score ?? 'N/A')],
            ['Source', v.source || 'static'],
        ];
        if (v.confidence != null) rows.push(['Confidence', `${Math.round(v.confidence * 100)}%`]);
        rows.push(['Affected Endpoint', v.affected_endpoint]);
        children.push(simpleTable(['Field', 'Details'], rows));

        if (v.payload) {
            children.push(para(txt('Payload Used:', { bold: true })));
            children.push(para(txt(v.payload, { font: 'Courier New' })));
        }
        children.push(para(txt('Description:', { bold: true })));
        children.push(para(txt(v.description)));
        if (v.ai_rationale) {
            children.push(para(txt('AI Rationale:', { bold: true })));
            children.push(para(txt(v.ai_rationale)));
        }
        if (v.evidence) {
            children.push(para(txt('Evidence:', { bold: true })));
            children.push(para(txt(v.evidence, { font: 'Courier New' })));
        }
        if (v.ai_explanation) {
            children.push(para(txt('Detailed Analysis:', { bold: true })));
            children.push(para(txt(v.ai_explanation)));
        }
        if (v.exploitation) {
            children.push(para(txt('Possible Exploit:', { bold: true })));
            children.push(para(txt(v.exploitation)));
        }
        children.push(para(txt('Remediation:', { bold: true })));
        children.push(para(txt(v.remediation)));
        children.push(para(txt('')));
    });

    if (hardening.length > 0) {
        children.push(para(txt('Hardening Gaps', { bold: true, size: 28 }), { heading: HeadingLevel.HEADING_1 }));
        children.push(para(txt('Configuration weaknesses that should be addressed but are not exploitable on their own.')));
        children.push(simpleTable(
            ['Severity', 'Title', 'Evidence'],
            hardening.map((h) => [String(h.severity).toUpperCase(), h.title, String(h.evidence || '').slice(0, 120)])
        ));
    }

    if (promptInjection.length > 0) {
        children.push(para(txt('Prompt-Injection Tests', { bold: true, size: 28 }), { heading: HeadingLevel.HEADING_1 }));
        children.push(simpleTable(
            ['Endpoint', 'Technique', 'Detected'],
            promptInjection.map((t) => [String(t.endpoint).slice(0, 70), t.technique, t.detected ? 'YES' : 'no'])
        ));
    }

    const endpointsList = (extras.reconData && Array.isArray(extras.reconData.endpoints)) ? extras.reconData.endpoints
        : (Array.isArray(extras.discoveredEndpoints) ? extras.discoveredEndpoints : []);
    if (endpointsList.length > 0) {
        children.push(para(txt('Discovered Endpoints', { bold: true, size: 28 }), { heading: HeadingLevel.HEADING_1 }));
        children.push(simpleTable(
            ['Path', 'Method', 'Kind', 'Params'],
            endpointsList.map((ep) => {
                const path = ep.path || ep.endpoint || ep.url || '';
                const method = ep.method || 'GET';
                const kind = ep.kind || ep.source || 'static';
                const params = Array.isArray(ep.params) ? ep.params.join(', ') : (ep.params || '');
                return [String(path), String(method).toUpperCase(), String(kind), String(params).slice(0, 120)];
            })
        ));
    }

    if (aiPayloads.length > 0) {
        children.push(para(txt('AI-Generated Payloads', { bold: true, size: 28 }), { heading: HeadingLevel.HEADING_1 }));
        children.push(simpleTable(
            ['Vuln Type', 'Payload', 'Rationale'],
            aiPayloads.map((p) => [p.vuln_type, String(p.payload).slice(0, 80), String(p.rationale || '').slice(0, 120)])
        ));
    }

    if (agentSteps.length > 0) {
        children.push(para(txt('Agent Action Trace', { bold: true, size: 28 }), { heading: HeadingLevel.HEADING_1 }));
        children.push(simpleTable(
            ['Step', 'Action', 'Injection Flag'],
            agentSteps.map((s) => [String(s.step_no), s.action, s.injection_flagged ? 'YES' : 'no'])
        ));
    }

    children.push(para(txt('Scan Timeline', { bold: true, size: 28 }), { heading: HeadingLevel.HEADING_1 }));
    children.push(simpleTable(
        ['Time', 'Stage', 'Type', 'Title'],
        events.map((e) => [String(e.timestamp), e.stage, e.event_type, String(e.title)])
    ));

    children.push(para(txt('')));
    children.push(para(txt('Report generated by Vulnix', { italics: true, size: 18 })));
    children.push(para(txt('Disclaimer: Only scan URLs you own or have explicit written permission to test.', { italics: true, size: 18, color: 'C00000' })));

    const doc = new Document({
        creator: 'Vulnix',
        title: `Vulnix Security Report — ${scan.id}`,
        sections: [{ properties: {}, children }],
    });

    return Packer.toBuffer(doc);
}

module.exports = { generate };
