const docx = require('../report/docx');

const scan = {
    id: 'scan-12345678',
    url: 'https://example.com',
    status: 'completed',
    created_at: '2026-01-01 00:00:00',
    completed_at: '2026-01-01 00:05:00',
    risk_score: 55,
    risk_level: 'high',
    vulnerability_count: 1,
    critical_count: 0,
    high_count: 1,
    medium_count: 0,
    low_count: 0,
    mode: 'hybrid',
    use_ai: 1,
    llm_model: 'qwen2.5-coder',
    prompt_injection_count: 1,
    executive_summary: 'A summary.',
};

const vulns = [{
    id: 'v1', type: 'xss', severity: 'high', title: 'Reflected XSS',
    description: 'desc', affected_endpoint: 'https://example.com/?q=1',
    payload: '<script>alert(1)</script>', evidence: 'reflected',
    ai_explanation: 'expl', exploitation: 'exploit', remediation: 'fix it',
    cvss_score: 7.2, source: 'ai', confidence: 0.9, ai_rationale: 'why',
    discovered_at: '2026-01-01',
}];

const events = [{ timestamp: '2026-01-01', stage: 'xss', event_type: 'finding', title: 'XSS' }];

const extras = {
    promptInjection: [{ endpoint: 'https://example.com/?prompt=1', technique: 'instruction_override', detected: 1 }],
    agentSteps: [{ step_no: 1, action: 'crawl', injection_flagged: 0 }],
    aiPayloads: [{ vuln_type: 'xss', payload: '<img>', rationale: 'r', payload_type: 'ai' }],
};

describe('docx report', () => {
    it('produces a valid PKZIP buffer', async () => {
        const buffer = await docx.generate(scan, vulns, events, extras);
        expect(Buffer.isBuffer(buffer)).toBe(true);
        expect(buffer.length).toBeGreaterThan(1000);
        // ZIP local file header magic: "PK\x03\x04"
        expect(buffer.slice(0, 2).toString()).toBe('PK');
    });

    it('handles a scan with no vulnerabilities', async () => {
        const buffer = await docx.generate({ ...scan, vulnerability_count: 0 }, [], [], {});
        expect(buffer.slice(0, 2).toString()).toBe('PK');
    });
});
