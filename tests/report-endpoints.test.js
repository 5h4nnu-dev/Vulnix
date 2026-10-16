/**
 * Report rendering for the recon discovery data:
 *   - the Markdown report renders a "Discovered Endpoints" section from
 *     `extras.reconData.endpoints` / `extras.discoveredEndpoints`,
 *   - the affected endpoint is highlighted in each finding,
 *   - the DOCX report accepts the same extras without throwing.
 */

const markdown = require('../report/markdown');
const docx = require('../report/docx');

const scan = {
    id: 'scan-abcdef01',
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
    hardening_count: 0,
    mode: 'deterministic',
    use_ai: 0,
    prompt_injection_count: 0,
};

const vulns = [{
    id: 'v1', type: 'sql_injection', severity: 'high', title: 'SQL Injection',
    description: 'desc', affected_endpoint: 'https://example.com/rest/products/search?q=1',
    payload: "' OR 1=1--", evidence: 'error', remediation: 'parameterize',
    cvss_score: 8.1, source: 'static', kind: 'vulnerability',
    discovered_at: '2026-01-01',
}];

const events = [{ timestamp: '2026-01-01', stage: 'sql_injection', event_type: 'finding', title: 'SQLi' }];

describe('markdown report — discovered endpoints', () => {
    it('renders the endpoints table from reconData', () => {
        const extras = {
            reconData: {
                endpoints: [
                    { path: '/rest/products/search', params: ['q'], source: 'html' },
                    { path: '/api/v1/users', params: [], source: 'js' },
                ],
            },
        };
        const md = markdown.generate(scan, vulns, events, extras);
        expect(md).toContain('Discovered Endpoints');
        expect(md).toContain('| Path | Method | Kind | Params |');
        expect(md).toContain('`/rest/products/search`');
        expect(md).toContain('/api/v1/users');
    });

    it('falls back to extras.discoveredEndpoints', () => {
        const extras = { discoveredEndpoints: [{ path: '/login', params: ['user'], method: 'post' }] };
        const md = markdown.generate(scan, vulns, events, extras);
        expect(md).toContain('Discovered Endpoints');
        expect(md).toContain('`/login`');
        expect(md).toContain('POST');
    });

    it('omits the section when no endpoints are known', () => {
        const md = markdown.generate(scan, vulns, events, {});
        expect(md).not.toContain('Discovered Endpoints');
    });

    it('highlights the affected endpoint in findings', () => {
        const md = markdown.generate(scan, vulns, events, {});
        expect(md).toContain('🎯 **Affected Endpoint:** `https://example.com/rest/products/search?q=1`');
    });
});

describe('docx report — discovered endpoints', () => {
    it('produces a valid buffer with endpoint extras', async () => {
        const extras = {
            reconData: { endpoints: [{ path: '/rest/products/search', params: ['q'], source: 'html' }] },
            discoveredEndpoints: [{ path: '/login', params: ['user'], method: 'post' }],
        };
        const buffer = await docx.generate(scan, vulns, events, extras);
        expect(Buffer.isBuffer(buffer)).toBe(true);
        expect(buffer.slice(0, 2).toString()).toBe('PK');
    });

    it('renders without endpoints too', async () => {
        const buffer = await docx.generate(scan, vulns, events, {});
        expect(buffer.slice(0, 2).toString()).toBe('PK');
    });
});
