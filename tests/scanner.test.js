jest.mock('../database', () => {
    const mockStmts = {
        insertScan: { run: jest.fn() },
        getScan: { get: jest.fn(() => ({ id: 'test-id' })) },
        listScans: { all: jest.fn(() => []) },
        countScans: { get: jest.fn(() => ({ count: 0 })) },
        updateScanProgress: { run: jest.fn() },
        updateScanStatus: { run: jest.fn() },
        updateScanRunning: { run: jest.fn() },
        completeScan: { run: jest.fn() },
        failScan: { run: jest.fn() },
        deleteScan: { run: jest.fn() },
        insertVuln: { run: jest.fn() },
        getVulns: { all: jest.fn(() => []) },
        insertEvent: { run: jest.fn() },
        getEvents: { all: jest.fn(() => []) },
        statsSummary: { get: jest.fn(() => ({ total_scans: 0, total_vulnerabilities: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, avg_risk_score: 0 })) },
        topVulnTypes: { all: jest.fn(() => []) },
        recentScans: { all: jest.fn(() => []) },
        recentVulns: { all: jest.fn(() => []) },
    };
    return { db: { prepare: () => ({ run: jest.fn(), get: jest.fn(), all: jest.fn() }), pragma: jest.fn(), exec: jest.fn() }, stmts: mockStmts };
});

const {
    simpleHash,
    extractFingerprint,
    isSoft404,
    htmlDecode,
    headersToObj,
    computeRiskScore,
    checkCspValue,
} = require('../scanner');

describe('simpleHash', () => {
    it('produces consistent hash for same input', () => {
        const h1 = simpleHash('hello world');
        const h2 = simpleHash('hello world');
        expect(h1).toBe(h2);
    });
    it('produces different hashes for different inputs', () => {
        const h1 = simpleHash('hello');
        const h2 = simpleHash('world');
        expect(h1).not.toBe(h2);
    });
    it('handles empty string', () => {
        expect(simpleHash('')).toBe('0');
    });
    it('produces hex string output', () => {
        const h = simpleHash('test data for scanning');
        expect(h).toMatch(/^-?[0-9a-f]+$/);
    });
});

describe('extractFingerprint', () => {
    it('detects 404 keywords', () => {
        const result = extractFingerprint('Page not found - 404 error');
        expect(result).toContain('not_found');
        expect(result).toContain('page_not_found');
        expect(result).toContain('404');
    });
    it('detects error keywords', () => {
        const result = extractFingerprint('An error occurred: Cannot find resource');
        expect(result).toContain('error');
        expect(result).toContain('cannot_find');
    });
    it('returns empty array for clean body', () => {
        const result = extractFingerprint('Welcome to our website!');
        expect(result).toEqual([]);
    });
    it('is case insensitive', () => {
        const result = extractFingerprint('NOT FOUND');
        expect(result).toContain('not_found');
    });
});

describe('isSoft404', () => {
    const baseline = { status: 200, bodyLength: 1000, bodyHash: 'abc123', keywords: [] };
    it('returns true for HTTP 404', () => expect(isSoft404('body', 404, baseline)).toBe(true));
    it('returns true for HTTP 403', () => expect(isSoft404('body', 403, baseline)).toBe(true));
    it('returns true for HTTP 401', () => expect(isSoft404('body', 401, baseline)).toBe(true));
    it('returns false for 200 without baseline', () => expect(isSoft404('body', 200, null)).toBe(false));
    it('returns true when body hash matches baseline', () => {
        const body = 'same content';
        const bl = { status: 200, bodyLength: body.length, bodyHash: simpleHash(body), keywords: [] };
        expect(isSoft404(body, 200, bl)).toBe(true);
    });
    it('returns true when body length is within 10% of baseline', () => {
        expect(isSoft404('x'.repeat(1050), 200, baseline)).toBe(true);
    });
    it('returns false when body is significantly different from baseline', () => {
        expect(isSoft404('x'.repeat(2000), 200, baseline)).toBe(false);
    });
    it('returns true when body contains 404 keywords', () => {
        expect(isSoft404('This page cannot be found or does not exist', 200, baseline)).toBe(true);
    });
});

describe('htmlDecode', () => {
    it('decodes &lt; to <', () => expect(htmlDecode('&lt;script&gt;')).toBe('<script>'));
    it('decodes &amp; to &', () => expect(htmlDecode('a&amp;b')).toBe('a&b'));
    it('decodes &quot; to "', () => expect(htmlDecode('&quot;hello&quot;')).toBe('"hello"'));
    it('decodes &#39; and &#x27; to single quote', () => expect(htmlDecode('&#39;test&#x27;')).toBe("'test'"));
    it('decodes &#x2F; to /', () => expect(htmlDecode('a&#x2F;b&#x2F;c')).toBe('a/b/c'));
    it('handles complex mixed encoding', () => {
        expect(htmlDecode('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;')).toBe('<img src=x onerror="alert(1)">');
    });
    it('returns unchanged string when no entities present', () => {
        expect(htmlDecode('hello world')).toBe('hello world');
    });
});

describe('headersToObj', () => {
    it('converts Headers-like object to plain object', () => {
        const mockHeaders = {
            _entries: { 'content-type': 'text/html', server: 'nginx' },
            forEach(cb) { Object.entries(this._entries).forEach(([k, v]) => cb(v, k)); }
        };
        expect(headersToObj(mockHeaders)).toEqual({ 'content-type': 'text/html', server: 'nginx' });
    });
    it('handles empty headers', () => {
        const mockHeaders = { _entries: {}, forEach(cb) { Object.entries(this._entries).forEach(([k, v]) => cb(v, k)); } };
        expect(headersToObj(mockHeaders)).toEqual({});
    });
});

describe('computeRiskScore', () => {
    it('returns info for empty vulns', () => {
        expect(computeRiskScore([])).toEqual({ score: 0, level: 'info' });
    });
    it('computes risk for critical vulns', () => {
        const result = computeRiskScore([
            { type: 'sql_injection', severity: 'critical' },
            { type: 'sql_injection', severity: 'critical' },
            { type: 'sql_injection', severity: 'critical' },
            { type: 'xss', severity: 'high' },
        ]);
        expect(result.score).toBeGreaterThanOrEqual(60);
        expect(result.level).toBe('high');
    });
    it('applies diminishing returns', () => {
        const score1 = computeRiskScore([{ type: 'xss', severity: 'high' }]).score;
        const scoreMany = computeRiskScore([
            { type: 'xss', severity: 'high' }, { type: 'xss', severity: 'high' }, { type: 'xss', severity: 'high' },
        ]).score;
        expect(scoreMany).toBeGreaterThan(score1);
        expect(scoreMany).toBeLessThan(score1 * 3);
    });
    it('handles mixed severity vulns', () => {
        const result = computeRiskScore([
            { type: 'xss', severity: 'high' },
            { type: 'info_disclosure', severity: 'low' },
            { type: 'missing_security_header', severity: 'medium' },
        ]);
        expect(result.score).toBeGreaterThan(0);
        expect(['info', 'low', 'medium', 'high', 'critical']).toContain(result.level);
    });
    it('caps score at 100', () => {
        const vulns = Array.from({ length: 20 }, (_, i) => ({ type: `vuln_${i}`, severity: 'critical' }));
        expect(computeRiskScore(vulns).score).toBeLessThanOrEqual(100);
    });
    it('handles different types separately', () => {
        expect(computeRiskScore([
            { type: 'xss', severity: 'high' },
            { type: 'sql_injection', severity: 'critical' },
            { type: 'xss', severity: 'high' },
        ]).score).toBeGreaterThan(0);
    });
});

describe('checkCspValue', () => {
    it('returns empty for empty CSP', () => expect(checkCspValue('')).toEqual([]));
    it('detects permissive default-src', () => {
        const issues = checkCspValue("default-src *");
        expect(issues[0]).toContain('default-src');
    });
    it('detects unsafe-inline in script-src', () => {
        const issues = checkCspValue("script-src 'unsafe-inline'");
        expect(issues[0]).toContain('unsafe-inline');
    });
    it('detects unsafe-eval in script-src', () => {
        const issues = checkCspValue("script-src 'unsafe-eval'");
        expect(issues[0]).toContain('unsafe-eval');
    });
    it('passes strict CSP', () => {
        expect(checkCspValue("default-src 'self'; script-src 'self'; style-src 'self'")).toEqual([]);
    });
    it('detects multiple issues', () => {
        expect(checkCspValue("default-src *; script-src 'unsafe-inline' 'unsafe-eval'").length).toBeGreaterThanOrEqual(2);
    });
    it('is case insensitive', () => {
        expect(checkCspValue("SCRIPT-SRC 'UNSAFE-INLINE'").length).toBeGreaterThan(0);
    });
});
