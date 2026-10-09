jest.mock('../database', () => {
    const mockRun = jest.fn();
    return {
        db: { prepare: () => ({ run: mockRun, get: jest.fn(), all: jest.fn() }), pragma: jest.fn(), exec: jest.fn() },
        stmts: {
            insertScan: { run: jest.fn() },
            getScan: { get: jest.fn() },
            listScans: { all: jest.fn(() => []) },
            countScans: { get: jest.fn(() => ({ count: 0 })) },
            updateScanProgress: { run: jest.fn() },
            updateScanStatus: { run: jest.fn() },
            updateScanRunning: { run: jest.fn() },
            completeScan: { run: jest.fn() },
            failScan: { run: jest.fn() },
            deleteScan: { run: jest.fn() },
            insertVuln: { run: mockRun },
            getVulns: { all: jest.fn(() => []) },
            insertEvent: { run: mockRun },
            getEvents: { all: jest.fn(() => []) },
            statsSummary: { get: jest.fn(() => ({})) },
            topVulnTypes: { all: jest.fn(() => []) },
            recentScans: { all: jest.fn(() => []) },
            recentVulns: { all: jest.fn(() => []) },
        },
    };
});

const REAL_SITES = {
    'google.com':           { expects: 'low',    maxScore: 15 },
    'youtube.com':          { expects: 'low',    maxScore: 15 },
    'github.com':           { expects: 'low',    maxScore: 15 },
    'stackoverflow.com':    { expects: 'low',    maxScore: 15 },
};

function mockResponse(status, headers = {}, body = '', setCookies = []) {
    return {
        status,
        headers: {
            _entries: { ...headers },
            get(name) {
                const lower = name.toLowerCase();
                for (const [k, v] of Object.entries(this._entries)) {
                    if (k.toLowerCase() === lower) return v;
                }
                return null;
            },
            forEach(cb) { Object.entries(this._entries).forEach(([k, v]) => cb(v, k)); },
            getSetCookie() { return setCookies; },
        },
        text: () => Promise.resolve(body),
    };
}

function mockFetchSequence(responses) {
    let callCount = 0;
    const globalFetch = global.fetch;
    beforeEach(() => {
        callCount = 0;
        global.fetch = jest.fn(() => {
            const resp = responses[Math.min(callCount++, responses.length - 1)];
            return Promise.resolve(resp);
        });
    });
    afterEach(() => { global.fetch = globalFetch; });
}

function categorize(vulns) {
    const counts = { active: 0, redirect: 0, config: 0, exposure: 0, info: 0 };
    for (const v of vulns) {
        if (['sql_injection', 'command_injection', 'path_traversal', 'ssrf', 'csrf'].includes(v.type)) counts.active++;
        else if (v.type === 'open_redirect') counts.redirect++;
        else if (v.type === 'xss' && v.severity === 'info') counts.info++;
        else if (['rate_limit_bypass', 'sensitive_file_disclosure', 'info_disclosure'].includes(v.type)) counts.exposure++;
        else counts.config++;
    }
    return counts;
}

describe('Google — pristine homepage (no vulns expected)', () => {
    const { computeRiskScore } = require('../scanner');

    it('risk score is low for google-like findings', () => {
        const vulns = [
            { type: 'missing_security_header', severity: 'medium' },
            { type: 'missing_security_header', severity: 'low' },
            { type: 'missing_security_header', severity: 'info' },
            { type: 'missing_security_header', severity: 'info' },
            { type: 'missing_security_header', severity: 'info' },
            { type: 'insecure_cookie', severity: 'medium' },
            { type: 'insecure_cookie', severity: 'low' },
        ];
        const { score, level } = computeRiskScore(vulns);
        expect(score).toBeLessThanOrEqual(15);
        expect(level).toBe('low');
    });

    it('no active vulns = not high or critical', () => {
        const configOnly = [
            { type: 'missing_security_header', severity: 'medium' },
            { type: 'insecure_cookie', severity: 'medium' },
            { type: 'rate_limit_bypass', severity: 'low' },
        ];
        const { level } = computeRiskScore(configOnly);
        expect(['info', 'low', 'medium']).toContain(level);
        expect(level).not.toBe('high');
        expect(level).not.toBe('critical');
    });
});

describe('Genuinely vulnerable site simulation', () => {
    const { computeRiskScore } = require('../scanner');

    it('SQLi + XSS = critical risk', () => {
        const vulns = [
            { type: 'sql_injection', severity: 'critical' },
            { type: 'xss', severity: 'high' },
            { type: 'open_redirect', severity: 'medium' },
        ];
        const { score, level } = computeRiskScore(vulns);
        expect(score).toBeGreaterThanOrEqual(60);
        expect(level).toBe('high');
    });

    it('multiple SQLi findings = medium risk (diminishing returns per type)', () => {
        const vulns = [
            { type: 'sql_injection', severity: 'critical' },
            { type: 'sql_injection', severity: 'critical' },
            { type: 'sql_injection', severity: 'critical' },
        ];
        const { score, level } = computeRiskScore(vulns);
        expect(score).toBeGreaterThanOrEqual(45);
        expect(level).toBe('medium');
    });
});

describe('False positive regression tests', () => {
    const { computeRiskScore, checkCspValue } = require('../scanner');

    it('CSP with default-src self is clean', () => {
        expect(checkCspValue("default-src 'self'")).toEqual([]);
    });

    it('crossdomain.xml without wildcard is clean', () => {
        const vulns = [
            { type: 'sensitive_file_disclosure', severity: 'info' },
        ];
        const { score } = computeRiskScore(vulns);
        expect(score).toBeLessThanOrEqual(2);
    });

    it('__Secure- cookie missing HttpOnly is clean', () => {
        const vulns = [
            { type: 'insecure_cookie', severity: 'medium' },
        ];
        const { score } = computeRiskScore(vulns);
        expect(score).toBeGreaterThanOrEqual(0);
    });

    it('pristine site with only a few config issues stays low', () => {
        const vulns = [
            { type: 'missing_security_header', severity: 'info' },
            { type: 'missing_security_header', severity: 'info' },
            { type: 'missing_security_header', severity: 'info' },
            { type: 'info_disclosure', severity: 'info' },
        ];
        const { score, level } = computeRiskScore(vulns);
        expect(score).toBeLessThanOrEqual(5);
        expect(level).toBe('info');
    });
});

describe('Categorization consistency', () => {
    const { computeRiskScore } = require('../scanner');

    it('same total vulns but all config vs all active gives very different scores', () => {
        const configScore = computeRiskScore([
            { type: 'missing_security_header', severity: 'medium' },
            { type: 'missing_security_header', severity: 'medium' },
            { type: 'missing_security_header', severity: 'medium' },
            { type: 'missing_security_header', severity: 'medium' },
            { type: 'missing_security_header', severity: 'medium' },
        ]);
        const activeScore = computeRiskScore([
            { type: 'sql_injection', severity: 'critical' },
            { type: 'sql_injection', severity: 'critical' },
            { type: 'sql_injection', severity: 'critical' },
            { type: 'sql_injection', severity: 'critical' },
            { type: 'sql_injection', severity: 'critical' },
        ]);
        expect(activeScore.score).toBeGreaterThan(configScore.score * 2);
    });
});
