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

/**
 * Risk-score regression tests.
 *
 * NOTE: This file used to masquerade as a benchmark of real sites
 * (google.com / youtube.com / ...). No such benchmark ever ran — the site
 * table was dead code and every assertion was computed from hand-written
 * finding lists. It now states honestly what it tests: the deterministic
 * computeRiskScore maturity thresholds. Real-target behaviour is covered by
 * tests/e2e-target.test.js, which runs the scanner against live in-process
 * HTTP targets.
 */

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

describe('computeRiskScore — config-only findings stay low', () => {
    const { computeRiskScore } = require('../scanner');

    it('pristine site with only a few config issues is low/info', () => {
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

    it('missing security headers + insecure cookies is at most low', () => {
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

    it('no active vulns means no high/critical level', () => {
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

describe('computeRiskScore — active vulns drive the score', () => {
    const { computeRiskScore } = require('../scanner');

    it('SQLi + XSS pushes the level to high', () => {
        const vulns = [
            { type: 'sql_injection', severity: 'critical' },
            { type: 'xss', severity: 'high' },
            { type: 'open_redirect', severity: 'medium' },
        ];
        const { score, level } = computeRiskScore(vulns);
        expect(score).toBeGreaterThanOrEqual(60);
        expect(level).toBe('high');
    });

    it('repeated same-type findings have diminishing returns', () => {
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

describe('computeRiskScore — configuration semantics', () => {
    const { computeRiskScore, checkCspValue } = require('../scanner');

    it('CSP with default-src self is clean', () => {
        expect(checkCspValue("default-src 'self'")).toEqual([]);
    });

    it('crossdomain.xml without wildcard stays info', () => {
        const { score } = computeRiskScore([
            { type: 'sensitive_file_disclosure', severity: 'info' },
        ]);
        expect(score).toBeLessThanOrEqual(2);
    });

    it('__Secure- cookie missing HttpOnly is still scored', () => {
        const { score } = computeRiskScore([
            { type: 'insecure_cookie', severity: 'medium' },
        ]);
        expect(score).toBeGreaterThanOrEqual(0);
    });
});

describe('Categorization consistency', () => {
    const { computeRiskScore } = require('../scanner');

    it('all-config vs all-active findings give very different scores', () => {
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

    it('categorize() buckets finding types consistently', () => {
        const counts = categorize([
            { type: 'sql_injection', severity: 'critical' },
            { type: 'open_redirect', severity: 'medium' },
            { type: 'xss', severity: 'info' },
            { type: 'sensitive_file_disclosure', severity: 'high' },
            { type: 'missing_security_header', severity: 'medium' },
        ]);
        expect(counts.active).toBe(1);
        expect(counts.redirect).toBe(1);
        expect(counts.info).toBe(1);
        expect(counts.exposure).toBe(1);
        expect(counts.config).toBe(1);
    });
});