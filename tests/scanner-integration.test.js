jest.mock('../database', () => {
    const mockRun = jest.fn();
    const mockAllFn = jest.fn(() => []);
    return {
        db: { prepare: () => ({ run: mockRun, get: jest.fn(), all: mockAllFn }), pragma: jest.fn(), exec: jest.fn() },
        stmts: {
            insertScan: { run: jest.fn() },
            getScan: { get: jest.fn(() => null) },
            listScans: { all: jest.fn(() => []) },
            countScans: { get: jest.fn(() => ({ count: 0 })) },
            updateScanProgress: { run: jest.fn() },
            updateScanStatus: { run: jest.fn() },
            updateScanRunning: { run: jest.fn() },
            completeScan: { run: jest.fn() },
            failScan: { run: jest.fn() },
            deleteScan: { run: jest.fn() },
            insertVuln: { run: mockRun },
            getVulns: { all: mockAllFn },
            insertEvent: { run: mockRun },
            getEvents: { all: jest.fn(() => []) },
            statsSummary: { get: jest.fn(() => ({})) },
            topVulnTypes: { all: jest.fn(() => []) },
            recentScans: { all: jest.fn(() => []) },
            recentVulns: { all: jest.fn(() => []) },
        },
    };
});

const { simpleHash } = require('../scanner');

describe('checkCspValue integration', () => {
    const {
        checkCspValue,
        computeRiskScore,
        isSoft404,
        htmlDecode,
    } = require('../scanner');

    it('detects common misconfigurations', () => {
        expect(checkCspValue("default-src 'self'")).toEqual([]);
        expect(checkCspValue("default-src *")).not.toEqual([]);
        expect(checkCspValue("script-src 'unsafe-inline'")).not.toEqual([]);
    });
});

describe('risk score edge cases', () => {
    const { computeRiskScore } = require('../scanner');

    it('handles many low severity vulns', () => {
        const vulns = Array.from({ length: 10 }, (_, i) => ({
            type: 'info_disclosure',
            severity: 'info',
        }));
        const result = computeRiskScore(vulns);
        expect(result.score).toBeLessThan(10);
        expect(result.level).toBe('info');
    });

    it('single critical gives medium risk', () => {
        const result = computeRiskScore([
            { type: 'sql_injection', severity: 'critical' },
        ]);
        expect(result.score).toBe(40);
        expect(result.level).toBe('medium');
    });

    it('mixed many types gives high risk', () => {
        const vulns = [
            { type: 'xss', severity: 'high' },
            { type: 'sql_injection', severity: 'critical' },
            { type: 'open_redirect', severity: 'medium' },
            { type: 'cors_misconfiguration', severity: 'medium' },
            { type: 'info_disclosure', severity: 'low' },
        ];
        const result = computeRiskScore(vulns);
        expect(result.score).toBeGreaterThanOrEqual(55);
        expect(result.level).toBe('high');
    });
});
