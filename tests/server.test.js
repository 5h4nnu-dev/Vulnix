jest.mock('../database', () => {
    const mockRun = jest.fn();
    const mockGet = jest.fn();
    const mockAll = jest.fn();
    return {
        db: { prepare: () => ({ run: mockRun, get: mockGet, all: mockAll }), pragma: jest.fn(), exec: jest.fn() },
        stmts: {
            insertScan: { run: mockRun },
            getScan: { get: mockGet },
            listScans: { all: jest.fn(() => []) },
            countScans: { get: jest.fn(() => ({ count: 0 })) },
            updateScanProgress: { run: jest.fn() },
            updateScanStatus: { run: jest.fn() },
            updateScanRunning: { run: jest.fn() },
            completeScan: { run: jest.fn() },
            failScan: { run: jest.fn() },
            deleteScan: { run: jest.fn() },
            insertVuln: { run: mockRun },
            getVulns: { all: mockAll },
            insertEvent: { run: mockRun },
            getEvents: { all: mockAll },
            statsSummary: { get: jest.fn(() => ({ total_scans: 5, total_vulnerabilities: 12, critical_count: 2, high_count: 4, medium_count: 3, low_count: 3, avg_risk_score: 45.5 })) },
            topVulnTypes: { all: jest.fn(() => [{ type: 'xss', count: 5 }]) },
            recentScans: { all: jest.fn(() => []) },
            recentVulns: { all: jest.fn(() => []) },
        },
    };
});

const request = require('supertest');
const app = require('../server');

describe('POST /api/scans', () => {
    it('rejects missing URL', async () => {
        const res = await request(app)
            .post('/api/scans')
            .send({})
            .expect(400);
        expect(res.body.error).toBe('URL is required');
    });

    it('rejects invalid URL', async () => {
        const res = await request(app)
            .post('/api/scans')
            .send({ url: 'not a url' })
            .expect(400);
        expect(res.body.error).toBe('Invalid URL');
    });

    it('returns 201 for valid scan', async () => {
        const res = await request(app)
            .post('/api/scans')
            .send({ url: 'https://example.com' })
            .expect(201);
        expect(res.body).toBeDefined();
    });
});

describe('GET /api/scans', () => {
    it('returns scan list', async () => {
        const res = await request(app)
            .get('/api/scans')
            .expect(200);
        expect(res.body.scans).toBeDefined();
        expect(res.body.total).toBeDefined();
    });

    it('respects limit parameter', async () => {
        const res = await request(app)
            .get('/api/scans?limit=5')
            .expect(200);
        expect(res.body).toBeDefined();
    });
});

describe('GET /api/scans/:id', () => {
    it('returns 404 for nonexistent scan', async () => {
        const { stmts } = require('../database');
        stmts.getScan.get.mockReturnValue(undefined);

        const res = await request(app)
            .get('/api/scans/nonexistent')
            .expect(404);
        expect(res.body.error).toBe('Scan not found');
    });

    it('returns scan with vulns and events', async () => {
        const { stmts } = require('../database');
        stmts.getScan.get.mockReturnValue({
            id: 'test-id',
            url: 'https://example.com',
            status: 'completed',
            risk_score: 50,
            risk_level: 'medium',
            vulnerability_count: 2,
        });
        stmts.getVulns.all.mockReturnValue([
            { id: 'v1', type: 'xss', severity: 'high', title: 'XSS Found', affected_endpoint: 'https://example.com?q=test' },
        ]);
        stmts.getEvents.all.mockReturnValue([
            { id: 'e1', stage: 'xss', event_type: 'finding', title: 'XSS detected' },
        ]);

        const res = await request(app)
            .get('/api/scans/test-id')
            .expect(200);
        expect(res.body.scan).toBeDefined();
        expect(res.body.vulnerabilities).toHaveLength(1);
        expect(res.body.events).toHaveLength(1);
    });
});

describe('GET /api/stats/summary', () => {
    it('returns stats summary', async () => {
        const res = await request(app)
            .get('/api/stats/summary')
            .expect(200);
        expect(res.body.total_scans).toBe(5);
        expect(res.body.total_vulnerabilities).toBe(12);
        expect(res.body.top_vulnerability_types).toBeDefined();
    });
});

describe('DELETE /api/scans/:id', () => {
    it('returns 204 on delete', async () => {
        await request(app)
            .delete('/api/scans/test-id')
            .expect(204);
    });
});
