const payloadEngine = require('../payloads');

describe('getPayloadsForVuln', () => {
    it('returns module for known vuln type', () => {
        const mod = payloadEngine.getPayloadsForVuln('xss');
        expect(mod).not.toBeNull();
        expect(mod.vulnerability).toBe('xss');
        expect(mod.payloads.length).toBeGreaterThan(0);
    });

    it('returns null for unknown vuln type', () => {
        expect(payloadEngine.getPayloadsForVuln('unknown_type')).toBeNull();
    });

    it('returns module with name and description', () => {
        const mod = payloadEngine.getPayloadsForVuln('sql_injection');
        expect(mod.name).toBe('SQL Injection');
        expect(mod.description).toContain('SQL');
    });
});

describe('getPayloadsByType', () => {
    it('filters by category', () => {
        const basic = payloadEngine.getPayloadsByType('xss', 'basic');
        expect(basic.length).toBeGreaterThan(0);
        basic.forEach(p => expect(p.type).toBe('basic'));
    });

    it('returns null for invalid vuln type', () => {
        expect(payloadEngine.getPayloadsByType('nonexistent', 'basic')).toBeNull();
    });

    it('returns empty for valid type but wrong category', () => {
        const result = payloadEngine.getPayloadsByType('xss', 'nonexistent_category');
        expect(result).toEqual([]);
    });

    it('returns all time-based SQLi payloads', () => {
        const timeBased = payloadEngine.getPayloadsByType('sql_injection', 'time_based');
        expect(timeBased.length).toBeGreaterThan(0);
        timeBased.forEach(p => expect(p.type).toBe('time_based'));
    });

    it('returns filter_bypass XSS payloads', () => {
        const bypass = payloadEngine.getPayloadsByType('xss', 'filter_bypass');
        expect(bypass.length).toBeGreaterThan(0);
    });
});

describe('getAllPayloads', () => {
    it('returns all payload modules', () => {
        const all = payloadEngine.getAllPayloads();
        expect(Array.isArray(all)).toBe(true);
        expect(all.length).toBeGreaterThanOrEqual(9);
    });

    it('each module has required fields', () => {
        const all = payloadEngine.getAllPayloads();
        all.forEach(mod => {
            expect(mod.vulnerability).toBeDefined();
            expect(mod.name).toBeDefined();
            expect(mod.payloads).toBeDefined();
            expect(mod.total_payloads).toBe(mod.payloads.length);
        });
    });
});

describe('listVulnTypes', () => {
    it('returns array of vulnerability type strings', () => {
        const types = payloadEngine.listVulnTypes();
        expect(Array.isArray(types)).toBe(true);
        expect(types).toContain('xss');
        expect(types).toContain('sql_injection');
        expect(types).toContain('open_redirect');
        expect(types).toContain('cors_misconfiguration');
    });
});

describe('getStats', () => {
    it('returns stats with module counts', () => {
        const stats = payloadEngine.getStats();
        expect(stats.total_modules).toBeGreaterThanOrEqual(9);
        expect(stats.total_payloads).toBeGreaterThan(0);
        expect(stats.modules.length).toBe(stats.total_modules);
    });

    it('each module stat has required fields', () => {
        const stats = payloadEngine.getStats();
        stats.modules.forEach(m => {
            expect(m.vulnerability).toBeDefined();
            expect(m.count).toBeGreaterThan(0);
            expect(Array.isArray(m.types)).toBe(true);
        });
    });
});

describe('mapPayloadsToScanResults', () => {
    it('returns empty array for no vulnerabilities', () => {
        expect(payloadEngine.mapPayloadsToScanResults([])).toEqual([]);
    });

    it('returns empty for null input', () => {
        expect(payloadEngine.mapPayloadsToScanResults(null)).toEqual([]);
    });

    it('maps detected vulns to relevant payloads', () => {
        const vulns = [
            { type: 'xss', severity: 'high', affected_endpoint: 'https://example.com?q=test', payload: '<script>alert(1)</script>' },
        ];
        const results = payloadEngine.mapPayloadsToScanResults(vulns);
        expect(results.length).toBe(1);
        expect(results[0].vulnerability).toBe('xss');
        expect(results[0].detected_instances).toBe(1);
        expect(results[0].payloads.length).toBeGreaterThan(0);
    });

    it('handles multiple vuln types', () => {
        const vulns = [
            { type: 'xss', severity: 'high', affected_endpoint: 'https://example.com?q=test', payload: '<script>' },
            { type: 'sql_injection', severity: 'critical', affected_endpoint: 'https://example.com?id=1', payload: "' OR 1=1--" },
        ];
        const results = payloadEngine.mapPayloadsToScanResults(vulns);
        expect(results.length).toBe(2);
        const types = results.map(r => r.vulnerability);
        expect(types).toContain('xss');
        expect(types).toContain('sql_injection');
    });

    it('preserves aliased vuln types', () => {
        const vulns = [
            { type: 'missing_security_header', severity: 'medium', affected_endpoint: 'https://example.com', payload: '' },
        ];
        const results = payloadEngine.mapPayloadsToScanResults(vulns);
        expect(results.length).toBe(1);
        expect(results[0].total_payloads).toBeGreaterThan(0);
    });

    it('sorts results by severity descending', () => {
        const vulns = [
            { type: 'info_disclosure', severity: 'low', affected_endpoint: 'https://example.com', payload: '' },
            { type: 'sql_injection', severity: 'critical', affected_endpoint: 'https://example.com?id=1', payload: "'" },
        ];
        const results = payloadEngine.mapPayloadsToScanResults(vulns);
        expect(results[0].vulnerability).toBe('sql_injection');
    });
});

describe('payload integrity', () => {
    it('all XSS payloads have required fields', () => {
        const mod = payloadEngine.getPayloadsForVuln('xss');
        mod.payloads.forEach(p => {
            expect(p.type).toBeDefined();
            expect(p.payload).toBeDefined();
            expect(p.description).toBeDefined();
            expect(p.expected_behavior).toBeDefined();
        });
    });

    it('all SQL injection payloads have required fields', () => {
        const mod = payloadEngine.getPayloadsForVuln('sql_injection');
        mod.payloads.forEach(p => {
            expect(p.type).toBeDefined();
            expect(p.payload).toBeDefined();
            expect(p.description).toBeDefined();
        });
    });

    it('payload modules have no duplicate payload strings in same category', () => {
        const all = payloadEngine.getAllPayloads();
        all.forEach(mod => {
            const seen = new Map();
            mod.payloads.forEach(p => {
                const key = `${p.type}:${p.payload}`;
                if (seen.has(key)) {
                    throw new Error(`Duplicate payload in ${mod.vulnerability}: ${key}`);
                }
                seen.set(key, true);
            });
        });
    });
});
