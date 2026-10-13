const config = require('../config');
const policy = require('../agent/policy');

describe('isInternalHost', () => {
    it('detects loopback and private ranges', () => {
        expect(policy.isInternalHost('localhost')).toBe(true);
        expect(policy.isInternalHost('127.0.0.1')).toBe(true);
        expect(policy.isInternalHost('10.1.2.3')).toBe(true);
        expect(policy.isInternalHost('172.16.0.1')).toBe(true);
        expect(policy.isInternalHost('192.168.1.1')).toBe(true);
        expect(policy.isInternalHost('169.254.169.254')).toBe(true);
        expect(policy.isInternalHost('::1')).toBe(true);
        expect(policy.isInternalHost('fe80::1')).toBe(true);
    });

    it('allows public hosts', () => {
        expect(policy.isInternalHost('example.com')).toBe(false);
        expect(policy.isInternalHost('8.8.8.8')).toBe(false);
    });
});

describe('checkScope', () => {
    const orig = { ...config.security };

    afterEach(() => Object.assign(config.security, orig));

    it('allows the original target even if local', () => {
        config.security.allowInternalIps = false;
        const result = policy.checkScope('http://localhost:5000/x', 'http://localhost:5000');
        expect(result.allowed).toBe(true);
    });

    it('blocks internal hosts that are not the target', () => {
        config.security.allowInternalIps = false;
        const result = policy.checkScope('http://127.0.0.1/', 'http://example.com');
        expect(result.allowed).toBe(false);
    });

    it('blocks cloud metadata endpoints', () => {
        const result = policy.checkScope('http://169.254.169.254/latest/meta-data/', 'http://169.254.169.254');
        expect(result.allowed).toBe(false);
    });

    it('blocks non-http protocols', () => {
        const result = policy.checkScope('file:///etc/passwd', 'http://example.com');
        expect(result.allowed).toBe(false);
    });

    it('enforces AUTHORIZED_TARGETS allowlist', () => {
        config.security.authorizedTargets = ['example.com'];
        config.security.allowInternalIps = false;
        expect(policy.checkScope('https://example.com/x', 'https://example.com').allowed).toBe(true);
        expect(policy.checkScope('https://sub.example.com/x', 'https://example.com').allowed).toBe(true);
        expect(policy.checkScope('https://evil.com/x', 'https://example.com').allowed).toBe(false);
    });

    it('rejects invalid URLs', () => {
        expect(policy.checkScope('not a url', 'http://example.com').allowed).toBe(false);
    });
});

describe('validateAction', () => {
    const orig = { ...config.agent };

    afterEach(() => Object.assign(config.agent, orig));

    it('allows safe GET requests in scope', () => {
        config.agent.allowDestructive = false;
        const v = policy.validateAction('http_request', { url: 'https://example.com/?x=1' }, { targetUrl: 'https://example.com' });
        expect(v.allowed).toBe(true);
    });

    it('blocks unknown methods', () => {
        const v = policy.validateAction('http_request', { method: 'TRACE', url: 'https://example.com' }, { targetUrl: 'https://example.com' });
        expect(v.allowed).toBe(false);
    });

    it('blocks destructive methods unless enabled', () => {
        config.agent.allowDestructive = false;
        const v = policy.validateAction('http_request', { method: 'DELETE', url: 'https://example.com' }, { targetUrl: 'https://example.com' });
        expect(v.allowed).toBe(false);
    });

    it('permits destructive methods when explicitly enabled', () => {
        config.agent.allowDestructive = true;
        const v = policy.validateAction('http_request', { method: 'DELETE', url: 'https://example.com' }, { targetUrl: 'https://example.com' });
        expect(v.allowed).toBe(true);
    });

    it('validates crawl paths against scope', () => {
        const v = policy.validateAction('crawl', { path: '/admin' }, { targetUrl: 'https://example.com' });
        expect(v.allowed).toBe(true);
        expect(v.url).toContain('https://example.com/admin');
    });

    it('requires a url for http_request', () => {
        expect(policy.validateAction('http_request', {}, { targetUrl: 'https://example.com' }).allowed).toBe(false);
    });
});
