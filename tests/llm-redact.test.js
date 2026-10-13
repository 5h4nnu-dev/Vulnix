const { redactString, redactHeaders, redactBody, REDACT } = require('../llm/redact');

describe('redactString', () => {
    it('redacts JWT tokens', () => {
        const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop';
        expect(redactString(`token=${jwt}`)).toContain(REDACT);
        expect(redactString(`token=${jwt}`)).not.toContain(jwt);
    });

    it('redacts OpenAI style keys', () => {
        const key = 'sk-' + 'a'.repeat(30);
        expect(redactString(`key: ${key}`)).not.toContain(key);
    });

    it('redacts AWS access keys', () => {
        const key = 'AKIAIOSFODNN7EXAMPLE';
        expect(redactString(`id=${key}`)).not.toContain(key);
    });

    it('keeps the key name but redacts assignment values', () => {
        const out = redactString('password=supersecret123');
        expect(out).toContain('password');
        expect(out).not.toContain('supersecret123');
    });

    it('leaves benign text untouched', () => {
        expect(redactString('hello world')).toBe('hello world');
    });

    it('handles non-strings', () => {
        expect(redactString(null)).toBeNull();
    });
});

describe('redactHeaders', () => {
    it('redacts sensitive header values by name', () => {
        const out = redactHeaders({ Authorization: 'Bearer abc123', 'Content-Type': 'application/json' });
        expect(out.Authorization).toBe(REDACT);
        expect(out['Content-Type']).toBe('application/json');
    });

    it('handles arrays of pairs', () => {
        const out = redactHeaders([['cookie', 'session=abc'], ['server', 'nginx']]);
        expect(out.cookie).toBe(REDACT);
        expect(out.server).toBe('nginx');
    });

    it('handles empty input', () => {
        expect(redactHeaders(null)).toEqual({});
    });
});

describe('redactBody', () => {
    it('truncates long bodies', () => {
        const out = redactBody('x'.repeat(5000), 100);
        expect(out.length).toBeLessThan(200);
        expect(out).toContain('truncated');
    });

    it('redacts secrets in the body', () => {
        const out = redactBody('api_key=abcdef123456', 1000);
        expect(out).not.toContain('abcdef123456');
    });

    it('handles non-strings', () => {
        expect(redactBody(null)).toBe('');
    });
});
