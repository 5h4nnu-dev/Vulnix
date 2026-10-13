const { scoreModel, rankModels, pickModel } = require('../llm/models');

describe('scoreModel', () => {
    it('prefers code models', () => {
        expect(scoreModel('qwen2.5-coder:7b')).toBeGreaterThan(scoreModel('llama3.1:8b'));
    });

    it('penalizes embedding models', () => {
        expect(scoreModel('nomic-embed-text')).toBeLessThan(scoreModel('llama3.1:8b'));
    });

    it('penalizes tiny models', () => {
        expect(scoreModel('smollm:1b')).toBeLessThan(scoreModel('llama3.1:8b'));
    });
});

describe('rankModels', () => {
    it('sorts best first', () => {
        const ranked = rankModels(['nomic-embed-text', 'llama3.1:8b', 'qwen2.5-coder:7b']);
        expect(ranked[0]).toBe('qwen2.5-coder:7b');
        expect(ranked[ranked.length - 1]).toBe('nomic-embed-text');
    });

    it('does not mutate the input', () => {
        const input = ['b', 'a'];
        rankModels(input);
        expect(input).toEqual(['b', 'a']);
    });
});

describe('pickModel', () => {
    it('returns the top ranked model', () => {
        expect(pickModel(['llama3.1', 'qwen2.5-coder'])).toBe('qwen2.5-coder');
    });

    it('returns null for empty or invalid input', () => {
        expect(pickModel([])).toBeNull();
        expect(pickModel(null)).toBeNull();
    });
});
