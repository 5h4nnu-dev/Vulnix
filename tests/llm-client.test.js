const config = require('../config');
const client = require('../llm/client');

function jsonResponse(data, status = 200) {
    return {
        ok: status >= 200 && status < 300,
        status,
        text: async () => JSON.stringify(data),
    };
}

describe('llm client', () => {
    const origFetch = global.fetch;
    const orig = { ...config.llm };

    beforeEach(() => {
        config.llm.enabled = true;
        config.llm.model = 'test-model';
        client.resetModelCache();
    });

    afterEach(() => {
        global.fetch = origFetch;
        Object.assign(config.llm, orig);
        client.resetModelCache();
    });

    it('parses Ollama chat responses', async () => {
        config.llm.provider = 'ollama';
        global.fetch = jest.fn(async () => jsonResponse({
            message: { role: 'assistant', content: 'hello' },
            eval_count: 3,
        }));

        const res = await client.chat([{ role: 'user', content: 'hi' }]);
        expect(res.content).toBe('hello');
        expect(res.provider).toBe('ollama');
        expect(res.model).toBe('test-model');
    });

    it('normalizes Ollama tool calls', async () => {
        config.llm.provider = 'ollama';
        global.fetch = jest.fn(async () => jsonResponse({
            message: {
                content: '',
                tool_calls: [{ function: { name: 'http_request', arguments: { url: 'http://x' } } }],
            },
        }));

        const res = await client.chat([{ role: 'user', content: 'go' }]);
        expect(res.toolCalls[0].name).toBe('http_request');
        expect(res.toolCalls[0].args).toEqual({ url: 'http://x' });
    });

    it('parses OpenAI-compatible chat responses', async () => {
        config.llm.provider = 'openai';
        config.llm.openaiBaseUrl = 'http://localhost:9999';
        global.fetch = jest.fn(async (url) => {
            expect(String(url)).toContain('/v1/chat/completions');
            return jsonResponse({ choices: [{ message: { content: 'world' } }], usage: { total_tokens: 5 } });
        });

        const res = await client.chat([{ role: 'user', content: 'hi' }]);
        expect(res.content).toBe('world');
        expect(res.provider).toBe('openai');
    });

    it('throws a clear error when the provider fails', async () => {
        config.llm.provider = 'ollama';
        global.fetch = jest.fn(async () => jsonResponse({ error: 'nope' }, 500));
        await expect(client.chat([{ role: 'user', content: 'hi' }])).rejects.toThrow(/Ollama chat failed/);
    });

    it('lists Ollama models', async () => {
        config.llm.provider = 'ollama';
        global.fetch = jest.fn(async () => jsonResponse({ models: [{ name: 'a' }, { name: 'b' }] }));
        expect(await client.listModels()).toEqual(['a', 'b']);
    });

    it('reports health and auto-selects a model', async () => {
        config.llm.provider = 'ollama';
        config.llm.model = '';
        client.resetModelCache();
        global.fetch = jest.fn(async () => jsonResponse({ models: [{ name: 'llama3.1:8b' }, { name: 'qwen2.5-coder:7b' }] }));
        const h = await client.health();
        expect(h.reachable).toBe(true);
        expect(h.model).toBe('qwen2.5-coder:7b');
    });

    it('retries chatJson once on invalid JSON', async () => {
        config.llm.provider = 'ollama';
        let call = 0;
        global.fetch = jest.fn(async () => {
            call++;
            return jsonResponse({ message: { content: call === 1 ? 'not json' : '{"ok":true}' } });
        });
        const { data } = await client.chatJson([{ role: 'user', content: 'hi' }]);
        expect(data).toEqual({ ok: true });
        expect(call).toBe(2);
    });

    it('returns data:null when JSON never parses', async () => {
        config.llm.provider = 'ollama';
        global.fetch = jest.fn(async () => jsonResponse({ message: { content: 'still not json' } }));
        const { data, error } = await client.chatJson([{ role: 'user', content: 'hi' }]);
        expect(data).toBeNull();
        expect(error).toBeDefined();
    });
});
