jest.mock('../llm/client', () => ({
    chatJson: jest.fn(),
}));

jest.mock('../agent/tools', () => ({
    execute: jest.fn(async (name, args, state) => {
        if (name === 'record_finding') {
            state.memory.addFinding({ title: args.title });
            state.addVuln({ title: args.title, severity: args.severity });
        }
        return { ok: true };
    }),
}));

const client = require('../llm/client');
const tools = require('../agent/tools');
const config = require('../config');
const { runAgent } = require('../agent/loop');

function htmlResponse() {
    return { status: 200, text: async () => '<html><body>hello</body></html>' };
}

describe('agent loop', () => {
    const origFetch = global.fetch;

    beforeEach(() => {
        global.fetch = jest.fn(async () => htmlResponse());
        client.chatJson.mockReset();
        tools.execute.mockClear();
    });

    afterEach(() => {
        global.fetch = origFetch;
    });

    it('runs plan -> act -> observe until finish', async () => {
        client.chatJson
            .mockResolvedValueOnce({ data: { thought: 'recon', action: 'crawl', args: { path: '/' } } })
            .mockResolvedValueOnce({ data: { thought: 'probe', action: 'test_parameter', args: { endpoint: 'http://localhost:5000/', param: 'id', vuln_type: 'sql_injection' } } })
            .mockResolvedValueOnce({ data: { thought: 'found', action: 'record_finding', args: { type: 'xss', severity: 'high', title: 'XSS', description: 'd', endpoint: 'http://localhost:5000/?q=1' } } })
            .mockResolvedValueOnce({ data: { thought: 'done', action: 'finish', args: { summary: 'complete' } } });

        const steps = [];
        const vulns = [];
        const result = await runAgent('scan-1', 'http://localhost:5000', { maxSteps: 10 }, {
            addEvent: () => {},
            addVuln: (id, v) => vulns.push(v),
            updateProgress: () => {},
            recordStep: (n, action) => steps.push({ n, action }),
        });

        expect(result.summary).toBe('complete');
        expect(result.findings).toBe(1);
        expect(vulns).toHaveLength(1);
        expect(vulns[0].title).toBe('XSS');
        expect(tools.execute).toHaveBeenCalledTimes(3);
    });

    it('stops when the step budget is exhausted', async () => {
        client.chatJson.mockResolvedValue({ data: { thought: 'loop', action: 'crawl', args: {} } });

        const result = await runAgent('scan-2', 'http://localhost:5000', { maxSteps: 2 }, {
            addEvent: () => {}, addVuln: () => {}, updateProgress: () => {}, recordStep: () => {},
        });

        expect(result.stopped).toBe('max steps reached');
        expect(result.steps).toBe(2);
    });

    it('honors cancellation', async () => {
        client.chatJson.mockResolvedValue({ data: { thought: 'loop', action: 'crawl', args: {} } });

        const result = await runAgent('scan-3', 'http://localhost:5000', {}, {
            addEvent: () => {}, addVuln: () => {}, updateProgress: () => {}, recordStep: () => {},
            isCancelled: () => true,
        });

        expect(result.stopped).toBe('cancelled');
        expect(tools.execute).not.toHaveBeenCalled();
    });

    it('rejects unknown tools and keeps going', async () => {
        client.chatJson
            .mockResolvedValueOnce({ data: { thought: 'bad', action: 'rm_rf', args: {} } })
            .mockResolvedValueOnce({ data: { thought: 'done', action: 'finish', args: { summary: 'ok' } } });

        const result = await runAgent('scan-4', 'http://localhost:5000', {}, {
            addEvent: () => {}, addVuln: () => {}, updateProgress: () => {}, recordStep: () => {},
        });

        expect(result.summary).toBe('ok');
        expect(tools.execute).not.toHaveBeenCalled();
    });

    it('stops on LLM errors', async () => {
        client.chatJson.mockRejectedValue(new Error('provider down'));

        const result = await runAgent('scan-5', 'http://localhost:5000', {}, {
            addEvent: () => {}, addVuln: () => {}, updateProgress: () => {}, recordStep: () => {},
        });

        expect(result.stopped).toBe('llm_error');
    });

    it('blocks out-of-scope actions via policy', async () => {
        client.chatJson
            .mockResolvedValueOnce({ data: { thought: 'evil', action: 'http_request', args: { url: 'http://169.254.169.254/latest/meta-data/' } } })
            .mockResolvedValueOnce({ data: { thought: 'done', action: 'finish', args: { summary: 'done' } } });

        const result = await runAgent('scan-6', 'https://example.com', {}, {
            addEvent: () => {}, addVuln: () => {}, updateProgress: () => {}, recordStep: () => {},
        });

        expect(result.stopped).toBe('finished');
        expect(tools.execute).not.toHaveBeenCalled();
    });
});
