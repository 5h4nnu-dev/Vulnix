/**
 * Agent working memory.
 *
 * Holds the action trace, findings, visited URLs and request/budget counters for
 * a single engagement. Kept deliberately simple and serializable so it can be
 * persisted and inspected.
 */

class AgentMemory {
    constructor({ targetUrl, maxSteps, maxRequests, maxSeconds }) {
        this.targetUrl = targetUrl;
        this.maxSteps = maxSteps;
        this.maxRequests = maxRequests;
        this.maxSeconds = maxSeconds;

        this.startedAt = Date.now();
        this.requestCount = 0;
        this.requestFailures = 0;
        this.scopeBlocked = 0;
        this.steps = [];
        this.findings = [];
        this.visited = new Set();
        this.discovered = new Set();
        this.cancelled = false;
        this.finished = false;
        this.summary = null;
    }

    addStep(step) {
        this.steps.push(step);
    }

    addFinding(finding) {
        this.findings.push(finding);
    }

    markVisited(url) {
        this.visited.add(url);
    }

    hasVisited(url) {
        return this.visited.has(url);
    }

    addDiscovered(urls) {
        for (const u of urls) this.discovered.add(u);
    }

    incrementRequests(n = 1) {
        this.requestCount += n;
    }

    elapsedSeconds() {
        return (Date.now() - this.startedAt) / 1000;
    }

    outOfBudget() {
        if (this.steps.length >= this.maxSteps) return 'max steps reached';
        if (this.requestCount >= this.maxRequests) return 'max requests reached';
        if (this.elapsedSeconds() >= this.maxSeconds) return 'time budget reached';
        return null;
    }

    cancel() {
        this.cancelled = true;
    }

    snapshot() {
        return {
            target: this.targetUrl,
            steps: this.steps.length,
            requests: this.requestCount,
            requestFailures: this.requestFailures,
            scopeBlocked: this.scopeBlocked,
            findings: this.findings.length,
            elapsed: Math.round(this.elapsedSeconds()),
        };
    }
}

module.exports = { AgentMemory };
