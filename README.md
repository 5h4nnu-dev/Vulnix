# Vulnix

> AI-assisted web vulnerability scanner for **authorized** penetration testing.

Vulnix combines a fast, deterministic scanning engine with an optional
large-language-model layer that writes custom, endpoint-specific payloads and can
drive an autonomous plan → act → observe agent loop. It detects classic web
vulnerabilities, tests targets for **prompt injection**, protects the agent from
prompt-injection attempts hidden in target responses, and exports professional
**Markdown** and **Word (.docx)** reports.

> ⚠️ **Authorized testing only.** Only scan systems you own or have explicit
> written permission to test. Unauthorized scanning is illegal in most
> jurisdictions.

---

## Quick Start

```bash
npm install
npm start
```

Open **http://127.0.0.1:5000** in your browser.

Development mode (auto-restart on changes):

```bash
npm run dev
```

No external database is required — SQLite runs locally and stores data in
`secureprobe.db`.

---

## Connecting the LLM (optional)

Vulnix works fully **without** any LLM (deterministic mode). The AI layer is a
thin, provider-agnostic client over the real HTTP APIs of Ollama or any
OpenAI-compatible server — there is no simulated or canned model output. If the
provider is not reachable, the AI endpoints return a real error and the scanner
simply keeps running deterministically.

To enable AI features:

1. Start a provider (Ollama or an OpenAI-compatible endpoint).
2. Set `LLM_ENABLED=true` and point Vulnix at the provider.
3. Restart (`npm start`) and confirm the connection.

### Step 1 — Start a provider

**Ollama (local, private, recommended — target data never leaves the machine)**

```bash
# install Ollama: https://ollama.com/download  (or: brew install ollama)
ollama serve                     # starts the API on http://localhost:11434
ollama pull qwen2.5-coder:7b     # any chat/code model works
```

**OpenAI or any OpenAI-compatible gateway**

Obtain an API key from your provider (OpenAI, Azure OpenAI, OpenRouter, Groq,
vLLM, LM Studio, LocalAI, …). You only need a base URL and, usually, a key.

### Step 2 — Point Vulnix at the provider

The easiest way is to copy `.env.example` to `.env` and fill it in — Vulnix
loads that file on startup (real environment variables always win).

**Ollama**

```dotenv
LLM_ENABLED=true
LLM_PROVIDER=ollama
OLLAMA_HOST=http://localhost:11434
# LLM_MODEL is auto-discovered when unset (prefers code/chat models)
```

**OpenAI-compatible**

```dotenv
LLM_ENABLED=true
LLM_PROVIDER=openai
OPENAI_BASE_URL=https://api.openai.com   # or your gateway, no trailing slash
OPENAI_API_KEY=sk-...
LLM_MODEL=gpt-4o-mini
```

You can also export the same names in your shell instead of using `.env`:

```bash
export LLM_ENABLED=true
export LLM_PROVIDER=ollama
export OLLAMA_HOST=http://localhost:11434
npm start
```

> **Model selection:** set `LLM_MODEL` to pin an exact model. When it is left
> empty Vulnix discovers the provider's models (`GET /api/tags` for Ollama,
> `GET /v1/models` for OpenAI-compatible) and ranks them, preferring
> code/instruction-tuned chat models.

> **Privacy note:** OpenAI-compatible (cloud) endpoints send redacted target data
> off-host. Sensitive values (tokens, cookies, keys, JWTs) are scrubbed before
> every model call, but the local Ollama option keeps everything on-device.

### Step 3 — Verify the connection

- **UI:** the AI status chip on the *New Scan* page shows
  `AI: <provider> · <model>` when the provider is reachable.
- **API:** `GET /api/ai/status` returns `{ enabled, reachable, provider,
  endpoint, models, model }`.
- **Smoke test:** ask the assistant a question with
  `POST /api/ai/analyze` `{ "question": "Reply with the word ready" }`.

If `reachable` is `false`, check that the provider is running, the host/URL is
correct, and (for cloud providers) `OPENAI_API_KEY` is set. See the table of
configuration variables below for every AI-related setting.

> **AI needs explicit consent.** Hybrid/agent scan modes and the on-demand
> endpoints require `authorized: true` (and the "I am authorized" checkbox in the
> UI) in addition to `LLM_ENABLED=true`. If the provider is unreachable at scan
> time, the scan reports the real error and continues with the deterministic
> engine rather than inventing results.

---

## Scan Modes

| Mode | What it does |
|------|--------------|
| `deterministic` | Fast, reproducible checks. No LLM required. |
| `hybrid` | Deterministic checks with AI-generated payloads, followed by adaptive agent probes. |
| `agent` | The fixed deterministic checks run first, followed by an adaptive plan → act → observe agent. |

All modes retain the deterministic checks as a baseline. Agent budgets count
scanner-issued requests, including retries and confirmation probes. Scan
events report disabled checks, discovery coverage, request failures, and budget
exhaustion. A clean result only means no issue was detected in the surfaces and
checks that completed; discovery is bounded, and blind SSRF without a callback
service is outside the current detector's coverage.

AI/autonomous modes require the **"I am authorized"** confirmation in the UI (and
`authorized: true` in the API) and `LLM_ENABLED=true`.

---

## Features

- 🛡️ **Deterministic engine** — security headers, cookie flags, CORS, SQLi
  (error/time/boolean), XSS (encoding-aware), open redirect, HTTP methods,
  sensitive files (signature-validated), rate limiting, tech fingerprinting.
- ⚡ **New active checks** — OS command injection (output + time based), path
  traversal/LFI, and SSRF (cloud-metadata aware).
- 🤖 **AI payload generation** — the model writes custom payloads tailored to the
  endpoint, technology, and context; every payload is schema-validated and
  safety-filtered before use.
- 🧭 **Autonomous agent** — a bounded plan → act → observe loop with tools for
  HTTP requests, crawling, fingerprinting, payload generation, parameter testing,
  and finding recording.
- 🧪 **Prompt-injection detection (target-side)** — canary/instruction-override
  probes against LLM-facing inputs (query params and JSON POST bodies), recorded
  as findings and coverage rows. In LLM mode the model writes endpoint-tailored
  probes, and any endpoint can be tested on demand via `POST /api/prompt-injection/test`.
- 🛡️ **Agent self-protection** — untrusted target content is isolated and scanned
  for injection attempts; model output is validated so the harness never executes
  arbitrary instructions.
- 📄 **Reports** — download Markdown **and** DOCX (Word) reports that include the
  executive summary, findings, AI payloads, prompt-injection results, and the
  agent action trace.
- 💾 **Persistent storage** — SQLite via better-sqlite3 (WAL mode).
- 🎨 **Dark cyber terminal UI** — real-time progress, live events, AI panels.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_HOST` | `127.0.0.1` | Bind address (localhost only by default) |
| `VULNIX_API_TOKEN` | unset | Random secret (at least 32 characters) required for API access on non-loopback binds; the UI prompts for it |
| `PORT` | `5000` | Server port |
| `LLM_ENABLED` | `false` | Master switch for all AI features |
| `LLM_PROVIDER` | `ollama` | `ollama` or `openai` |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama base URL |
| `OPENAI_BASE_URL` | `https://api.openai.com` | OpenAI-compatible base URL |
| `OPENAI_API_KEY` | — | API key for OpenAI-compatible providers |
| `LLM_MODEL` | auto | Model name; auto-discovered when unset |
| `LLM_TEMPERATURE` | `0.2` | Sampling temperature |
| `LLM_TIMEOUT_MS` | `60000` | Per-request timeout |
| `LLM_MAX_PAYLOADS` | `12` | Max AI payloads per vulnerability class |
| `AGENT_MAX_STEPS` | `25` | Max agent iterations |
| `AGENT_MAX_REQUESTS` | `200` | Max HTTP requests per engagement |
| `AGENT_MAX_SECONDS` | `600` | Wall-clock budget |
| `AGENT_ALLOW_DESTRUCTIVE` | `false` | Allow PUT/DELETE/PATCH |
| `AUTHORIZED_TARGETS` | — | Comma-separated host allowlist |
| `REQUIRE_AUTHORIZATION` | `true` | Require explicit consent for AI modes |
| `ALLOW_INTERNAL_IPS` | `false` | Allow private/loopback targets |

---

## Safety Model

Vulnix is built so the model **proposes** and a deterministic harness
**disposes**:

- **Scope allowlist** — every request must match the target / `AUTHORIZED_TARGETS`.
- **Consent gate** — AI/agent modes require explicit authorization.
- **IP & metadata guard** — blocks cloud metadata endpoints and private ranges
  (except the original target), and disables destructive HTTP methods by default.
- **Hard budgets** — step, request, and time caps; a cancel endpoint stops a run.
- **Redaction** — tokens, cookies, keys, and JWTs are scrubbed before model calls.
- **Injection isolation** — target content is wrapped as untrusted data and
  scanned; model output is validated against dangerous patterns.
- **Audit trail** — every agent step and prompt-injection test is persisted.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scans` | Start a scan (`mode`, `useAi`, `authorized`, `options`) |
| GET | `/api/scans` | List scans (paginated) |
| GET | `/api/scans/:id` | Scan with vulnerabilities and events |
| GET | `/api/scans/:id/status` | Poll scan progress |
| GET | `/api/scans/:id/events` | Scan event timeline |
| GET | `/api/scans/:id/vulnerabilities` | Scan vulnerabilities |
| POST | `/api/scans/:id/cancel` | Cancel a running agent scan |
| GET | `/api/scans/:id/report` | Download Markdown report |
| GET | `/api/scans/:id/report.docx` | Download DOCX (Word) report |
| GET | `/api/scans/:id/ai-payloads` | AI-generated payloads for the scan |
| GET | `/api/scans/:id/prompt-injection` | Prompt-injection test results |
| POST | `/api/prompt-injection/test` | On-demand prompt-injection test (`url`, `authorized`, optional `method`/`parameters`/`useAi`) |
| GET | `/api/scans/:id/agent-trace` | Agent action trace |
| GET | `/api/scans/:id/payloads` | Mapped payloads for detected vulns |
| DELETE | `/api/scans/:id` | Delete a scan |
| GET | `/api/ai/status` | LLM provider status and models |
| GET | `/api/ai/models` | List provider models |
| POST | `/api/ai/payloads` | Generate custom payloads on demand |
| POST | `/api/ai/analyze` | Ask the guarded assistant a question |
| GET | `/api/stats/summary` | Aggregate statistics |
| GET | `/api/stats/recent-activity` | Recent scans and vulnerabilities |
| GET | `/api/payloads` | Browse the payload database |
| GET | `/api/payloads/stats` | Payload statistics |

---

## Testing

```bash
npm test
```

The suite covers the scanner engine, the LLM client/guard/redaction, the agent
loop and policy, the payload generator, and the DOCX report generator.

Two kinds of tests run:

- **Unit tests** — mock `global.fetch` and never dial external hosts. The
  post-scan API happy path is deliberately driven through a hermetic fetch mock,
  so the suite never depends on external connectivity.
- **Real-target end-to-end tests** (`tests/e2e-target.test.js`) — spin up live
  in-process HTTP servers (a well-configured benign site and a deliberately
  vulnerable one) and run the actual scanner engine and agent detectors against
  them over real HTTP. These tests prove detection *and* prove there are no
  false positives: the benign site with all security headers, strict CSP,
  HTML-encoded output, and a page that mentions "canary"/"SSRF" terms yields
  **zero** vulnerabilities, while the vulnerable fixture is caught for SQLi,
  XSS, command injection, path traversal, SSRF, open redirect, and prompt
  injection.

All tests run without a live LLM; `useAi` paths are exercised with the LLM
disabled.

---

## Project Structure

```
Vulnix/
├── server.js            # Express API + routes
├── scanner.js           # Deterministic engine + new checks + PI detection
├── database.js          # SQLite schema, migrations, prepared statements
├── config.js            # Env/.env configuration layer
├── llm/
│   ├── client.js        # Ollama / OpenAI-compatible provider abstraction
│   ├── models.js        # Model discovery & ranking
│   ├── prompts.js       # Hardened prompts
│   ├── guard.js         # Injection detection + output validation
│   ├── redact.js        # Secret redaction
│   ├── payloadGenerator.js
│   ├── analyst.js
│   └── summary.js
├── agent/
│   ├── loop.js          # plan → act → observe orchestration
│   ├── tools.js         # http_request, crawl, fingerprint, test_parameter, …
│   ├── policy.js        # Scope + safety enforcement
│   └── memory.js        # Working memory / budgets
├── report/
│   ├── markdown.js
│   └── docx.js
├── payloads/            # Static payload modules
├── public/              # Vanilla SPA (HTML/CSS/JS)
└── tests/               # Jest + supertest suites
```

---

## Disclaimer

**Only scan URLs you own or have explicit, written permission to test.**
Unauthorized scanning may violate laws and regulations. The authors accept no
liability for misuse.

*Vulnix — built for accurate, actionable, authorized security analysis.*
