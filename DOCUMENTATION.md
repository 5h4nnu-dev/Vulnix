# 🛡️ Vulnix v3.0 — Documentation

**AI-Assisted Web Security Vulnerability Scanner for Authorized Testing**

---

## Overview

Vulninx is a lightweight, single-server Node.js security scanner that performs active security analysis against target URLs. It identifies vulnerabilities across multiple categories and generates detailed reports with evidence, AI-powered explanations, exploitation scenarios, and remediation guidance.

### Key Accuracy Features (v2.1)

| Feature | Purpose |
|---------|---------|
| **Baseline Fingerprinting** | Fetches a random nonexistent path to fingerprint soft-404 pages, eliminating false positives in file discovery |
| **Response Time Baselining** | Measures median response time before testing, so time-based SQLi detection compares against actual server behavior |
| **Content-Signature Validation** | Each sensitive file has a regex signature (e.g., `.env` must contain `KEY=VALUE` patterns) to confirm the file type |
| **Boolean-Blind SQLi Comparison** | Tests TRUE and FALSE conditions and compares response sizes against a baseline to detect blind injection |
| **HTML-Decoded XSS Matching** | Detects reflected XSS even when the server HTML-encodes the payload, reporting encoding context accurately |
| **CSP-Aware XSS Severity** | Reduces XSS severity to "medium" when a strict CSP is present, avoiding overreporting |
| **TRACE Echo Verification** | Confirms the TRACE response actually echoes request content instead of just checking HTTP 200 |
| **Diminishing Risk Score** | Duplicate vulnerability types contribute less to the risk score, preventing inflated scores |
| **Cookie Flag Analysis** | Checks Set-Cookie headers for missing HttpOnly, Secure, and SameSite attributes |
| **Technology Fingerprinting** | Identifies frameworks (WordPress, React, Next.js, etc.) via headers and HTML signatures |

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Runtime | Node.js 18+ (global `fetch`) (server + scanner) |
| Server | Express.js |
| Database | SQLite via better-sqlite3 (WAL mode) |
| Frontend | Vanilla HTML/CSS/JS (SPA) |
| UUID | uuid v4 |
| DOCX Reports | `docx` (pure JS, no native deps) |
| LLM Providers | Ollama (default, local) · OpenAI-compatible endpoints |
| LLM Client | Custom provider abstraction using global `fetch` |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Browser (SPA UI)                              │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐│
│  │  Dashboard  │ │  New Scan  │ │  History   │ │   Scan Detail      ││
│  │  (AI chip)  │ │ (mode, AI) │ │            │ │  (AI panels)       ││
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘│
└──────────────────────┬───────────────────────────────────────────────┘
                       │ REST API (JSON)
┌──────────────────────┴───────────────────────────────────────────────┐
│                      Express Server (server.js)                      │
│  ┌─────────────────┐  ┌──────────────────────┐  ┌──────────────────┐│
│  │  API Routes      │  │  Scan Runner         │  │  Reports         ││
│  │  (CRUD + AI)     │  │  (Background Async)  │  │  MD + DOCX       ││
│  └─────────────────┘  └──────────┬───────────┘  └──────────────────┘│
│                                  │                                   │
│  ┌───────────────────────────────┴───────────────────────────────────┐│
│  │                  Scanner Engine (scanner.js)                     ││
│  │  deterministic checks ─┐                        ┌─ agent/loop.js ││
│  │  AI payload injection ─┤                        │  plan→act→obs  ││
│  │  prompt-injection PI ──┤  mode dispatch         │  tools/policy  ││
│  │  baseline + fingerprint┘  (hybrid/agent)        │  memory        ││
│  └───────────────────────────────────────────────────────────────────┘│
│  ┌───────────────┐  ┌─────────────────────┐  ┌──────────────────────┐│
│  │ SQLite        │  │ llm/ (client, guard,│  │ payloads/ static    ││
│  │ secureprobe.db│  │ redact, generator,…)│  │ + AI payloads table ││
│  └───────────────┘  └─────────────────────┘  └──────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

---

## Scan Pipeline

Each scan follows this pipeline:

1. **Initialization** — Create scan record, begin progress tracking
2. **Baseline Fingerprinting** — Fetch a random nonexistent path to fingerprint soft-404s
3. **Response Time Baseline** — Measure median response time for time-based detection calibration
4. **Technology Fingerprinting** — Identify frameworks and server software
5. **AI Payload Generation** *(hybrid/agent mode)* — model writes endpoint-specific payloads
6. **Security Headers Analysis** — Check 7+ security headers + cookie security flags
7. **CORS Analysis** — Test with malicious origins for reflection or wildcard policies
8. **SQL Injection** — Error-based, time-based (with baseline), and boolean-blind detection
9. **XSS Detection** — Reflected payload matching with HTML-decode awareness and CSP context
10. **Open Redirect** — Server-side (Location header) and client-side (meta refresh/JS) redirect detection
11. **OS Command Injection** — Command-output signatures (`uid=`, passwd) and time-based sleep detection
12. **Path Traversal / LFI** — File-content signatures with soft-404 elimination
13. **SSRF** — Cloud metadata / internal-response markers after URL injection
14. **Discovered API Endpoint Probing** — same-origin API paths mined from the page and JS bundles (error-based SQLi, reflection, POST auth-bypass)
15. **Prompt Injection (target-side)** — Canary instruction-override, prompt-leak, and role-confusion probes over query params and JSON POST bodies (AI-written probes when enabled)
16. **HTTP Method Analysis** — Test all HTTP methods with TRACE echo verification
17. **Sensitive File Discovery** — Content-signature validated file/directory probing
18. **Rate Limit Testing** — 20 rapid requests with success rate verification
19. **Discovered-Surface Fuzzing** — every parameterised link and form found with cheerio is tested only with the vulnerability classes its parameters can carry (GET query or POST body), using fixed + AI payloads
20. **Autonomous Agent** *(hybrid/agent mode)* — bounded plan → act → observe loop
21. **Risk Scoring** — Weighted score with diminishing returns per vulnerability type
22. **AI Enrichment** *(when enabled)* — findings analyzed, executive summary generated

---

## Vulnerability Detection Details

### Security Headers (7+ checks)
- Content-Security-Policy (with `unsafe-inline`/`unsafe-eval`/`*` detection)
- Strict-Transport-Security
- X-Frame-Options (with ALLOWALL detection)
- X-Content-Type-Options
- Referrer-Policy (with `unsafe-url` detection)
- Permissions-Policy
- X-Permitted-Cross-Domain-Policies
- Server banner disclosure
- X-Powered-By disclosure
- Cookie security flags (HttpOnly, Secure, SameSite)

### SQL Injection (3 detection methods)
- **Error-based**: 16+ database error patterns (MySQL, PostgreSQL, MSSQL, SQLite, ODBC, PDO)
- **Time-based**: Calibrated against baseline response time (3x threshold)
- **Boolean-blind**: Compares TRUE/FALSE condition responses against baseline body length

### XSS (encoding-aware)
- Exact (unencoded) reflection detection
- HTML entity-decoded reflection detection
- CSP-aware severity adjustment

### Sensitive Files (signature-validated)
- 18 common paths with content-type signatures
- Soft-404 elimination via baseline comparison
- Special handling for robots.txt (only flags if sensitive paths disclosed)

### OS Command Injection
- Command-output signatures (`uid=0(root) gid=…`, passwd lines, `www-data`)
- Time-based sleep payloads calibrated against baseline response time
- Parameter candidates: `cmd`, `exec`, `command`, `ping`, `host`, `ip`, `file`

### Path Traversal / LFI
- Traversal payloads mapped across candidate parameters (`file`, `path`, `page`, …)
- `/etc/passwd` and Windows `win.ini` content signatures
- Soft-404 / same-hash elimination to reduce false positives

### SSRF
- URL payloads (`127.0.0.1`, `169.254.169.254`, IPv6 loopback) into URL-like parameters
- Cloud metadata markers (`instance-id`, `ami-id`, `iam/security-credentials`, …) confirm server-side fetch

### Prompt Injection (target-side)
- Canary tokens: a unique `VULNIX-CANARY-…` string is injected with an instruction override
- Payload templates use a `{{CANARY}}` placeholder that the harness substitutes per run; a
  response that returns the token *without* echoing the instruction is the detection signal,
  which distinguishes a model following instructions from a page that merely mirrors input
- Prompt-leak probes ask the target LLM to repeat its system prompt
- Role-confusion probes attempt an unrestricted-assistant persona
- Probed over query parameters, JSON POST bodies for chat/completions-style endpoints, and
  same-origin LLM-ish endpoints discovered during recon
- In LLM mode the model writes additional endpoint-tailored probes (schema-validated and
  safety-filtered) alongside the curated set
- Every probe is recorded in `prompt_injection_tests`; confirmed cases are vulnerabilities
- A single endpoint can be tested on demand with `POST /api/prompt-injection/test` (no scan,
  nothing persisted)

---

## AI Layer

### Provider abstraction (`llm/client.js`)
A single `chat(messages, opts)` / `chatJson(messages, opts)` interface supports:

| Provider | Endpoint | Tool calls |
|----------|----------|------------|
| Ollama | `POST /api/tags`, `POST /api/chat` | Native + JSON fallback |
| OpenAI-compatible | `GET /v1/models`, `POST /v1/chat/completions` | Parsed from `function.arguments` |

`chatJson` requests strict JSON and retries once when the model mangles the output.

### Prompt-injection defense (agent self-protection)
- `llm/redact.js` scrubs JWTs, bearer/basic auth, cookies, API keys, private keys, and
  `key=value` assignments before anything leaves the host.
- `llm/guard.js` detects injection indicators (instruction overrides, role hijacks,
  fake system turns, prompt leak requests, markdown-image exfiltration) in untrusted
  target content.
- `llm/guard.js#isolate()` wraps target data in explicit data delimiters and
  neutralizes delimiter-escape attempts.
- Model output is validated (`isSafeOutput`) and payloads are schema-checked,
  capped, and deduped (`validatePayloads`) before the harness ever uses them.
- `agent/policy.js` is the hard boundary: every model-requested action must pass
  scope, protocol, IP, and method checks before `agent/tools.js` executes it.

### Autonomous agent (`agent/loop.js`)
The model selects one tool per turn as JSON; the harness validates, executes,
observes, and feeds the observation back (guarded). Tools: `http_request`,
`crawl`, `fingerprint`, `generate_payloads`, `test_parameter`, `record_finding`,
`finish`. Budgets (steps/requests/seconds) are enforced in `agent/memory.js`, and
every step is persisted to `agent_steps` for the audit trail and report.

---

## Connecting the LLM

Vulnix talks to a **real** model over HTTP — it does not ship a simulated or
canned model response. When no provider is reachable, the AI endpoints return an
error and every scan keeps working in deterministic mode. Enable the AI layer in
three steps.

### 1. Start a provider

| Provider | How to start | Default endpoint |
|----------|--------------|------------------|
| **Ollama** (local, private, recommended) | `ollama serve` then `ollama pull qwen2.5-coder:7b` | `http://localhost:11434` |
| **OpenAI / OpenAI-compatible** (OpenAI, Azure, OpenRouter, Groq, vLLM, LM Studio, LocalAI, …) | obtain a base URL + API key from the provider | `https://api.openai.com` |

### 2. Configure Vulnix

Copy `.env.example` to `.env` (loaded automatically; real environment variables
take precedence), export shell variables, or set them in your process manager.

**Ollama**

```dotenv
LLM_ENABLED=true
LLM_PROVIDER=ollama
OLLAMA_HOST=http://localhost:11434
# LLM_MODEL=          # auto-discovered when unset
```

**OpenAI-compatible**

```dotenv
LLM_ENABLED=true
LLM_PROVIDER=openai
OPENAI_BASE_URL=https://api.openai.com   # no trailing slash
OPENAI_API_KEY=sk-...
LLM_MODEL=gpt-4o-mini
```

The provider is selected by `LLM_PROVIDER`: `openai` uses the
OpenAI-compatible path; any other value (including the default `ollama`) uses the
Ollama path.

### 3. Verify and use

- **UI** — the AI status chip on the *New Scan* page shows
  `AI: <provider> · <model>` when reachable, or `AI unreachable (<provider>)`
  otherwise.
- **API** — `GET /api/ai/status` returns
  `{ enabled, reachable, provider, endpoint, models, model }`.
- **Smoke test** — `POST /api/ai/analyze` with
  `{ "question": "Reply with the word ready" }`.

Once reachable, choose `hybrid` or `agent` as the scan mode (and tick
*I am authorized*), or call `POST /api/ai/payloads` /
`POST /api/prompt-injection/test` with `"useAi": true`.

### Provider calls made by the client

| Action | Ollama | OpenAI-compatible |
|--------|--------|-------------------|
| List models | `GET /api/tags` | `GET /v1/models` |
| Chat | `POST /api/chat` | `POST /v1/chat/completions` |

Auth: Ollama needs none on localhost; the OpenAI-compatible path sends
`Authorization: Bearer $OPENAI_API_KEY` when a key is set.

### Model selection

If `LLM_MODEL` is empty, Vulnix ranks the provider's models
(`llm/models.js`) — code-capable models first, then chat models, with tiny/embed
models deprioritized. Set `LLM_MODEL` to pin an exact model and skip discovery.

### Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `reachable: false`, `models: []` | Provider not running, wrong host/URL, or a firewall. Confirm with `curl http://localhost:11434/api/tags`. |
| `No LLM model available` | Provider reported zero models. `ollama pull <model>` or set `LLM_MODEL`. |
| `OpenAI chat failed (401)` | Missing/invalid `OPENAI_API_KEY`. |
| `... failed (404)` | Wrong `OPENAI_BASE_URL`/`OLLAMA_HOST` (do not include `/v1`; it is appended for you). |
| Requests time out | Raise `LLM_TIMEOUT_MS`; the first call also loads the model into memory. |
| AI mode silently ran deterministic | `LLM_ENABLED` was false or no provider was reachable — the scan logs an *AI Disabled* / provider error event instead of faking output. |

### Configuration reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `LLM_ENABLED` | `false` | Master switch for every AI feature |
| `LLM_PROVIDER` | `ollama` | `ollama` or `openai` |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama base URL |
| `OPENAI_BASE_URL` | `https://api.openai.com` | OpenAI-compatible base URL |
| `OPENAI_API_KEY` | — | API key for cloud/gateway providers |
| `LLM_MODEL` | auto | Pin a model; auto-discovered when unset |
| `LLM_TEMPERATURE` | `0.2` | Sampling temperature |
| `LLM_TIMEOUT_MS` | `60000` | Per-request timeout |
| `LLM_MAX_PAYLOADS` | `12` | Max AI payloads per vulnerability class |
| `LLM_CONCURRENCY` | `2` | Provider concurrency |

> **No mocked output.** Production code only ever returns parsed responses from
> the configured provider. Test doubles (`jest.mock`, a stubbed `global.fetch`)
> exist only under `tests/` and never touch the running tool.

### Scanner configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `SCAN_MAX_REQUESTS` | `400` | Cap on requests a single deterministic scan may issue |
| `SCAN_MAX_SECONDS` | `120` | Wall-clock cap (enforced per request) |
| `SCAN_SKIP_STATIC_INJECTION` | `true` | Skip the injection battery on pages with no dynamic surface |
| `SCAN_RATE_LIMIT_SAMPLES` | `4` | Spaced probes used by the rate-limit check |
| `SCAN_DISCOVERY_SCRIPTS` | `3` | JS bundles mined for API paths |
| `SCAN_DISCOVERY_ENDPOINTS` | `8` | Top candidate API endpoints actually probed |
| `SCAN_DISCOVERY_PROBES` | `4` | Probe requests allowed per API endpoint |
| `SCAN_DISCOVERY_POST` | `true` | Allow the POST auth-bypass probe on login endpoints |
| `SCAN_FUZZ_SURFACES` | `true` | Fuzz every discovered input surface with type-appropriate fixed + AI payloads |
| `SCAN_DISCOVERY_SURFACES` | `12` | Max discovered surfaces fuzzed per scan |
| `SCAN_DISCOVERY_DEPTH` | `1` | Recursive crawl depth (`1` = target page only; `N` adds `N-1` link hops) |
| `SCAN_DISCOVERY_VISITED` | `30` | Max pages visited during recursive crawl |
| `SCAN_DISCOVERY_PROBE_COMMON` | `false` | Probe common paths (e.g. /login, /api) if not linked |
| `SCAN_DISCOVERY_COMMON_PATHS` | `/login,/signin,...` | Comma-separated paths to probe when enabled |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scans` | Start a new scan (`mode`, `useAi`, `authorized`, `options`) |
| GET | `/api/scans` | List scans (paginated) |
| GET | `/api/scans/:id` | Get scan with vulnerabilities and events |
| GET | `/api/scans/:id/status` | Poll scan progress |
| GET | `/api/scans/:id/events` | Get scan event timeline |
| GET | `/api/scans/:id/vulnerabilities` | Get scan vulnerabilities |
| POST | `/api/scans/:id/cancel` | Cancel a running agent scan |
| GET | `/api/scans/:id/report` | Download Markdown report |
| GET | `/api/scans/:id/report.docx` | Download DOCX (Word) report |
| GET | `/api/scans/:id/payloads` | Get mapped payloads for detected vulns |
| GET | `/api/scans/:id/ai-payloads` | AI-generated payloads used in the scan |
| GET | `/api/scans/:id/prompt-injection` | Prompt-injection test results |
| POST | `/api/prompt-injection/test` | On-demand prompt-injection test against an endpoint (no scan; `useAi` lets the model write probes) |
| GET | `/api/scans/:id/agent-trace` | Agent action trace |
| DELETE | `/api/scans/:id` | Delete a scan |
| GET | `/api/stats/summary` | Aggregate statistics |
| GET | `/api/stats/recent-activity` | Recent scans and vulnerabilities |
| GET | `/api/payloads` | Browse the payload database |
| GET | `/api/payloads/stats` | Payload statistics |
| GET | `/api/ai/status` | LLM provider status + models |
| GET | `/api/ai/models` | List provider models |
| POST | `/api/ai/payloads` | Generate custom payloads on demand |
| POST | `/api/ai/analyze` | Guarded ad-hoc assistant query |

---

## Running

```bash
npm install
npm start          # Production
npm run dev        # Development with --watch
```

Open `http://127.0.0.1:5000` in your browser.

AI features are optional — see **Connecting the LLM** above, and `README.md` /
`.env.example` for the full variable list. Without a provider, Vulnix runs in
deterministic mode.

---

## Risk Score Algorithm

The risk score (0–100) uses weighted severity with diminishing returns:

```
For each vulnerability type:
  Sort by severity (worst first)
  For the i-th vulnerability of that type:
    score += weight × (1 / (1 + i × 0.6))

Weights: critical=40, high=25, medium=10, low=3, info=1
```

This prevents inflated scores when a site has many of the same type of finding (e.g., 10 missing headers won't score the same as 10 different critical vulnerabilities).

---

## ⚠️ Disclaimer

**Only scan URLs you own or have explicit, written permission to test.** Unauthorized scanning may violate laws and regulations.

*Vulnix v3.0 — Built for accurate, authorized, actionable security analysis.*
