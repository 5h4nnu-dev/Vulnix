# 🛡️ Vulnix v2.1 — Documentation

**Automated Web Security Vulnerability Scanner with Accurate, Low-False-Positive Results**

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
| Runtime | Node.js (server + scanner) |
| Server | Express.js |
| Database | SQLite via better-sqlite3 (WAL mode) |
| Frontend | Vanilla HTML/CSS/JS (SPA) |
| UUID | uuid v4 |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Browser (SPA UI)                              │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐│
│  │  Dashboard  │ │  New Scan  │ │  History   │ │   Scan Detail      ││
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘│
└──────────────────────┬───────────────────────────────────────────────┘
                       │ REST API (JSON)
┌──────────────────────┴───────────────────────────────────────────────┐
│                      Express Server (server.js)                      │
│  ┌─────────────────┐  ┌──────────────────────┐  ┌──────────────────┐│
│  │  API Routes      │  │  Scan Runner         │  │  Report Generator││
│  │  (CRUD + Stats)  │  │  (Background Async)  │  │  (Markdown)      ││
│  └─────────────────┘  └──────────┬───────────┘  └──────────────────┘│
│                                  │                                   │
│  ┌───────────────────────────────┴───────────────────────────────────┐│
│  │                   Scanner Engine (scanner.js)                     ││
│  │  ┌──────────────┐  ┌──────────┐  ┌───────────────┐              ││
│  │  │ Baseline     │  │ Security │  │ Vulnerability  │              ││
│  │  │ Fingerprint  │  │ Checks   │  │ Recording      │              ││
│  │  └──────────────┘  └──────────┘  └───────────────┘              ││
│  └───────────────────────────────────────────────────────────────────┘│
│                                                                      │
│  ┌───────────────────┐  ┌──────────────────────────────────────────┐ │
│  │ SQLite Database   │  │ Payload Engine (payloads/)               │ │
│  │ (secureprobe.db)  │  │  SQL · XSS · CORS · SSRF · CSRF · etc. │ │
│  └───────────────────┘  └──────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Scan Pipeline

Each scan follows this pipeline:

1. **Initialization** — Create scan record, begin progress tracking
2. **Baseline Fingerprinting** — Fetch a random nonexistent path to fingerprint soft-404s
3. **Response Time Baseline** — Measure median response time for time-based SQLi calibration
4. **Technology Fingerprinting** — Identify frameworks and server software
5. **Security Headers Analysis** — Check 7+ security headers + cookie security flags
6. **CORS Analysis** — Test with malicious origins for reflection or wildcard policies
7. **SQL Injection** — Error-based, time-based (with baseline), and boolean-blind detection
8. **XSS Detection** — Reflected payload matching with HTML-decode awareness and CSP context
9. **Open Redirect** — Server-side (Location header) and client-side (meta refresh/JS) redirect detection
10. **HTTP Method Analysis** — Test all HTTP methods with TRACE echo verification
11. **Sensitive File Discovery** — Content-signature validated file/directory probing
12. **Rate Limit Testing** — 20 rapid requests with success rate verification
13. **Risk Scoring** — Weighted score with diminishing returns per vulnerability type

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

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scans` | Start a new scan |
| GET | `/api/scans` | List scans (paginated) |
| GET | `/api/scans/:id` | Get scan with vulnerabilities and events |
| GET | `/api/scans/:id/status` | Poll scan progress |
| GET | `/api/scans/:id/events` | Get scan event timeline |
| GET | `/api/scans/:id/vulnerabilities` | Get scan vulnerabilities |
| GET | `/api/scans/:id/report` | Download Markdown report |
| GET | `/api/scans/:id/payloads` | Get mapped payloads for detected vulns |
| DELETE | `/api/scans/:id` | Delete a scan |
| GET | `/api/stats/summary` | Aggregate statistics |
| GET | `/api/stats/recent-activity` | Recent scans and vulnerabilities |
| GET | `/api/payloads` | Browse the payload database |
| GET | `/api/payloads/stats` | Payload statistics |

---

## Running

```bash
npm install
npm start          # Production
npm run dev        # Development with --watch
```

Open `http://localhost:3000` in your browser.

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

*SecureProbe v2.1 — Built for accurate, actionable security analysis.*
