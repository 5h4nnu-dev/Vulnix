# SecureProbe v2.0 — Complete Project Documentation

---

## Table of Contents

1. [Overview](#1-overview)
2. [Tech Stack](#2-tech-stack)
3. [Architecture](#3-architecture)
4. [How It Works](#4-how-it-works)
5. [API Reference](#5-api-reference)
6. [Security Checks Explained](#6-security-checks-explained)
7. [Database Schema](#7-database-schema)
8. [Frontend Design](#8-frontend-design)
9. [Report Generation](#9-report-generation)
10. [Development Guide](#10-development-guide)
11. [Ethical Disclaimer](#11-ethical-disclaimer)

---

## 1. Overview

**SecureProbe** is a full-stack web application that automates security vulnerability scanning of websites. Users paste a URL, the app simulates real-world attack scenarios, detects vulnerabilities, and generates a detailed visual report — all from a single page.

### Key Features

- **7 vulnerability checks**: Security headers, CORS, SQL injection, XSS, open redirects, HTTP methods, rate limiting
- **Real-time progress**: Live scan progress with event feed
- **Detailed payloads & exploits**: Every vulnerability includes the exact payload used, evidence found, and a practical "Possible Exploit" explanation.
- **Report export**: Downloadable Markdown reports with full vulnerability documentation
- **Zero config**: SQLite database (no external DB), single `npm start` command
- **3 dependencies**: Express, better-sqlite3, uuid — nothing else

---

## 2. Tech Stack

| Layer     | Technology        | Why                                                  |
|-----------|-------------------|------------------------------------------------------|
| Runtime   | **Node.js 18+**   | Native `fetch()` support, `--watch` mode for dev     |
| Server    | **Express 4**     | Industry standard, minimal, well-documented          |
| Database  | **SQLite** (better-sqlite3) | Zero-config, file-based, no external server |
| Frontend  | **Vanilla HTML/CSS/JS** | No build step, no bundler, instant iteration   |
| Fonts     | **Inter + JetBrains Mono** | Modern typography from Google Fonts          |

### Why These Choices?

- **No TypeScript compilation** — The original project required `pnpm`, TypeScript, esbuild, Drizzle ORM codegen, Orval API client generation, and React. This version strips all of that while keeping the same scanning logic.
- **No PostgreSQL** — SQLite stores everything in a single `secureprobe.db` file. No connection strings, no setup.
- **No monorepo** — One flat directory. 6 files total.
- **No build step** — Edit any file and reload. Use `npm run dev` for auto-restart.

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────────┐
│                      Browser (Client)                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │   public/index.html + style.css + app.js             │  │
│  │   - Dashboard with stats                             │  │
│  │   - Scan form with configurable options              │  │
│  │   - Live progress polling (every 1.5s)               │  │
│  │   - Scan detail with expandable vulnerability cards  │  │
│  │   - Report download button                           │  │
│  └──────────────────────────┬───────────────────────────┘  │
│                             │ HTTP (fetch API)             │
└─────────────────────────────┼──────────────────────────────┘
                              │
┌─────────────────────────────┼──────────────────────────────┐
│                     server.js (Express)                    │
│  ┌──────────────────────────┴───────────────────────────┐  │
│  │   Static file serving: /public                       │  │
│  │   REST API: /api/scans, /api/stats, /api/scans/:id   │  │
│  │   Report generator: /api/scans/:id/report            │  │
│  └──────────────────────────┬───────────────────────────┘  │
│                             │                              │
│  ┌──────────────────────────┴───────────────────────────┐  │
│  │   scanner.js (Background Scan Engine)                │  │
│  │   - Runs asynchronously after scan creation          │  │
│  │   - 7 independent check modules                      │  │
│  │   - Writes events, vulns, progress to DB             │  │
│  └──────────────────────────┬───────────────────────────┘  │
│                             │                              │
│  ┌──────────────────────────┴───────────────────────────┐  │
│  │   database.js (SQLite via better-sqlite3)            │  │
│  │   - WAL mode for concurrent read                     │  │
│  │   - Pre-compiled prepared statements                 │  │
│  │   - 3 tables: scans, vulnerabilities, scan_events    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│              secureprobe.db (SQLite file)                  │
└────────────────────────────────────────────────────────────┘
```

### Request Flow

1. **User pastes URL** → Frontend sends `POST /api/scans`
2. **Server creates scan record** in SQLite, returns immediately
3. **Scanner runs in background** — each check module runs sequentially
4. **Frontend polls** `GET /api/scans/:id/status` every 1.5 seconds
5. **Scan completes** → Risk score calculated, frontend navigates to detail view
6. **User downloads report** → Server generates Markdown from scan data

---

## 4. How It Works

### Scan Lifecycle

```
[pending] → [running] → [completed/failed]
    │            │              │
    │            │              └── Risk score computed
    │            └── Each check module runs sequentially
    └── Scan record created in DB
```

### Progress Updates

The scanner writes progress to the database after each check module completes:

| Stage               | Progress |
|---------------------|----------|
| Initialization      | 10%      |
| Security Headers    | 25%      |
| CORS Analysis       | 40%      |
| SQL Injection       | 55%      |
| XSS Detection       | 68%      |
| Open Redirect       | 78%      |
| HTTP Methods        | 88%      |
| Rate Limiting       | 95%      |
| Finalization        | 100%     |

### Risk Score Algorithm

Each vulnerability severity contributes to a 0–100 risk score:

| Severity | Points |
|----------|--------|
| Critical | +40    |
| High     | +25    |
| Medium   | +10    |
| Low      | +3     |
| Info     | +1     |

Score is capped at 100. Risk levels: **Critical** (80+), **High** (60+), **Medium** (30+), **Low** (10+), **Info** (<10).

---

## 5. API Reference

All endpoints are prefixed with `/api`.

### Scans

| Method   | Endpoint                     | Description                              |
|----------|------------------------------|------------------------------------------|
| `POST`   | `/scans`                     | Create and start a new scan              |
| `GET`    | `/scans`                     | List all scans (paginated)               |
| `GET`    | `/scans/:id`                 | Get scan + vulnerabilities + events      |
| `DELETE` | `/scans/:id`                 | Delete a scan and all related data       |
| `GET`    | `/scans/:id/status`          | Poll scan progress                       |
| `GET`    | `/scans/:id/events`          | Get timeline events                      |
| `GET`    | `/scans/:id/vulnerabilities` | Get vulnerabilities only                 |
| `GET`    | `/scans/:id/report`          | Download Markdown report                 |

### Stats

| Method | Endpoint                  | Description               |
|--------|---------------------------|---------------------------|
| `GET`  | `/stats/summary`          | Aggregate scan statistics |
| `GET`  | `/stats/recent-activity`  | Recent scans and vulns    |

### POST `/scans` Body

```json
{
  "url": "https://example.com",
  "options": {
    "checkHeaders": true,
    "checkCors": true,
    "checkSqlInjection": true,
    "checkXss": true,
    "checkOpenRedirect": true,
    "checkHttpMethods": true,
    "checkRateLimit": true
  }
}
```

---

## 6. Security Checks Explained

### 6.1 Security Headers Analysis

Checks for the presence of critical HTTP security headers:

| Header                    | Severity | Why It Matters                         |
|---------------------------|----------|----------------------------------------|
| Content-Security-Policy   | High     | Prevents XSS by restricting resource loading |
| Strict-Transport-Security | Medium   | Prevents SSL stripping / MITM attacks  |
| X-Frame-Options           | Medium   | Prevents clickjacking                  |
| X-Content-Type-Options    | Low      | Prevents MIME-type sniffing            |
| Referrer-Policy           | Low      | Prevents sensitive URL leakage         |
| Permissions-Policy        | Info     | Restricts browser API access           |

### 6.2 CORS Misconfiguration

Tests if the server reflects arbitrary `Origin` headers:

- Sends requests with `Origin: https://evil.com`, `https://attacker.com`, and `null`
- Checks if `Access-Control-Allow-Origin` reflects the malicious origin
- Escalates severity if `Access-Control-Allow-Credentials: true` is also set

### 6.3 SQL Injection

Tests for SQL injection via query parameters using payloads:

```
' OR '1'='1
' OR 1=1--
'; DROP TABLE users--
```

Looks for database error patterns in responses (MySQL, PostgreSQL, SQLite, Oracle, MSSQL).

### 6.4 Cross-Site Scripting (XSS)

Tests for reflected XSS by injecting payloads into query parameters:

```html
<script>alert('xss')</script>
"><img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

Checks if payload appears unescaped in the response AND no CSP header is present.

### 6.5 Open Redirect

Tests redirect parameters (`redirect`, `next`, `url`) with malicious URLs:

```
//evil.com
https://evil.com
```

Checks if the `Location` header in 3xx responses points to the attacker-controlled domain.

### 6.6 HTTP Method Analysis

Tests all HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE):

- Reports if **TRACE** is enabled (enables Cross-Site Tracing attacks)
- Logs which methods the server accepts

### 6.7 Rate Limiting

Sends 15 rapid consecutive requests and checks if the server responds with:

- **HTTP 429** (Too Many Requests)
- **Retry-After** header

If neither appears, reports missing rate limiting.

---

## 7. Database Schema

Three tables in SQLite (`secureprobe.db`):

### `scans`

| Column              | Type    | Description                        |
|---------------------|---------|------------------------------------|
| id                  | TEXT PK | UUID                               |
| url                 | TEXT    | Target URL                         |
| status              | TEXT    | pending/running/completed/failed   |
| risk_score          | REAL    | 0-100 computed risk score          |
| risk_level          | TEXT    | critical/high/medium/low/info      |
| vulnerability_count | INTEGER | Total vulnerabilities found        |
| critical_count      | INTEGER | Count by severity                  |
| high_count          | INTEGER | Count by severity                  |
| medium_count        | INTEGER | Count by severity                  |
| low_count           | INTEGER | Count by severity                  |
| progress            | INTEGER | 0-100 scan progress                |
| current_stage       | TEXT    | Current check being run            |
| stages_completed    | TEXT    | JSON array of completed stages     |
| options             | TEXT    | JSON of scan options               |
| created_at          | TEXT    | Timestamp                          |
| completed_at        | TEXT    | Timestamp                          |

### `vulnerabilities`

| Column            | Type    | Description                          |
|-------------------|---------|--------------------------------------|
| id                | TEXT PK | UUID                                 |
| scan_id           | TEXT FK | References scans(id) CASCADE DELETE  |
| type              | TEXT    | e.g. sql_injection, xss, cors_misc   |
| severity          | TEXT    | critical/high/medium/low/info        |
| title             | TEXT    | Human-readable title                 |
| description       | TEXT    | What was found                       |
| affected_endpoint | TEXT    | The URL tested                       |
| **payload**       | TEXT    | **The exact payload used**           |
| **evidence**      | TEXT    | **What confirmed the vulnerability** |
| ai_explanation    | TEXT    | Detailed plain-English analysis      |
| **exploitation**  | TEXT    | **How an attacker might exploit it** |
| remediation       | TEXT    | How to fix it                        |
| cvss_score        | REAL    | CVSS v3 score                        |
| discovered_at     | TEXT    | Timestamp                            |

### `scan_events`

Timeline of actions taken during a scan (requests sent, responses received, findings).

| Column           | Type    | Description                |
|------------------|---------|----------------------------|
| id               | TEXT PK | UUID                       |
| scan_id          | TEXT FK | References scans(id)       |
| stage            | TEXT    | Which check module         |
| event_type       | TEXT    | request/response/finding/error/info |
| title            | TEXT    | Short event title          |
| description      | TEXT    | Event details              |
| payload          | TEXT    | Payload used (if any)      |
| request_headers  | TEXT    | Request headers sent       |
| response_status  | INTEGER | HTTP status received       |
| response_headers | TEXT    | Response headers           |
| response_body    | TEXT    | Response body (truncated)  |
| severity         | TEXT    | Severity if finding        |
| timestamp        | TEXT    | When it happened           |

---

## 8. Frontend Design

The frontend is a **single-page application** built entirely with vanilla HTML, CSS, and JavaScript (no React, no build tools).

### Pages

| Page         | Purpose                                          |
|--------------|--------------------------------------------------|
| Dashboard    | Stats overview, recent scans, vulnerability breakdown |
| New Scan     | URL input, scan options toggles, live progress   |
| Scan History | All past scans with status and risk indicators   |
| Scan Detail  | Full results with expandable vulnerability cards |

### Design Decisions

- **Dark cybersecurity theme** — Dark backgrounds with cyan/purple neon accents
- **Glassmorphism sidebar** — Blurred background, subtle border
- **Animated grid background** — Subtle grid pattern with floating glow orbs
- **JetBrains Mono** for code/URLs — Monospace font for technical data
- **Inter** for UI text — Clean, modern sans-serif
- **Expandable vulnerability cards** — Click to reveal payload, evidence, analysis, possible exploit steps, and remediation
- **Severity color system** — Red (critical), orange (high), yellow (medium), blue (low), gray (info)
- **Responsive layout** — Sidebar collapses on mobile

---

## 9. Report Generation

The `/api/scans/:id/report` endpoint generates a **downloadable Markdown file** containing:

1. **Header** — Target URL, scan ID, dates
2. **Risk Summary Table** — Score, level, counts by severity
3. **Vulnerability List** — For each vulnerability:
   - Title with severity emoji
   - Severity, type, CVSS score, affected endpoint
   - **Payload used** (in code block)
   - Description
   - **Evidence** (in code block)
   - Detailed analysis
   - **Possible exploit** steps
   - Remediation steps
4. **Scan Timeline** — Table of all events with timestamps

Reports are served as `.md` files with `Content-Disposition: attachment` for automatic download.

---

## 10. Development Guide

### Prerequisites

- Node.js 18+ (for native `fetch()`)
- npm

### Getting Started

```bash
git clone <repo-url>
cd Secure-Data-Vault
npm install
npm run dev    # auto-restart on file changes
```

### File Responsibilities

| File          | What to edit when…                              |
|---------------|--------------------------------------------------|
| `scanner.js`  | Adding new vulnerability checks                 |
| `server.js`   | Adding new API endpoints                        |
| `database.js` | Changing the database schema                    |
| `public/app.js` | Adding new UI features                       |
| `public/style.css` | Changing the design                        |
| `public/index.html` | Adding new page sections                  |

### Adding a New Security Check

1. **Write the check function** in `scanner.js`:
   ```js
   async function checkMyNewThing(scanId, url) {
     // Use addEvent() to log what you're doing
     // Use addVuln() to report findings
     // Always include payload and evidence
   }
   ```

2. **Add the option** to the scan options in `scanner.js` (`runScan` function) and `server.js` (default options)

3. **Add the UI toggle** in `public/index.html` (inside `.options-grid`)

4. **Wire it up** in `public/app.js` (`startScan` function)

### Resetting the Database

Delete `secureprobe.db` and restart the server. The schema is recreated automatically.

---

## 11. Ethical Disclaimer

⚠️ **Only scan URLs that you own or have explicit written permission to test.**

SecureProbe sends real HTTP requests including:
- SQL injection payloads in query parameters
- XSS payloads in query parameters
- Rapid sequential requests (rate limit testing)
- Various HTTP methods (including TRACE)

While the scanner is **passive** (it does not exploit vulnerabilities), sending these requests to systems you don't own may violate laws and terms of service.

**You are solely responsible for ensuring you have authorization before scanning any target.**

---

*SecureProbe v2.0 — Built for simplicity, security, and speed.*
