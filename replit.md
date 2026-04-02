# Workspace

## Overview

SecureProbe — a full-stack security analysis platform (mini bug bounty automation tool). Users paste a URL, the app simulates real-world attack scenarios, detects vulnerabilities, and generates a detailed visual report.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)
- **Frontend**: React + Vite + Tailwind CSS + shadcn/ui
- **State management**: TanStack React Query (via Orval-generated hooks)
- **Routing**: wouter

## Security Scanning Features

The scanning engine (`artifacts/api-server/src/lib/scanner.ts`) performs:
1. **Security Headers Analysis** — checks for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
2. **CORS Misconfiguration Detection** — tests wildcard origins and origin reflection with credentials
3. **SQL Injection Testing** — tests common payloads, looks for error patterns and 500 responses
4. **XSS Testing** — tests reflected XSS payloads against query parameters
5. **Open Redirect Testing** — checks redirect parameters for unvalidated redirects
6. **HTTP Method Analysis** — tests all HTTP methods including dangerous TRACE
7. **Rate Limiting Detection** — sends rapid requests to check if rate limiting is enforced

Each vulnerability includes an AI-written plain-English explanation, CVSS score, and remediation advice.

## Structure

```text
artifacts-monorepo/
├── artifacts/
│   ├── api-server/         # Express API server
│   │   └── src/
│   │       ├── lib/scanner.ts  # Security scanning engine
│   │       └── routes/scans.ts # All scan API endpoints
│   └── security-scanner/   # React frontend (SecureProbe UI)
│       └── src/pages/      # Dashboard, Scan Detail, Scan History
├── lib/
│   ├── api-spec/           # OpenAPI spec + Orval codegen config
│   ├── api-client-react/   # Generated React Query hooks
│   ├── api-zod/            # Generated Zod schemas from OpenAPI
│   └── db/
│       └── src/schema/scans.ts  # scans, vulnerabilities, scan_events tables
```

## Database Schema

- `scans` — scan records with status, risk score, vulnerability counts, progress
- `vulnerabilities` — individual vulnerabilities with type, severity, payload, evidence, AI explanation
- `scan_events` — timeline events showing the attack simulation step by step

## API Endpoints

- `POST /api/scans` — create and start a scan
- `GET /api/scans` — list all scans
- `GET /api/scans/:id` — get scan detail with vulns and events
- `DELETE /api/scans/:id` — delete a scan
- `GET /api/scans/:id/status` — poll scan progress (used for live updates)
- `GET /api/scans/:id/events` — get timeline events
- `GET /api/scans/:id/vulnerabilities` — get vulnerabilities
- `GET /api/stats/summary` — aggregate statistics
- `GET /api/stats/recent-activity` — recent scans and vulns

## TypeScript & Composite Projects

Every package extends `tsconfig.base.json` which sets `composite: true`. The root `tsconfig.json` lists all packages as project references.

- Always typecheck from the root: `pnpm run typecheck`
- Run codegen after OpenAPI changes: `pnpm --filter @workspace/api-spec run codegen`
- Push DB schema: `pnpm --filter @workspace/db run push`

## Important Notes

- The scanning engine runs asynchronously in the background after scan creation
- The frontend polls `/api/scans/:id/status` every 2 seconds while a scan is running
- All vulnerability explanations are pre-written expert descriptions (no external AI API required)
- Scanning is passive/safe — it only sends HTTP requests without exploiting vulnerabilities
- Ethical disclaimer: Only scan URLs you own or have explicit permission to test
