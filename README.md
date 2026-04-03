# SecureProbe v2.0

> Automated web security vulnerability scanner with detailed reports.

## Quick Start

```bash
npm install
npm start
```

Then open **http://localhost:3000** in your browser.

### Development Mode (auto-restart on changes)

```bash
npm run dev
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT`   | `3000`  | Server port |

No external database needed — SQLite runs locally, data stored in `secureprobe.db`.

## Project Structure

```
Secure-Data-Vault/
├── server.js      # Express server + API routes + report generator
├── scanner.js     # Security scanning engine (7 check types)
├── database.js    # SQLite schema + prepared statements
├── public/
│   ├── index.html # Single-page app shell
│   ├── style.css  # Dark cybersecurity theme
│   └── app.js     # Frontend logic
├── package.json   # 3 dependencies only
└── DOCUMENTATION.md
```

## Features

- 🛡️ 7 vulnerability check types (headers, CORS, SQLi, XSS, redirects, HTTP methods, rate limiting)
- 📊 Real-time scan progress with live event feed
- 📋 Downloadable Markdown vulnerability reports
- 🎯 Every vulnerability includes its payload, evidence, and a "Possible Exploit" explanation
- 💾 Persistent SQLite storage
- 🎨 Premium dark-mode UI

## License

MIT
