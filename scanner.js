const { stmts } = require('./database');
const { v4: uuid } = require('uuid');

// ── Payloads ────────────────────────────────────────────────────────────────

const SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "1' AND SLEEP(5)--",
    "' UNION SELECT NULL,NULL--",
];

const XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
];

const OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//google.com",
    "/\\evil.com",
];

// ── Helpers ─────────────────────────────────────────────────────────────────

function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
}

async function fetchSafe(url, opts = {}, timeoutMs = 8000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const resp = await fetch(url, {
            redirect: 'follow', // Default to follow
            ...opts,
            signal: controller.signal
        });
        clearTimeout(timer);
        return resp;
    } catch {
        clearTimeout(timer);
        return null;
    }
}

function headersToObj(headers) {
    const obj = {};
    headers.forEach((v, k) => { obj[k] = v; });
    return obj;
}

function headersToString(headers) {
    return JSON.stringify(headersToObj(headers), null, 2);
}

// ── Event & Vuln helpers ────────────────────────────────────────────────────

function addEvent(scanId, stage, eventType, title, description, extras = {}) {
    stmts.insertEvent.run({
        id: uuid(),
        scan_id: scanId,
        stage,
        event_type: eventType,
        title,
        description,
        payload: extras.payload ?? null,
        request_headers: extras.requestHeaders ?? null,
        response_status: extras.responseStatus ?? null,
        response_headers: extras.responseHeaders ?? null,
        response_body: extras.responseBody ?? null,
        severity: extras.severity ?? null,
    });
}

function addVuln(scanId, vuln) {
    stmts.insertVuln.run({
        id: uuid(),
        scan_id: scanId,
        type: vuln.type,
        severity: vuln.severity,
        title: vuln.title,
        description: vuln.description,
        affected_endpoint: vuln.affectedEndpoint,
        payload: vuln.payload ?? null,
        evidence: vuln.evidence ?? null,
        ai_explanation: vuln.aiExplanation ?? null,
        exploitation: vuln.exploitation ?? null,
        remediation: vuln.remediation,
        cvss_score: vuln.cvssScore ?? null,
    });
}

function updateProgress(scanId, progress, currentStage, stagesCompleted) {
    stmts.updateScanProgress.run({
        id: scanId,
        progress,
        current_stage: currentStage,
        stages_completed: JSON.stringify(stagesCompleted),
    });
}

// ── Security Checks ─────────────────────────────────────────────────────────

async function checkSecurityHeaders(scanId, url) {
    addEvent(scanId, 'headers_analysis', 'request', 'Fetching HTTP Headers',
        `Sending GET request to ${url} to inspect response headers`,
        { requestHeaders: JSON.stringify({ 'User-Agent': 'SecureProbe/2.0' }, null, 2) });

    const resp = await fetchSafe(url, { method: 'GET', headers: { 'User-Agent': 'SecureProbe/2.0' } });
    if (!resp) {
        addEvent(scanId, 'headers_analysis', 'error', 'Connection Failed', 'Could not connect to the target URL', { severity: 'info' });
        return;
    }

    const rHeaders = headersToObj(resp.headers);
    const rHeadersStr = JSON.stringify(rHeaders, null, 2);
    addEvent(scanId, 'headers_analysis', 'response', 'Headers Received',
        `Received HTTP ${resp.status} response`, { responseStatus: resp.status, responseHeaders: rHeadersStr });

    const checks = [
        {
            name: 'Content-Security-Policy', header: 'content-security-policy',
            severity: 'high', cvss: 6.1,
            remediation: "Add a Content-Security-Policy header. Example: Content-Security-Policy: default-src 'self'",
            aiExplanation: "The Content-Security-Policy (CSP) header is missing or poorly configured. CSP is a critical defense against XSS by controlling what resources can load.",
            exploitation: "Attackers can perform XSS attacks if they can inject scripts; without CSP, the browser will execute them unconditionally.",
            badValues: [/unsafe-inline/i, /unsafe-eval/i, /\*/]
        },
        {
            name: 'Strict-Transport-Security', header: 'strict-transport-security',
            severity: 'medium', cvss: 4.3,
            remediation: 'Enable HTTPS and add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            aiExplanation: "The HSTS header is missing, allowing for protocol downgrade attacks (SSL stripping).",
            exploitation: "An attacker on the same network can intercept traffic and perform SSL stripping, downgrading the connection to HTTP.",
        },
        {
            name: 'X-Frame-Options', header: 'x-frame-options',
            severity: 'medium', cvss: 4.3,
            remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN',
            aiExplanation: "Missing X-Frame-Options makes the site vulnerable to clickjacking.",
            exploitation: "Attackers can embed the site in an iframe and trick users into clicking buttons they didn't intend to, known as Clickjacking.",
            badValues: [/ALLOWALL/i]
        },
        {
            name: 'X-Content-Type-Options', header: 'x-content-type-options',
            severity: 'low', cvss: 3.1,
            remediation: 'Add X-Content-Type-Options: nosniff',
            aiExplanation: "Missing nosniff allows browsers to guess MIME types, which can lead to content injection vulnerabilities.",
            exploitation: "Attackers can upload a file with an innocent extension (e.g., image.jpg) that contains HTML/JS, and the browser might execute it.",
        },
    ];

    for (const c of checks) {
        const val = resp.headers.get(c.header);
        if (!val) {
            addVuln(scanId, {
                type: 'missing_security_header', severity: c.severity,
                title: `Missing ${c.name} Header`,
                description: `The ${c.name} header is not present.`,
                affectedEndpoint: url,
                evidence: `Response did not include ${c.name} header.`,
                aiExplanation: c.aiExplanation, exploitation: c.exploitation, remediation: c.remediation, cvssScore: c.cvss,
            });
        } else if (c.badValues && c.badValues.some(p => p.test(val))) {
            addVuln(scanId, {
                type: 'weak_security_header', severity: 'low',
                title: `Weak ${c.name} Configuration`,
                description: `The ${c.name} header value "${val}" is considered weak.`,
                affectedEndpoint: url,
                evidence: `Header ${c.name}: ${val}`,
                aiExplanation: `A weak ${c.name} configuration may still allow certain classes of attacks despite the header being present.`,
                exploitation: c.exploitation,
                remediation: c.remediation, cvssScore: 3.0,
            });
        }
    }

    // Check for Information Disclosure in Server header
    const server = resp.headers.get('server');
    if (server && (/\d/.test(server) || server.toLowerCase().includes('ubuntu') || server.toLowerCase().includes('apache') || server.toLowerCase().includes('nginx'))) {
        addVuln(scanId, {
            type: 'info_disclosure', severity: 'low',
            title: 'Detailed Server Banner Detected',
            description: `The Server header "${server}" reveals software version information.`,
            affectedEndpoint: url,
            evidence: `Server: ${server}`,
            aiExplanation: "Revealing specific server versions helps attackers find known CVEs for your stack.",
            exploitation: "Attackers use the banner to search Exploit-DB or similar databases for known CVEs affecting the exact server version, simplifying their exploitation attempts.",
            remediation: 'Configure your web server to suppress the Server banner and version info.',
            cvssScore: 2.1,
        });
    }
}

async function checkCors(scanId, url) {
    const origins = ['https://evil.com', 'https://attacker.com', 'null'];

    for (const origin of origins) {
        addEvent(scanId, 'cors_analysis', 'request', 'Testing CORS with malicious origin',
            `Sending request with Origin: ${origin}`,
            { requestHeaders: JSON.stringify({ Origin: origin }, null, 2), payload: origin });

        const resp = await fetchSafe(url, { method: 'GET', headers: { Origin: origin, 'User-Agent': 'SecureProbe/2.0' } });
        if (!resp) continue;

        const acao = resp.headers.get('access-control-allow-origin');
        const acac = resp.headers.get('access-control-allow-credentials');
        const rHeaders = headersToString(resp.headers);

        addEvent(scanId, 'cors_analysis', 'response', 'CORS Response',
            `Access-Control-Allow-Origin: ${acao ?? 'not set'}`,
            { responseStatus: resp.status, responseHeaders: rHeaders });

        if (acao === '*') {
            addVuln(scanId, {
                type: 'cors_misconfiguration', severity: 'medium',
                title: 'Permissive CORS Policy (Wildcard Origin)',
                description: 'The server responds with Access-Control-Allow-Origin: * allowing any origin to read the response.',
                affectedEndpoint: url,
                payload: `Origin: ${origin}`,
                evidence: `Response header: Access-Control-Allow-Origin: *`,
                aiExplanation: "A wildcard CORS policy means any website can make cross-origin requests and read responses. If the endpoint returns sensitive data, a malicious site can fetch it on behalf of a logged-in victim.",
                exploitation: "An attacker can create a malicious page that makes an AJAX request to this endpoint and reads the sensitive data returned, then exfiltrates it.",
                remediation: 'Replace the wildcard with a specific allowlist of trusted origins.',
                cvssScore: 5.3,
            });
            break;
        } else if (acao === origin) {
            const severity = acac === 'true' ? 'high' : 'medium';
            addEvent(scanId, 'cors_analysis', 'finding', 'CORS Reflects Origin',
                `Server reflects arbitrary origin: ${origin}`, { severity });
            addVuln(scanId, {
                type: 'cors_misconfiguration', severity,
                title: 'CORS Origin Reflection Vulnerability',
                description: `The server reflects arbitrary origins in ACAO${acac === 'true' ? ' with credentials allowed' : ''}.`,
                affectedEndpoint: url,
                payload: `Origin: ${origin}`,
                evidence: `Request Origin: ${origin} → Response ACAO: ${acao}${acac === 'true' ? ' + ACAC: true' : ''}`,
                aiExplanation: acac === 'true'
                    ? "Critical: The server reflects the Origin AND sets credentials: true. Any malicious website can make authenticated requests on behalf of a user and read sensitive response data."
                    : "The server reflects arbitrary origins, allowing any website to read cross-origin responses from unauthenticated endpoints.",
                exploitation: "An attacker can trick an authenticated victim into visiting a malicious site, which then makes authenticated requests to the API and reads sensitive data.",
                remediation: 'Implement a strict CORS allowlist. Never dynamically reflect arbitrary origins.',
                cvssScore: acac === 'true' ? 8.1 : 5.4,
            });
            break;
        }
    }
}

async function checkSqlInjection(scanId, url) {
    const testUrl = new URL(url);
    const params = Array.from(testUrl.searchParams.keys());
    const candidates = params.length > 0 ? params : ['id', 'search', 'query', 'p', 'view'];

    for (const payload of SQL_PAYLOADS) {
        for (const param of candidates) {
            const target = new URL(url);
            target.searchParams.set(param, payload);
            const targetStr = target.toString();

            addEvent(scanId, 'sql_injection', 'request', `Testing ${param}`, `Testing payload: ${payload}`, { payload });

            const start = Date.now();
            const resp = await fetchSafe(targetStr, { headers: { 'User-Agent': 'SecureProbe/2.0' } });
            const duration = Date.now() - start;
            if (!resp) continue;

            let body = '';
            try { body = await resp.text(); } catch { }

            addEvent(scanId, 'sql_injection', 'response', 'Response Received',
                `HTTP ${resp.status} — ${body.length} bytes (Duration: ${duration}ms)`,
                { responseStatus: resp.status, responseBody: body.slice(0, 500) });

            const errorPatterns = [
                /sql syntax/i, /mysql_fetch/i, /ora-\d{5}/i, /pg_query/i,
                /sqlite_/i, /syntax error/i, /unclosed quotation/i,
                /quoted string not properly terminated/i, /microsoft ole db/i,
                /PostgreSQL.*ERROR/i, /MariaDB.*syntax/i, /ODBC Driver/i,
            ];

            if (errorPatterns.some((p) => p.test(body))) {
                addVuln(scanId, {
                    type: 'sql_injection', severity: 'critical',
                    title: 'Error-Based SQL Injection Detected',
                    description: `The payload "${payload}" on parameter "${param}" triggered a database error.`,
                    affectedEndpoint: targetStr,
                    payload,
                    evidence: `Error pattern found in response: ${body.match(errorPatterns.find(p => p.test(body)))?.[0]}`,
                    aiExplanation: "Error-based SQL injection confirms that user input is directly concatenated into SQL queries. An attacker can extract database structure, tables, and sensitive data like credentials.",
                    exploitation: "Attackers can use tools like sqlmap or crafted UNION SELECT payloads to read arbitrary database tables, update records, or bypass authentication.",
                    remediation: 'Use parameterized queries/prepared statements. Validate all user input. Apply least privilege principle at DB level.',
                    cvssScore: 9.8,
                });
                return; // Stop after first critical finding for this module
            }

            // Time-based detection: payload SLEEP(5) should take at least 4s more than baseline
            if (payload.includes('SLEEP') && duration > 5000) {
                addVuln(scanId, {
                    type: 'sql_injection', severity: 'critical',
                    title: 'Time-Based SQL Injection Detected',
                    description: `The payload "${payload}" on parameter "${param}" caused a significant response delay (${duration}ms).`,
                    affectedEndpoint: targetStr,
                    payload,
                    evidence: `Response took ${duration}ms which is consistent with SLEEP(5) command payload execution`,
                    aiExplanation: "Time-based blind SQL injection occurs when an attacker can infer data or determine vulnerability by observing response time delays. It's used when the application doesn't return actual data or errors in responses.",
                    exploitation: "Attackers can use tools like sqlmap to extract data character by character based on whether the sleep command is executed (true/false conditions).",
                    remediation: 'Use prepared statements. Sanitize all inputs. Avoid direct SQL concatenation.',
                    cvssScore: 9.8,
                });
                return;
            }
        }
    }
}

async function checkXss(scanId, url) {
    const testUrl = new URL(url);
    const params = Array.from(testUrl.searchParams.keys());
    const candidates = params.length > 0 ? params : ['q', 'search', 'query', 'name', 'id'];

    for (const payload of XSS_PAYLOADS) {
        for (const param of candidates) {
            const target = new URL(url);
            target.searchParams.set(param, payload);
            const targetStr = target.toString();

            addEvent(scanId, 'xss', 'request', `Testing ${param}`, `Testing payload: ${payload}`, { payload });

            const resp = await fetchSafe(targetStr, { headers: { 'User-Agent': 'SecureProbe/2.0' } });
            if (!resp) continue;

            let body = '';
            try { body = await resp.text(); } catch { }

            addEvent(scanId, 'xss', 'response', 'Response Received', `Checking if payload reflects in ${param}`,
                { responseStatus: resp.status, responseBody: body.slice(0, 500) });

            const hasCsp = resp.headers.get('content-security-policy');
            if (body.includes(payload) && !hasCsp) {
                addVuln(scanId, {
                    type: 'xss', severity: 'high',
                    title: 'Reflected Cross-Site Scripting (XSS)',
                    description: `The payload "${payload}" on parameter "${param}" was reflected in the response without encoding or CSP.`,
                    affectedEndpoint: targetStr,
                    payload,
                    evidence: `Payload reflected at position ${body.indexOf(payload)} in response body`,
                    aiExplanation: "Reflected XSS occurs when user input is included in the page response without escaping. Attackers can execute malicious scripts in the victim's browser context to steal cookies or hijack sessions.",
                    exploitation: "Attackers can send a crafted link to victims; when clicked, the script runs in the victim's session, potentially stealing cookies, tokens, or performing actions on their behalf.",
                    remediation: 'Context-aware output encoding. Implement strict CSP. Use sanitization libraries.',
                    cvssScore: 7.2,
                });
                return;
            }
        }
    }
}

async function checkOpenRedirect(scanId, url) {
    const testUrl = new URL(url);
    const params = Array.from(testUrl.searchParams.keys());
    const candidates = params.length > 0 ? params : ['redirect', 'url', 'next', 'u', 'dest', 'destination'];

    for (const payload of OPEN_REDIRECT_PAYLOADS) {
        for (const param of candidates) {
            const target = new URL(url);
            target.searchParams.set(param, payload);
            const targetStr = target.toString();

            addEvent(scanId, 'open_redirect', 'request', `Testing ${param}`, `Testing redirect parameter: ${payload}`, { payload });

            const resp = await fetchSafe(targetStr, {
                method: 'GET', redirect: 'manual', headers: { 'User-Agent': 'SecureProbe/2.0' },
            });
            if (!resp) continue;

            const location = resp.headers.get('location');
            addEvent(scanId, 'open_redirect', 'response', 'Response Received', `Checking Location header for ${param}`,
                { responseStatus: resp.status, responseHeaders: headersToString(resp.headers) });

            if (location && (location.includes('evil.com') || location.includes('google.com') || location.startsWith('//'))) {
                addVuln(scanId, {
                    type: 'open_redirect', severity: 'medium',
                    title: 'Open Redirect Vulnerability',
                    description: `The application redirects to arbitrary URLs via parameter "${param}".`,
                    affectedEndpoint: targetStr,
                    payload,
                    evidence: `HTTP ${resp.status} redirect to: ${location} found via parameter ${param}`,
                    aiExplanation: "Open redirect vulnerabilities allow attackers to redirect users to malicious websites via your trusted brand's URL. This is frequently used in phishing campaigns to lend credibility to malicious links.",
                    exploitation: "Attackers can construct links pointing to the legitimate domain, but transparently redirecting to a phishing site, making the malicious link appear trustworthy.",
                    remediation: 'Validate redirect targets against an allowlist. Use relative URLs. Implement a "click-through" warning page for external redirects.',
                    cvssScore: 5.4,
                });
                return;
            }
        }
    }
}

async function checkSensitiveFiles(scanId, url) {
    const commonPaths = [
        '.env', '.git/config', '.gitignore', 'package.json', 'phpinfo.php',
        'config.php', 'config.js', 'admin/', 'backup.sql', 'db.sql',
        'server-status', '.htaccess', '.DS_Store'
    ];

    const baseUrl = new URL(url);
    baseUrl.search = '';
    baseUrl.hash = '';
    const base = baseUrl.toString().endsWith('/') ? baseUrl.toString() : baseUrl.toString() + '/';

    for (const path of commonPaths) {
        const target = base + path;
        addEvent(scanId, 'file_discovery', 'request', `Checking ${path}`, `Testing for sensitive file: ${path}`, {});

        const resp = await fetchSafe(target, { method: 'GET' });
        if (resp && resp.status === 200) {
            // Basic check to see if it's not a generic 200 (like a custom 404 page)
            const text = await resp.text().catch(() => '');
            if (text.length > 0 && !text.includes('Page Not Found') && !text.includes('404')) {
                addVuln(scanId, {
                    type: 'sensitive_file_disclosure', severity: 'high',
                    title: `Sensitive File/Directory Discovered: ${path}`,
                    description: `The sensitive resource "${path}" was found at ${target}. This may leak configuration or source code.`,
                    affectedEndpoint: target,
                    evidence: `HTTP 200 OK — Resource size: ${text.length} bytes`,
                    aiExplanation: "Sensitive files like .env or .git/config often contain database credentials, API keys, or internal system details that an attacker can use to compromise the entire server.",
                    exploitation: "Attackers can read this file to obtain sensitive configuration, such as database credentials, API keys, or hidden administrative paths, leading to further compromise.",
                    remediation: 'Restrict access to administrative paths and sensitive files. Configure your web server to deny access to hidden files (starting with a dot) and backup files.',
                    cvssScore: 7.5,
                });
            }
        }
    }
}

async function checkHttpMethods(scanId, url) {
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE'];

    for (const method of methods) {
        addEvent(scanId, 'http_methods', 'request', `Testing ${method}`,
            `Sending ${method} request`, {});

        const resp = await fetchSafe(url, { method, headers: { 'User-Agent': 'SecureProbe/2.0' } });
        if (!resp) continue;

        addEvent(scanId, 'http_methods', 'response', `${method} Response`,
            `HTTP ${resp.status}`, { responseStatus: resp.status, responseHeaders: headersToString(resp.headers) });

        if (method === 'TRACE' && resp.status === 200) {
            addVuln(scanId, {
                type: 'http_method_abuse', severity: 'medium',
                title: 'HTTP TRACE Method Enabled',
                description: 'TRACE is enabled. This can be used in Cross-Site Tracing (XST) attacks into steal HttpOnly cookies.',
                affectedEndpoint: url,
                payload: 'TRACE / HTTP/1.1',
                evidence: `TRACE ${url} returned HTTP 200`,
                aiExplanation: "TRACE echoes back the request body including headers. Combined with XSS, an attacker can read HttpOnly cookies.",
                exploitation: "Attackers can use Cross-Site Tracing (XST) by coercing a victim's browser to send a TRACE request, then reading the response to bypass HttpOnly flags on cookies.",
                remediation: 'Disable TRACE method in your server configuration.',
                cvssScore: 5.8,
            });
        }
    }
}

async function checkRateLimit(scanId, url) {
    addEvent(scanId, 'rate_limit', 'info', 'Rate Limit Test', 'Sending 15 rapid requests…', {});

    let blocked = false;
    for (let i = 0; i < 15; i++) {
        const resp = await fetchSafe(url, { method: 'GET' }, 3000);
        if (resp && (resp.status === 429 || resp.headers.get('retry-after'))) {
            blocked = true;
            addEvent(scanId, 'rate_limit', 'info', 'Rate Limit Applied',
                `Rate limited after ${i + 1} requests (HTTP ${resp.status})`,
                { responseStatus: resp.status });
            break;
        }
    }

    if (!blocked) {
        addVuln(scanId, {
            type: 'rate_limit_bypass', severity: 'medium',
            title: 'Missing Rate Limiting',
            description: 'The endpoint does not enforce rate limiting, enabling automated attacks.',
            affectedEndpoint: url,
            payload: '15 rapid requests',
            evidence: '15 consecutive requests returned with 200 OK',
            aiExplanation: "Lack of rate limiting allows attackers to brute-force passwords, scrape content, or perform DoS attacks.",
            exploitation: "Attackers can run automated tools to brute-force login endpoints, guess OTPs, or perform application-layer Denial of Service by sending thousands of requests.",
            remediation: 'Implement rate limiting using a token bucket or sliding window algorithm.',
            cvssScore: 5.3,
        });
    }
}

// ── Risk Score ───────────────────────────────────────────────────────────────

function computeRiskScore(vulns) {
    let score = 0;
    for (const v of vulns) {
        if (v.severity === 'critical') score += 40;
        else if (v.severity === 'high') score += 25;
        else if (v.severity === 'medium') score += 10;
        else if (v.severity === 'low') score += 3;
        else score += 1;
    }
    score = Math.min(score, 100);

    let level = 'info';
    if (score >= 80) level = 'critical';
    else if (score >= 60) level = 'high';
    else if (score >= 30) level = 'medium';
    else if (score >= 10) level = 'low';

    return { score, level };
}

// ── Main Runner ─────────────────────────────────────────────────────────────

async function runScan(scanId, url, options) {
    const completed = [];

    try {
        stmts.updateScanRunning.run(scanId);
        addEvent(scanId, 'initialization', 'info', 'Scan Initialized', `Starting security analysis for ${url}`, {});
        await sleep(300);
        completed.push('initialization');
        updateProgress(scanId, 10, 'headers_analysis', completed);

        if (options.checkHeaders) {
            addEvent(scanId, 'headers_analysis', 'info', 'Starting Security Headers Analysis', 'Checking for missing or misconfigured HTTP security headers', {});
            await checkSecurityHeaders(scanId, url);
            completed.push('headers_analysis');
            updateProgress(scanId, 25, 'cors_analysis', completed);
        }

        if (options.checkCors) {
            addEvent(scanId, 'cors_analysis', 'info', 'Starting CORS Analysis', 'Testing Cross-Origin Resource Sharing configuration', {});
            await checkCors(scanId, url);
            completed.push('cors_analysis');
            updateProgress(scanId, 40, 'sql_injection', completed);
        }

        if (options.checkSqlInjection) {
            addEvent(scanId, 'sql_injection', 'info', 'Starting SQL Injection Tests', 'Testing input parameters for SQL injection vulnerabilities', {});
            await checkSqlInjection(scanId, url);
            completed.push('sql_injection');
            updateProgress(scanId, 55, 'xss', completed);
        }

        if (options.checkXss) {
            addEvent(scanId, 'xss', 'info', 'Starting XSS Tests', 'Testing for reflected Cross-Site Scripting', {});
            await checkXss(scanId, url);
            completed.push('xss');
            updateProgress(scanId, 68, 'open_redirect', completed);
        }

        if (options.checkOpenRedirect) {
            addEvent(scanId, 'open_redirect', 'info', 'Starting Open Redirect Tests', 'Testing redirect parameters', {});
            await checkOpenRedirect(scanId, url);
            completed.push('open_redirect');
            updateProgress(scanId, 78, 'http_methods', completed);
        }

        if (options.checkHttpMethods) {
            addEvent(scanId, 'http_methods', 'info', 'Starting HTTP Method Analysis', 'Testing which HTTP methods are allowed', {});
            await checkHttpMethods(scanId, url);
            completed.push('http_methods');
            updateProgress(scanId, 85, 'file_discovery', completed);
        }

        if (options.checkSensitiveFiles !== false) { // Default true
            addEvent(scanId, 'file_discovery', 'info', 'Starting Sensitive File Discovery', 'Scanning for configuration files and sensitive directories', {});
            await checkSensitiveFiles(scanId, url);
            completed.push('file_discovery');
            updateProgress(scanId, 92, 'rate_limit', completed);
        }

        if (options.checkRateLimit) {
            addEvent(scanId, 'rate_limit', 'info', 'Starting Rate Limit Tests', 'Testing whether rate limiting is enforced', {});
            await checkRateLimit(scanId, url);
            completed.push('rate_limit');
        }

        completed.push('finalization');
        updateProgress(scanId, 95, 'finalization', completed);

        const vulns = stmts.getVulns.all(scanId);
        const { score, level } = computeRiskScore(vulns);
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const v of vulns) {
            if (v.severity in counts) counts[v.severity]++;
        }

        stmts.completeScan.run({
            id: scanId,
            risk_score: score,
            risk_level: level,
            vulnerability_count: vulns.length,
            critical_count: counts.critical,
            high_count: counts.high,
            medium_count: counts.medium,
            low_count: counts.low,
            stages_completed: JSON.stringify(completed),
        });

        addEvent(scanId, 'finalization', 'info', 'Scan Completed',
            `Found ${vulns.length} vulnerabilities. Risk score: ${score}/100 (${level})`,
            { severity: level });

        console.log(`[scan:${scanId}] completed — ${vulns.length} vulns, risk ${score}/100 (${level})`);
    } catch (err) {
        console.error(`[scan:${scanId}] failed:`, err);
        stmts.failScan.run(scanId);
        addEvent(scanId, 'finalization', 'error', 'Scan Failed', String(err), { severity: 'info' });
    }
}

module.exports = { runScan };
