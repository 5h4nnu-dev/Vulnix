const { stmts } = require('./database');
const { v4: uuid } = require('uuid');
const payloadEngine = require('./payloads');

// ── Payloads (loaded from modular payload engine) ───────────────────────────

const SQL_BASIC = payloadEngine.getPayloadsByType('sql_injection', 'basic').map(p => p.payload);
const SQL_TIME = payloadEngine.getPayloadsByType('sql_injection', 'time_based').map(p => p.payload);
const SQL_ADVANCED = payloadEngine.getPayloadsByType('sql_injection', 'advanced')?.slice(0, 3).map(p => p.payload) || [];
const SQL_PAYLOADS = [...SQL_BASIC, ...SQL_TIME, ...SQL_ADVANCED];

const XSS_PAYLOADS = [
    ...payloadEngine.getPayloadsByType('xss', 'basic').map(p => p.payload),
    ...(payloadEngine.getPayloadsByType('xss', 'filter_bypass')?.slice(0, 4).map(p => p.payload) || []),
];

const OPEN_REDIRECT_PAYLOADS = [
    ...payloadEngine.getPayloadsByType('open_redirect', 'basic').map(p => p.payload),
    ...(payloadEngine.getPayloadsByType('open_redirect', 'filter_bypass')?.slice(0, 4).map(p => p.payload) || []),
];

const UA = 'SecureProbe/2.0';

// ── Helpers ─────────────────────────────────────────────────────────────────

function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
}

async function fetchSafe(url, opts = {}, timeoutMs = 10000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const resp = await fetch(url, {
            redirect: 'follow',
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

function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const chr = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + chr;
        hash |= 0;
    }
    return hash.toString(16);
}

function extractFingerprint(body) {
    const keywords = [];
    const lower = body.toLowerCase();
    if (lower.includes('not found')) keywords.push('not_found');
    if (lower.includes('page not found')) keywords.push('page_not_found');
    if (lower.includes('404')) keywords.push('404');
    if (lower.includes('does not exist')) keywords.push('does_not_exist');
    if (lower.includes('error')) keywords.push('error');
    if (lower.includes('cannot find')) keywords.push('cannot_find');
    return keywords;
}

function isSoft404(responseBody, responseStatus, baseline) {
    if (responseStatus === 404 || responseStatus === 403 || responseStatus === 401) return true;
    if (!baseline || baseline.status === null) return false;

    if (simpleHash(responseBody) === baseline.bodyHash) return true;

    const lenDiff = Math.abs(responseBody.length - baseline.bodyLength);
    if (baseline.bodyLength > 0 && lenDiff / baseline.bodyLength < 0.1) return true;

    const lower = responseBody.toLowerCase();
    const has404Indicators = ['not found', '404', 'page not found', 'does not exist', 'cannot find', 'no such file']
        .some(kw => lower.includes(kw));
    if (has404Indicators) return true;

    return false;
}

function htmlDecode(str) {
    return str
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/&amp;/gi, '&')
        .replace(/&quot;/gi, '"')
        .replace(/&#39;/gi, "'")
        .replace(/&#x27;/gi, "'")
        .replace(/&#x2F;/gi, '/');
}

function computeRiskScore(vulns) {
    if (vulns.length === 0) return { score: 0, level: 'info' };

    const VULN_CATEGORIES = {
        active:     { types: ['sql_injection', 'command_injection', 'path_traversal', 'ssrf', 'csrf'], multiplier: 1.0 },
        xss:        { types: ['xss'], multiplier: 0.8 },
        redirect:   { types: ['open_redirect'], multiplier: 0.6 },
        config:     { types: ['cors_misconfiguration', 'http_method_abuse', 'insecure_cookie', 'missing_security_header', 'weak_security_header'], multiplier: 0.35 },
        exposure:   { types: ['sensitive_file_disclosure', 'rate_limit_bypass', 'info_disclosure'], multiplier: 0.2 },
    };

    const TYPE_TO_CATEGORY = {};
    for (const [, cat] of Object.entries(VULN_CATEGORIES)) {
        for (const t of cat.types) TYPE_TO_CATEGORY[t] = cat;
    }

    const byType = {};
    for (const v of vulns) {
        if (!byType[v.type]) byType[v.type] = [];
        byType[v.type].push(v);
    }

    let rawScore = 0;
    const sevWeights = { critical: 40, high: 25, medium: 10, low: 2, info: 0.5 };

    for (const [, typeVulns] of Object.entries(byType)) {
        const cat = TYPE_TO_CATEGORY[typeVulns[0].type] || { multiplier: 0.5 };
        typeVulns.sort((a, b) => (sevWeights[b.severity] || 0) - (sevWeights[a.severity] || 0));

        let groupScore = 0;
        for (let i = 0; i < typeVulns.length; i++) {
            const weight = sevWeights[typeVulns[i].severity] || 0.5;
            const diminish = 1 / (1 + i * 0.5);
            groupScore += weight * diminish;
        }
        rawScore += Math.min(groupScore, 50) * cat.multiplier;
    }

    const score = Math.min(Math.round(rawScore), 100);
    let level = 'info';
    if (score >= 75) level = 'critical';
    else if (score >= 55) level = 'high';
    else if (score >= 25) level = 'medium';
    else if (score >= 8) level = 'low';

    return { score, level };
}

// ── Baseline ────────────────────────────────────────────────────────────────

async function getBaselineFingerprint(baseUrl) {
    const randomPath = `nonexistent-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const target = baseUrl.endsWith('/') ? baseUrl + randomPath : baseUrl + '/' + randomPath;
    const resp = await fetchSafe(target, { method: 'GET' });
    if (!resp) return { status: null, bodyLength: 0, bodyHash: '', keywords: [] };

    const body = await resp.text().catch(() => '');
    return {
        status: resp.status,
        bodyLength: body.length,
        bodyHash: simpleHash(body),
        keywords: extractFingerprint(body),
    };
}

async function getBaselineResponseTime(url, samples = 3) {
    const times = [];
    for (let i = 0; i < samples; i++) {
        const start = Date.now();
        await fetchSafe(url, { headers: { 'User-Agent': UA } }, 5000);
        times.push(Date.now() - start);
    }
    times.sort((a, b) => a - b);
    return times[Math.floor(times.length / 2)];
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

function checkCspValue(csp) {
    const directives = csp.split(';').map(d => d.trim().toLowerCase());
    const findings = [];
    for (const dir of directives) {
        if (dir.startsWith('default-src') && (dir.includes('*') || dir.includes("'unsafe-inline'"))) {
            findings.push('default-src is too permissive');
        }
        if (dir.startsWith('script-src') && dir.includes("'unsafe-inline'")) {
            findings.push('unsafe-inline allowed in script-src');
        }
        if (dir.startsWith('script-src') && dir.includes("'unsafe-eval'")) {
            findings.push('unsafe-eval allowed in script-src');
        }
    }
    return findings;
}

async function checkSecurityHeaders(scanId, url) {
    const resp = await fetchSafe(url, { method: 'GET', headers: { 'User-Agent': UA } });
    if (!resp) {
        addEvent(scanId, 'headers_analysis', 'error', 'Connection Failed', 'Could not connect to the target URL', { severity: 'info' });
        return;
    }

    const rHeadersStr = headersToString(resp.headers);

    const checks = [
        {
            name: 'Content-Security-Policy', header: 'content-security-policy',
            severity: 'medium', cvss: 6.1,
            remediation: "Add a Content-Security-Policy header. Example: Content-Security-Policy: default-src 'self'",
            aiExplanation: "The Content-Security-Policy (CSP) header is missing or poorly configured. CSP is a critical defense against XSS by controlling what resources can load.",
            exploitation: "Attackers can perform XSS attacks if they can inject scripts; without CSP, the browser will execute them unconditionally.",
            checkValue: (val) => {
                const issues = checkCspValue(val);
                return issues.length > 0 ? issues.join('; ') : null;
            }
        },
        {
            name: 'Strict-Transport-Security', header: 'strict-transport-security',
            severity: 'low', cvss: 4.3,
            remediation: 'Enable HTTPS and add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            aiExplanation: "The HSTS header is missing, allowing for protocol downgrade attacks (SSL stripping).",
            exploitation: "An attacker on the same network can intercept traffic and perform SSL stripping, downgrading the connection to HTTP.",
        },
        {
            name: 'X-Frame-Options', header: 'x-frame-options',
            severity: 'low', cvss: 4.3,
            remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN',
            aiExplanation: "Missing X-Frame-Options makes the site vulnerable to clickjacking.",
            exploitation: "Attackers can embed the site in an iframe and trick users into clicking buttons they didn't intend to, known as Clickjacking.",
            badValues: [/^allowall$/i]
        },
        {
            name: 'X-Content-Type-Options', header: 'x-content-type-options',
            severity: 'info', cvss: 3.1,
            remediation: 'Add X-Content-Type-Options: nosniff',
            aiExplanation: "Missing nosniff allows browsers to guess MIME types, which can lead to content injection vulnerabilities.",
            exploitation: "Attackers can upload a file with an innocent extension (e.g., image.jpg) that contains HTML/JS, and the browser might execute it.",
        },
        {
            name: 'Referrer-Policy', header: 'referrer-policy',
            severity: 'info', cvss: 2.5,
            remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer',
            aiExplanation: "Without a Referrer-Policy, the browser may leak the full URL (including query parameters with sensitive data) to external sites via the Referer header.",
            exploitation: "Session tokens, API keys, or personally identifiable information in URLs can be leaked to third-party analytics or ad networks.",
            badValues: [/unsafe-url/i]
        },
        {
            name: 'Permissions-Policy', header: 'permissions-policy',
            severity: 'info', cvss: 2.0,
            remediation: 'Add Permissions-Policy: camera=(), microphone=(), geolocation=() to restrict browser features',
            aiExplanation: "Without Permissions-Policy, the page (and any iframes/scripts) can access powerful browser APIs like camera, microphone, and geolocation.",
            exploitation: "If an attacker achieves XSS, they can silently access the camera, microphone, or GPS without additional prompts if no Permissions-Policy is set.",
        },
        {
            name: 'X-Permitted-Cross-Domain-Policies', header: 'x-permitted-cross-domain-policies',
            severity: 'info', cvss: 1.5,
            remediation: 'Add X-Permitted-Cross-Domain-Policies: none',
            aiExplanation: "This header controls whether Flash and PDF readers can load data from the site cross-domain.",
            exploitation: "Legacy Flash/PDF plugins can make cross-domain requests if this header is permissive.",
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
        } else if (c.checkValue) {
            const issue = c.checkValue(val);
            if (issue) {
                addVuln(scanId, {
                    type: 'weak_security_header', severity: 'low',
                    title: `Weak ${c.name} Configuration`,
                    description: `The ${c.name} header has issues: ${issue}`,
                    affectedEndpoint: url,
                    evidence: `Header ${c.name}: ${val}`,
                    aiExplanation: `A weak ${c.name} configuration may still allow certain classes of attacks.`,
                    exploitation: c.exploitation,
                    remediation: c.remediation, cvssScore: 3.0,
                });
            }
        } else if (c.badValues && c.badValues.some(p => p.test(val))) {
            addVuln(scanId, {
                type: 'weak_security_header', severity: 'low',
                title: `Weak ${c.name} Configuration`,
                description: `The ${c.name} header value "${val}" is considered weak.`,
                affectedEndpoint: url,
                evidence: `Header ${c.name}: ${val}`,
                aiExplanation: `A weak ${c.name} configuration may still allow certain classes of attacks.`,
                exploitation: c.exploitation,
                remediation: c.remediation, cvssScore: 3.0,
            });
        }
    }

    const server = resp.headers.get('server');
    if (server && /\d+\.\d+(\.\d+)?/.test(server)) {
        addVuln(scanId, {
            type: 'info_disclosure', severity: 'low',
            title: 'Detailed Server Banner Detected',
            description: `The Server header "${server}" reveals software version information.`,
            affectedEndpoint: url,
            evidence: `Server: ${server}`,
            aiExplanation: "Revealing specific server versions helps attackers find known CVEs for your stack.",
            exploitation: "Attackers use the banner to search Exploit-DB or similar databases for known CVEs affecting the exact server version.",
            remediation: 'Configure your web server to suppress the Server banner and version info.',
            cvssScore: 2.1,
        });
    }

    const poweredBy = resp.headers.get('x-powered-by');
    if (poweredBy) {
        addVuln(scanId, {
            type: 'info_disclosure', severity: 'low',
            title: 'X-Powered-By Header Detected',
            description: `The X-Powered-By header "${poweredBy}" reveals backend technology information.`,
            affectedEndpoint: url,
            evidence: `X-Powered-By: ${poweredBy}`,
            aiExplanation: "The X-Powered-By header reveals the backend framework (e.g., Express, PHP, ASP.NET), helping attackers narrow their attack surface.",
            exploitation: "Knowing the exact framework and version lets attackers target framework-specific vulnerabilities and default configurations.",
            remediation: 'Remove the X-Powered-By header. In Express: app.disable("x-powered-by")',
            cvssScore: 2.0,
        });
    }

    const setCookies = resp.headers.getSetCookie?.() || [];
    const rawSetCookie = resp.headers.get('set-cookie');
    const cookieList = setCookies.length > 0 ? setCookies : (rawSetCookie ? [rawSetCookie] : []);

    for (const cookie of cookieList) {
        const name = cookie.split('=')[0]?.trim() || 'unknown';
        const lower = cookie.toLowerCase();
        const issues = [];

        const isSecurePrefix = name.startsWith('__Secure-') || name.startsWith('__Host-');
        if (!lower.includes('httponly') && !isSecurePrefix) issues.push('HttpOnly');
        if (!lower.includes('secure')) issues.push('Secure');
        if (!lower.includes('samesite')) issues.push('SameSite');

        if (issues.length > 0) {
            addVuln(scanId, {
                type: 'insecure_cookie', severity: issues.includes('HttpOnly') ? 'medium' : 'low',
                title: `Insecure Cookie: ${name} (Missing ${issues.join(', ')})`,
                description: `The cookie "${name}" is missing security flags: ${issues.join(', ')}.`,
                affectedEndpoint: url,
                evidence: `Set-Cookie: ${cookie.slice(0, 200)}`,
                aiExplanation: `Missing ${issues.join(' and ')} flag(s) on cookies can lead to session hijacking.`,
                exploitation: "Without HttpOnly, XSS attacks can steal cookies via document.cookie. Without Secure, cookies can be intercepted over HTTP. Without SameSite, CSRF attacks are easier.",
                remediation: `Set cookie flags: Set-Cookie: ${name}=value; HttpOnly; Secure; SameSite=Lax`,
                cvssScore: issues.includes('HttpOnly') ? 5.3 : 3.1,
            });
        }
    }
}

async function checkCors(scanId, url) {
    const origins = ['https://evil.com', 'https://attacker.com', 'null'];

    for (const origin of origins) {
        const resp = await fetchSafe(url, { method: 'GET', headers: { Origin: origin, 'User-Agent': UA } });
        if (!resp) continue;

        const acao = resp.headers.get('access-control-allow-origin');
        const acac = resp.headers.get('access-control-allow-credentials');

        if (acao === '*') {
            const hasCredentials = acac === 'true';
            addVuln(scanId, {
                type: 'cors_misconfiguration', severity: hasCredentials ? 'high' : 'medium',
                title: 'Permissive CORS Policy (Wildcard Origin)',
                description: `The server responds with Access-Control-Allow-Origin: *${hasCredentials ? ' with credentials allowed' : ''}.`,
                affectedEndpoint: url,
                payload: `Origin: ${origin}`,
                evidence: `Response: ACAO: *${hasCredentials ? ', ACAC: true' : ''}`,
                aiExplanation: "A wildcard CORS policy means any website can make cross-origin requests and read responses.",
                exploitation: "An attacker can create a malicious page that reads sensitive data via AJAX.",
                remediation: 'Replace the wildcard with a specific allowlist of trusted origins.',
                cvssScore: hasCredentials ? 7.5 : 5.3,
            });
            break;
        } else if (acao === origin) {
            const severity = acac === 'true' ? 'high' : 'medium';
            addVuln(scanId, {
                type: 'cors_misconfiguration', severity,
                title: 'CORS Origin Reflection Vulnerability',
                description: `The server reflects arbitrary origins in ACAO${acac === 'true' ? ' with credentials allowed' : ''}.`,
                affectedEndpoint: url,
                payload: `Origin: ${origin}`,
                evidence: `Request Origin: ${origin} → Response ACAO: ${acao}${acac === 'true' ? ' + ACAC: true' : ''}`,
                aiExplanation: acac === 'true'
                    ? "Critical: The server reflects the Origin AND sets credentials: true."
                    : "The server reflects arbitrary origins, allowing any website to read cross-origin responses.",
                exploitation: "An attacker can trick a victim into visiting a malicious site that makes cross-origin requests.",
                remediation: 'Implement a strict CORS allowlist. Never dynamically reflect arbitrary origins.',
                cvssScore: acac === 'true' ? 8.1 : 5.4,
            });
            break;
        }
    }
}

const SQL_ERROR_PATTERNS = [
    /sql syntax/i, /mysql_fetch/i, /ora-\d{5}/i, /pg_query/i,
    /sqlite_/i, /syntax error.*sql/i, /unclosed quotation/i,
    /quoted string not properly terminated/i, /microsoft ole db/i,
    /PostgreSQL.*ERROR/i, /MariaDB.*syntax/i, /ODBC Driver/i,
    /\bsqlstate\b/i, /\bpdo[_-]?exception/i, /database error/i,
    /unexpected end of sql/i, /you have an error in your sql/i,
];

async function checkSqlInjection(scanId, url, baselineTime) {
    const parsedUrl = new URL(url);
    const params = Array.from(parsedUrl.searchParams.keys());
    const candidates = params.length > 0 ? params : ['id', 'search', 'query', 'p', 'view'];

    let baselineBody = '';
    const baselineResp = await fetchSafe(url, { headers: { 'User-Agent': UA } });
    if (baselineResp) {
        try { baselineBody = await baselineResp.text(); } catch { }
    }

    for (const payload of SQL_PAYLOADS) {
        for (const param of candidates) {
            const target = new URL(url);
            target.searchParams.set(param, payload);
            const targetStr = target.toString();

            const start = Date.now();
            const resp = await fetchSafe(targetStr, { headers: { 'User-Agent': UA } });
            const duration = Date.now() - start;
            if (!resp) continue;

            let body = '';
            try { body = await resp.text(); } catch { }

            for (const pattern of SQL_ERROR_PATTERNS) {
                const match = body.match(pattern);
                if (match) {
                    addVuln(scanId, {
                        type: 'sql_injection', severity: 'critical',
                        title: 'Error-Based SQL Injection Detected',
                        description: `The payload "${payload}" on parameter "${param}" triggered a database error.`,
                        affectedEndpoint: targetStr, payload,
                        evidence: `Error pattern found: ${match[0]}`,
                        aiExplanation: "Error-based SQL injection confirms user input is concatenated into SQL queries.",
                        exploitation: "Attackers can use UNION SELECT to extract arbitrary database tables.",
                        remediation: 'Use parameterized queries/prepared statements.',
                        cvssScore: 9.8,
                    });
                    return;
                }
            }

            if ((payload.includes('SLEEP') || payload.includes('WAITFOR') || payload.includes('pg_sleep'))) {
                const threshold = Math.max(4000, (baselineTime || 1000) * 3);
                if (duration > threshold) {
                    addVuln(scanId, {
                        type: 'sql_injection', severity: 'critical',
                        title: 'Time-Based SQL Injection Detected',
                        description: `Payload "${payload}" on "${param}" caused ${duration}ms delay (baseline: ${baselineTime || 'N/A'}ms).`,
                        affectedEndpoint: targetStr, payload,
                        evidence: `Response: ${duration}ms vs baseline ${baselineTime || 'N/A'}ms`,
                        aiExplanation: "Time-based blind SQL injection confirms injectable parameter via response delay.",
                        exploitation: "Attackers extract data character-by-character using conditional sleep statements.",
                        remediation: 'Use prepared statements. Avoid direct SQL concatenation.',
                        cvssScore: 9.8,
                    });
                    return;
                }
            }

            if ((payload.includes('AND 1=1') || payload.includes("OR '1'='1")) && baselineBody.length > 0) {
                const falsePayload = payload.replace('1=1', '1=2').replace("'1'='1", "'1'='2");
                const falseTarget = new URL(url);
                falseTarget.searchParams.set(param, falsePayload);
                const falseResp = await fetchSafe(falseTarget.toString(), { headers: { 'User-Agent': UA } });
                if (falseResp) {
                    let falseBody = '';
                    try { falseBody = await falseResp.text(); } catch { }

                    const trueLen = body.length;
                    const falseLen = falseBody.length;
                    const baseLen = baselineBody.length;
                    const maxLen = Math.max(baseLen, 1);

                    const trueMatchesBase = Math.abs(trueLen - baseLen) / maxLen < 0.15;
                    const falseDiffers = Math.abs(falseLen - baseLen) / maxLen > 0.25;

                    if (trueMatchesBase && falseDiffers) {
                        addVuln(scanId, {
                            type: 'sql_injection', severity: 'high',
                            title: 'Boolean-Based Blind SQL Injection',
                            description: `"${param}" differs: TRUE=${trueLen}B, FALSE=${falseLen}B, baseline=${baseLen}B.`,
                            affectedEndpoint: targetStr, payload,
                            evidence: `TRUE: ${trueLen}B, FALSE: ${falseLen}B, Baseline: ${baseLen}B`,
                            aiExplanation: "Boolean-based blind SQL injection confirmed via TRUE vs FALSE response differences.",
                            exploitation: "Attackers extract data bit-by-bit via conditional SQL statements.",
                            remediation: 'Use parameterized queries/prepared statements.',
                            cvssScore: 8.6,
                        });
                        return;
                    }
                }
            }
        }
    }
}

async function checkXss(scanId, url) {
    const parsedUrl = new URL(url);
    const params = Array.from(parsedUrl.searchParams.keys());
    const candidates = params.length > 0 ? params : ['q', 'search', 'query', 'name', 'id'];

    for (const payload of XSS_PAYLOADS) {
        for (const param of candidates) {
            const target = new URL(url);
            target.searchParams.set(param, payload);
            const targetStr = target.toString();

            const resp = await fetchSafe(targetStr, { headers: { 'User-Agent': UA } });
            if (!resp) continue;

            let body = '';
            try { body = await resp.text(); } catch { }

            const cspHeader = resp.headers.get('content-security-policy');
            const hasStrictCsp = cspHeader && !(/unsafe-inline/i.test(cspHeader)) && !(/unsafe-eval/i.test(cspHeader));

            const exactReflection = body.includes(payload);
            const decodedBody = htmlDecode(body);
            const decodedReflection = !exactReflection && decodedBody.includes(payload);

            if (exactReflection) {
                const severity = hasStrictCsp ? 'medium' : 'high';
                addVuln(scanId, {
                    type: 'xss', severity,
                    title: `Reflected XSS${hasStrictCsp ? ' — Mitigated by CSP' : ''}`,
                    description: `Payload "${payload}" on "${param}" reflected unencoded${hasStrictCsp ? ', but strict CSP may block execution' : ''}.`,
                    affectedEndpoint: targetStr, payload,
                    evidence: `Reflected at position ${body.indexOf(payload)}${hasStrictCsp ? '. CSP: ' + cspHeader.slice(0, 100) : '. No effective CSP.'}`,
                    aiExplanation: hasStrictCsp
                        ? "Payload reflected unencoded but CSP may block execution. CSP bypass may still succeed."
                        : "Reflected XSS: user input included without encoding. Attackers can execute scripts in victim's browser.",
                    exploitation: "Attackers send crafted link; script runs in victim's session, stealing cookies or tokens.",
                    remediation: 'Apply context-aware output encoding. Implement strict CSP.',
                    cvssScore: hasStrictCsp ? 4.7 : 7.2,
                });
                return;
            } else if (decodedReflection && body.length > 200) {
                const hasHtmlTag = /<[a-z][\s>]|<\//i.test(payload) && /<[a-z][\s>]|<\//i.test(decodedBody);
                if (!hasHtmlTag) continue;
                addVuln(scanId, {
                    type: 'xss', severity: 'info',
                    title: 'Partial XSS Reflection — HTML Encoded',
                    description: `Payload "${payload}" on "${param}" reflected with HTML encoding.`,
                    affectedEndpoint: targetStr, payload,
                    evidence: 'Payload reflected with HTML entity encoding.',
                    aiExplanation: "HTML entity encoding is applied, but may be insufficient in JS contexts.",
                    exploitation: "If rendered inside a JavaScript string or attribute, encoding may not prevent execution.",
                    remediation: 'Use context-aware encoding per output context.',
                    cvssScore: 3.4,
                });
            }
        }
    }
}

async function checkOpenRedirect(scanId, url) {
    const parsedUrl = new URL(url);
    const params = Array.from(parsedUrl.searchParams.keys());
    const candidates = params.length > 0 ? params : ['redirect', 'url', 'next', 'u', 'dest', 'destination', 'return', 'returnUrl', 'goto', 'redir', 'return_to', 'continue'];

    for (const payload of OPEN_REDIRECT_PAYLOADS) {
        for (const param of candidates) {
            const target = new URL(url);
            target.searchParams.set(param, payload);
            const targetStr = target.toString();

            const resp = await fetchSafe(targetStr, {
                method: 'GET', redirect: 'manual', headers: { 'User-Agent': UA },
            });
            if (!resp) continue;

            const location = resp.headers.get('location');

            if (resp.status >= 300 && resp.status < 400 && location) {
                let targetHost = null;
                try { targetHost = new URL(location, url).hostname; } catch { targetHost = location; }
                const targetDomain = targetHost.replace(/^www\./, '');
                const originalDomain = new URL(url).hostname.replace(/^www\./, '');
                const isExternal = (
                    targetHost !== null &&
                    targetDomain !== originalDomain &&
                    targetDomain !== ''
                );

                if (isExternal) {
                    addVuln(scanId, {
                        type: 'open_redirect', severity: 'medium',
                        title: 'Open Redirect Vulnerability',
                        description: `App redirects to external URLs via parameter "${param}".`,
                        affectedEndpoint: targetStr, payload,
                        evidence: `HTTP ${resp.status} → ${location} via ${param}`,
                        aiExplanation: "Open redirect lets attackers redirect users to phishing sites via your domain.",
                        exploitation: "Attackers craft links to your domain that transparently redirect to phishing pages.",
                        remediation: 'Validate redirect targets against an allowlist. Use relative URLs.',
                        cvssScore: 5.4,
                    });
                    return;
                }
            }

            if (resp.status === 200) {
                let body = '';
                try { body = await resp.text(); } catch { }
                const lower = body.toLowerCase();
                if (
                    (lower.includes('meta') && lower.includes('refresh') && (lower.includes('evil.com') || lower.includes('attacker.com'))) ||
                    (lower.includes('window.location') && (lower.includes('evil.com') || lower.includes('attacker.com')))
                ) {
                    addVuln(scanId, {
                        type: 'open_redirect', severity: 'medium',
                        title: 'Client-Side Open Redirect',
                        description: `Client-side redirect to external domain via "${param}".`,
                        affectedEndpoint: targetStr, payload,
                        evidence: 'Meta refresh or JS redirect to external domain detected.',
                        aiExplanation: "Client-side redirects can be abused similarly for phishing.",
                        exploitation: "Victim visits legitimate URL, redirected to phishing page after load.",
                        remediation: 'Validate all redirect destinations server-side before rendering.',
                        cvssScore: 4.7,
                    });
                    return;
                }
            }
        }
    }
}

async function checkSensitiveFiles(scanId, url, baseline) {
    const commonPaths = [
        { path: '.env', indicator: /^[A-Z_]+=.+/m, desc: 'Environment configuration file' },
        { path: '.git/config', indicator: /\[core\]|\[remote/i, desc: 'Git repository configuration' },
        { path: '.git/HEAD', indicator: /^ref: refs\//m, desc: 'Git HEAD reference' },
        { path: '.gitignore', indicator: /node_modules|\.env|\.log/i, desc: 'Git ignore rules' },
        { path: 'package.json', indicator: /"(name|version|dependencies)":/i, desc: 'Node.js package manifest' },
        { path: 'composer.json', indicator: /"(require|autoload)":/i, desc: 'PHP Composer manifest' },
        { path: 'phpinfo.php', indicator: /phpinfo|php version|configuration/i, desc: 'PHP info page' },
        { path: 'wp-config.php', indicator: /DB_NAME|DB_PASSWORD|WP_/i, desc: 'WordPress configuration' },
        { path: 'config.php', indicator: /password|database|db_/i, desc: 'PHP config file' },
        { path: '.htaccess', indicator: /RewriteEngine|Deny|Allow/i, desc: 'Apache configuration' },
        { path: '.DS_Store', indicator: null, desc: 'macOS directory metadata' },
        { path: 'backup.sql', indicator: /CREATE TABLE|INSERT INTO|DROP TABLE/i, desc: 'SQL database backup' },
        { path: 'db.sql', indicator: /CREATE TABLE|INSERT INTO|DROP TABLE/i, desc: 'SQL database dump' },
        { path: 'server-status', indicator: /Apache Server Status|Server Version/i, desc: 'Apache server status' },
        { path: 'web.config', indicator: /<configuration|<system\.web/i, desc: 'IIS configuration' },
        { path: '.svn/entries', indicator: /\d+\.\d+/m, desc: 'SVN repository metadata' },
        { path: 'crossdomain.xml', indicator: /<cross-domain-policy/i, desc: 'Flash cross-domain policy' },
        { path: 'robots.txt', indicator: /disallow|user-agent|sitemap/i, desc: 'Robots exclusion file' },
    ];

    const baseUrl = new URL(url);
    baseUrl.search = '';
    baseUrl.hash = '';
    const base = baseUrl.toString().endsWith('/') ? baseUrl.toString() : baseUrl.toString() + '/';

    for (const { path, indicator, desc } of commonPaths) {
        const target = base + path;
        const resp = await fetchSafe(target, { method: 'GET' });
        if (!resp || resp.status !== 200) continue;

        const text = await resp.text().catch(() => '');
        if (text.length === 0 || isSoft404(text, resp.status, baseline)) continue;

        const contentMatches = indicator ? indicator.test(text) : text.length > 0;
        if (!contentMatches) continue;

        if (path === 'robots.txt') {
            const hasInteresting = /disallow:\s*\/(admin|api|backup|config|db|dashboard|internal|private|secret|staging)/i.test(text);
            if (!hasInteresting) continue;
            addVuln(scanId, {
                type: 'info_disclosure', severity: 'info',
                title: 'Robots.txt Reveals Sensitive Paths',
                description: `robots.txt at ${target} discloses sensitive directories.`,
                affectedEndpoint: target,
                evidence: `HTTP 200 — ${text.length}B. Disallow rules for sensitive paths.`,
                aiExplanation: "robots.txt can inadvertently reveal admin panels or internal APIs to attackers.",
                exploitation: "Attackers use robots.txt as a directory map.",
                remediation: 'Avoid listing sensitive paths in robots.txt. Use authentication instead.',
                cvssScore: 2.0,
            });
            continue;
        }

        if (path === 'crossdomain.xml') {
            const isPermissive = /<allow-access-from\s+domain\s*=\s*["']\*["']/i.test(text);
            if (!isPermissive) continue;
        }

        const pathLower = path.toLowerCase();
        const severity = /\.env|config\.php|wp-config|backup\.sql|db\.sql/i.test(path) ? 'high'
            : /crossdomain\.xml|\.ds_store|robots\.txt/i.test(pathLower) ? 'info'
            : 'low';
        addVuln(scanId, {
            type: 'sensitive_file_disclosure', severity,
            title: `Sensitive File Discovered: ${path}`,
            description: `"${path}" (${desc}) found at ${target}.`,
            affectedEndpoint: target,
            evidence: `HTTP 200 — ${text.length}B. Signature matched for ${desc}.`,
            aiExplanation: "Sensitive files often contain credentials or internal details.",
            exploitation: "Attackers read this file to obtain credentials or system details.",
            remediation: 'Restrict access to sensitive files. Deny access to dotfiles.',
            cvssScore: severity === 'high' ? 7.5 : 5.0,
        });
    }
}

async function checkHttpMethods(scanId, url) {
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE'];

    for (const method of methods) {
        const resp = await fetchSafe(url, { method, headers: { 'User-Agent': UA } });
        if (!resp) continue;

        if (method === 'TRACE' && resp.status === 200) {
            let body = '';
            try { body = await resp.text(); } catch { }
            if (body.toLowerCase().includes('trace') || body.includes('User-Agent')) {
                addVuln(scanId, {
                    type: 'http_method_abuse', severity: 'medium',
                    title: 'HTTP TRACE Method Enabled',
                    description: 'TRACE echoes requests, enabling Cross-Site Tracing (XST) attacks.',
                    affectedEndpoint: url,
                    payload: 'TRACE / HTTP/1.1',
                    evidence: `TRACE returned HTTP 200 with echoed request content`,
                    aiExplanation: "TRACE + XSS bypasses HttpOnly to steal cookies.",
                    exploitation: "XST bypasses HttpOnly cookies via TRACE + XSS combo.",
                    remediation: 'Disable TRACE method in server configuration.',
                    cvssScore: 5.8,
                });
            }
        }
    }
}

async function checkRateLimit(scanId, url) {
    let blocked = false;
    const statusCodes = [];

    for (let i = 0; i < 20; i++) {
        const resp = await fetchSafe(url, { method: 'GET', headers: { 'User-Agent': UA } }, 5000);
        if (resp) {
            statusCodes.push(resp.status);
            if (resp.status === 429 || resp.headers.get('retry-after')) {
                blocked = true;
                break;
            }
        }
    }

    if (!blocked) {
        const successCount = statusCodes.filter(s => s >= 200 && s < 400).length;
        if (successCount >= 18) {
            addVuln(scanId, {
                type: 'rate_limit_bypass', severity: 'low',
                title: 'Missing Rate Limiting',
                description: `No rate limiting: ${successCount}/20 requests succeeded.`,
                affectedEndpoint: url,
                payload: '20 rapid requests',
                evidence: `${successCount}/20 succeeded. Codes: ${[...new Set(statusCodes)].join(', ')}`,
                aiExplanation: "Lack of rate limiting enables brute-force and DoS attacks.",
                exploitation: "Attackers brute-force passwords, guess OTPs, or DoS the endpoint.",
                remediation: 'Implement rate limiting via express-rate-limit or similar.',
                cvssScore: 5.3,
            });
        }
    }
}

async function checkTechnologyFingerprint(scanId, url) {
    const resp = await fetchSafe(url, { method: 'GET', headers: { 'User-Agent': UA } });
    if (!resp) return;

    let body = '';
    try { body = await resp.text(); } catch { }
    const headers = headersToObj(resp.headers);
    const techs = [];

    if (headers['x-powered-by']) techs.push(headers['x-powered-by']);
    if (headers['server']) techs.push(headers['server']);
    if (headers['x-aspnet-version']) techs.push('ASP.NET ' + headers['x-aspnet-version']);
    if (headers['x-drupal-cache']) techs.push('Drupal');
    if (headers['x-generator']) techs.push(headers['x-generator']);

    const lower = body.toLowerCase();
    if (lower.includes('wp-content') || lower.includes('wp-includes')) techs.push('WordPress');
    if (lower.includes('joomla')) techs.push('Joomla');
    if (lower.includes('drupal')) techs.push('Drupal');
    if (lower.includes('next-head') || lower.includes('_next/')) techs.push('Next.js');
    if (lower.includes('__nuxt') || lower.includes('_nuxt/')) techs.push('Nuxt.js');
    if (lower.includes('react') && lower.includes('__react')) techs.push('React');
    if (body.includes('ng-app') || body.includes('ng-controller')) techs.push('AngularJS');
    if (lower.includes('laravel')) techs.push('Laravel');

    if (techs.length > 0) {
        addEvent(scanId, 'tech_fingerprint', 'finding', 'Technologies Detected',
            `Identified: ${techs.join(', ')}`, { severity: 'info' });
    }
}

// ── Main Runner ─────────────────────────────────────────────────────────────

async function runScan(scanId, url, options) {
    const completed = [];

    try {
        stmts.updateScanRunning.run(scanId);
        addEvent(scanId, 'initialization', 'info', 'Scan Initialized', `Starting security analysis for ${url}`, {});

        addEvent(scanId, 'initialization', 'info', 'Baseline Fingerprinting', 'Gathering baseline response for soft-404 detection', {});
        const [baseline, baselineTime] = await Promise.all([
            getBaselineFingerprint(url),
            getBaselineResponseTime(url),
        ]);

        addEvent(scanId, 'initialization', 'info', 'Baseline Timing', `Median response time: ${baselineTime}ms`, {});

        completed.push('initialization');
        updateProgress(scanId, 8, 'tech_fingerprint', completed);

        addEvent(scanId, 'tech_fingerprint', 'info', 'Starting Technology Fingerprinting', 'Identifying web technologies in use', {});
        await checkTechnologyFingerprint(scanId, url);
        completed.push('tech_fingerprint');
        updateProgress(scanId, 12, 'headers_analysis', completed);

        // Phase 1: Headers + CORS (both need 1 request each, can parallelize)
        const headerPromise = options.checkHeaders
            ? checkSecurityHeaders(scanId, url).then(() => { completed.push('headers_analysis'); updateProgress(scanId, 25, 'cors_analysis', completed); })
            : Promise.resolve();

        const corsPromise = options.checkCors
            ? checkCors(scanId, url).then(() => { completed.push('cors_analysis'); updateProgress(scanId, 38, 'sql_injection', completed); })
            : Promise.resolve();

        await Promise.all([headerPromise, corsPromise]);

        // Phase 2: SQLi + XSS (both test params, independent)
        const sqliPromise = options.checkSqlInjection
            ? checkSqlInjection(scanId, url, baselineTime).then(() => { completed.push('sql_injection'); updateProgress(scanId, 52, 'xss', completed); })
            : Promise.resolve();

        const xssPromise = options.checkXss
            ? checkXss(scanId, url).then(() => { completed.push('xss'); updateProgress(scanId, 64, 'open_redirect', completed); })
            : Promise.resolve();

        await Promise.all([sqliPromise, xssPromise]);

        // Phase 3: Open redirects (independent)
        if (options.checkOpenRedirect) {
            await checkOpenRedirect(scanId, url);
            completed.push('open_redirect');
            updateProgress(scanId, 74, 'http_methods', completed);
        }

        // Phase 4: HTTP methods, file discovery, rate limit (all independent)
        const httpPromise = options.checkHttpMethods
            ? checkHttpMethods(scanId, url).then(() => { completed.push('http_methods'); updateProgress(scanId, 83, 'file_discovery', completed); })
            : Promise.resolve();

        const filePromise = options.checkSensitiveFiles !== false
            ? checkSensitiveFiles(scanId, url, baseline).then(() => { completed.push('file_discovery'); updateProgress(scanId, 92, 'rate_limit', completed); })
            : Promise.resolve();

        const ratePromise = options.checkRateLimit
            ? checkRateLimit(scanId, url).then(() => { completed.push('rate_limit'); })
            : Promise.resolve();

        await Promise.all([httpPromise, filePromise, ratePromise]);

        completed.push('finalization');
        updateProgress(scanId, 95, 'finalization', completed);

        const vulns = stmts.getVulns.all(scanId);
        const { score, level } = computeRiskScore(vulns);
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
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

module.exports = {
    runScan,
    payloadEngine,
    simpleHash,
    extractFingerprint,
    isSoft404,
    htmlDecode,
    headersToObj,
    computeRiskScore,
    checkCspValue,
};
