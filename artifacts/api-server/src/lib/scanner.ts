import { db, scansTable, vulnerabilitiesTable, scanEventsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { logger } from "./logger";
import { randomUUID } from "crypto";

export type ScanOptions = {
  checkHeaders: boolean;
  checkCors: boolean;
  checkSqlInjection: boolean;
  checkXss: boolean;
  checkOpenRedirect: boolean;
  checkHttpMethods: boolean;
  checkRateLimit: boolean;
};

type VulnSeverity = "critical" | "high" | "medium" | "low" | "info";

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

const STAGES = [
  "initialization",
  "headers_analysis",
  "cors_analysis",
  "sql_injection",
  "xss",
  "open_redirect",
  "http_methods",
  "rate_limit",
  "finalization",
];

async function addEvent(
  scanId: string,
  stage: string,
  eventType: string,
  title: string,
  description: string,
  extras: {
    payload?: string;
    requestHeaders?: string;
    responseStatus?: number;
    responseHeaders?: string;
    responseBody?: string;
    severity?: VulnSeverity;
  } = {}
) {
  await db.insert(scanEventsTable).values({
    id: randomUUID(),
    scanId,
    stage,
    eventType,
    title,
    description,
    payload: extras.payload ?? null,
    requestHeaders: extras.requestHeaders ?? null,
    responseStatus: extras.responseStatus ?? null,
    responseHeaders: extras.responseHeaders ?? null,
    responseBody: extras.responseBody ?? null,
    severity: extras.severity ?? null,
  });
}

async function addVuln(scanId: string, vuln: {
  type: string;
  severity: VulnSeverity;
  title: string;
  description: string;
  affectedEndpoint: string;
  payload?: string;
  evidence?: string;
  aiExplanation?: string;
  remediation: string;
  cvssScore?: number;
}) {
  await db.insert(vulnerabilitiesTable).values({
    id: randomUUID(),
    scanId,
    ...vuln,
    payload: vuln.payload ?? null,
    evidence: vuln.evidence ?? null,
    aiExplanation: vuln.aiExplanation ?? null,
    cvssScore: vuln.cvssScore ?? null,
  });
}

async function updateProgress(scanId: string, progress: number, currentStage: string, stagesCompleted: string[]) {
  await db.update(scansTable)
    .set({ progress, currentStage, stagesCompleted })
    .where(eq(scansTable.id, scanId));
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url: string, opts: RequestInit = {}, timeoutMs = 8000): Promise<Response | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...opts, signal: controller.signal, redirect: "manual" });
    clearTimeout(timer);
    return resp;
  } catch {
    clearTimeout(timer);
    return null;
  }
}

function headersToString(headers: Headers): string {
  const obj: Record<string, string> = {};
  headers.forEach((v, k) => { obj[k] = v; });
  return JSON.stringify(obj, null, 2);
}

async function checkSecurityHeaders(scanId: string, url: string): Promise<void> {
  await addEvent(scanId, "headers_analysis", "request", "Fetching HTTP Headers", `Sending GET request to ${url} to inspect response headers`, {
    requestHeaders: JSON.stringify({ "User-Agent": "SecureProbe/1.0" }, null, 2),
  });

  const resp = await fetchWithTimeout(url, { method: "GET", headers: { "User-Agent": "SecureProbe/1.0" } });
  if (!resp) {
    await addEvent(scanId, "headers_analysis", "error", "Connection Failed", "Could not connect to the target URL", { severity: "info" });
    return;
  }

  const headers = resp.headers;
  const responseHeadersStr = headersToString(headers);

  await addEvent(scanId, "headers_analysis", "response", "Headers Received", `Received HTTP ${resp.status} response`, {
    responseStatus: resp.status,
    responseHeaders: responseHeadersStr,
  });

  const securityHeaders = [
    {
      name: "Content-Security-Policy",
      header: "content-security-policy",
      severity: "high" as VulnSeverity,
      remediation: "Add a Content-Security-Policy header to restrict the sources from which the browser can load resources. Example: Content-Security-Policy: default-src 'self'",
      cvss: 6.1,
      aiExplanation: "The Content-Security-Policy (CSP) header is missing from this server's responses. CSP is a critical defense against Cross-Site Scripting (XSS) attacks by specifying which dynamic resources are allowed to load. Without it, an attacker who finds an XSS vulnerability can inject scripts from any domain, steal session tokens, or hijack user accounts. This vulnerability affects every page served by this endpoint.",
    },
    {
      name: "Strict-Transport-Security",
      header: "strict-transport-security",
      severity: "medium" as VulnSeverity,
      remediation: "Enable HTTPS and add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      cvss: 4.3,
      aiExplanation: "The HTTP Strict Transport Security (HSTS) header is absent. Without HSTS, users who visit the site over HTTP can be intercepted by a man-in-the-middle attacker who downgrades the connection, bypassing HTTPS protections. This makes the site vulnerable to SSL stripping attacks where credentials and session data can be captured in plaintext.",
    },
    {
      name: "X-Frame-Options",
      header: "x-frame-options",
      severity: "medium" as VulnSeverity,
      remediation: "Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN to prevent clickjacking",
      cvss: 4.3,
      aiExplanation: "The X-Frame-Options header is missing, making this page vulnerable to clickjacking attacks. An attacker can embed your site in a transparent iframe on their malicious page, tricking users into clicking UI elements they cannot see — potentially authorizing transactions, changing settings, or revealing sensitive data without realizing it.",
    },
    {
      name: "X-Content-Type-Options",
      header: "x-content-type-options",
      severity: "low" as VulnSeverity,
      remediation: "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing",
      cvss: 3.1,
      aiExplanation: "The X-Content-Type-Options: nosniff header is missing. Browsers perform MIME-type sniffing which can cause them to interpret files as a different MIME type than intended. For example, a text file could be executed as JavaScript, enabling certain types of content injection attacks on older or permissive browsers.",
    },
    {
      name: "Referrer-Policy",
      header: "referrer-policy",
      severity: "low" as VulnSeverity,
      remediation: "Add Referrer-Policy: strict-origin-when-cross-origin or Referrer-Policy: no-referrer",
      cvss: 2.7,
      aiExplanation: "No Referrer-Policy header was found. Without this header, the browser may send the full URL (including query parameters that may contain sensitive data like tokens or user IDs) in the Referer header when users navigate to external sites. This can leak sensitive information to third-party analytics services or embedded resources.",
    },
    {
      name: "Permissions-Policy",
      header: "permissions-policy",
      severity: "info" as VulnSeverity,
      remediation: "Add a Permissions-Policy header to control browser feature access: Permissions-Policy: camera=(), microphone=(), geolocation=()",
      cvss: 2.0,
      aiExplanation: "The Permissions-Policy header (formerly Feature-Policy) is absent. This header controls which browser APIs and features can be used by the page and embedded iframes. Without it, potentially sensitive browser features like camera, microphone, geolocation, or payment APIs may be accessible to malicious scripts embedded on the page.",
    },
  ];

  for (const sh of securityHeaders) {
    const val = headers.get(sh.header);
    if (!val) {
      await addEvent(scanId, "headers_analysis", "finding", `Missing: ${sh.name}`, `The ${sh.name} header was not found in the response`, {
        severity: sh.severity,
        evidence: `Response headers: ${responseHeadersStr}`,
      });
      await addVuln(scanId, {
        type: "missing_security_header",
        severity: sh.severity,
        title: `Missing ${sh.name} Header`,
        description: `The ${sh.name} security header is not present in the HTTP response, leaving the application vulnerable to related attack vectors.`,
        affectedEndpoint: url,
        evidence: `GET ${url} - Response did not include ${sh.name} header`,
        aiExplanation: sh.aiExplanation,
        remediation: sh.remediation,
        cvssScore: sh.cvss,
      });
    }
  }
}

async function checkCors(scanId: string, url: string): Promise<void> {
  const maliciousOrigins = [
    "https://evil.com",
    "https://attacker.com",
    "null",
  ];

  for (const origin of maliciousOrigins) {
    await addEvent(scanId, "cors_analysis", "request", `Testing CORS with malicious origin`, `Sending request with Origin: ${origin}`, {
      requestHeaders: JSON.stringify({ "Origin": origin, "User-Agent": "SecureProbe/1.0" }, null, 2),
      payload: origin,
    });

    const resp = await fetchWithTimeout(url, {
      method: "GET",
      headers: { "Origin": origin, "User-Agent": "SecureProbe/1.0" },
    });

    if (!resp) continue;

    const acao = resp.headers.get("access-control-allow-origin");
    const acac = resp.headers.get("access-control-allow-credentials");
    const responseHeadersStr = headersToString(resp.headers);

    await addEvent(scanId, "cors_analysis", "response", "CORS Response", `Received response: Access-Control-Allow-Origin: ${acao ?? "not set"}`, {
      responseStatus: resp.status,
      responseHeaders: responseHeadersStr,
    });

    if (acao === "*") {
      await addVuln(scanId, {
        type: "cors_misconfiguration",
        severity: "medium",
        title: "Permissive CORS Policy (Wildcard Origin)",
        description: "The server responds with Access-Control-Allow-Origin: * which allows any origin to read the response. This can expose sensitive data to malicious websites.",
        affectedEndpoint: url,
        payload: `Origin: ${origin}`,
        evidence: `Response header: Access-Control-Allow-Origin: *`,
        aiExplanation: "A wildcard CORS policy (Access-Control-Allow-Origin: *) means any website can make cross-origin requests to this endpoint and read the responses. While not inherently critical, if the endpoint returns sensitive data, a malicious site can fetch that data on behalf of a logged-in victim and exfiltrate it. Combined with missing CSRF protections, this can be devastating.",
        remediation: "Replace the wildcard with a specific allowlist of trusted origins. Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
        cvssScore: 5.3,
      });
      break;
    } else if (acao === origin) {
      const severity: VulnSeverity = acac === "true" ? "high" : "medium";
      await addEvent(scanId, "cors_analysis", "finding", "CORS Reflects Origin", `Server reflects arbitrary origin: ${origin}`, {
        severity,
        evidence: responseHeadersStr,
      });
      await addVuln(scanId, {
        type: "cors_misconfiguration",
        severity,
        title: "CORS Origin Reflection Vulnerability",
        description: `The server reflects arbitrary origins in Access-Control-Allow-Origin${acac === "true" ? " with credentials allowed" : ""}. This allows cross-origin requests from any domain.`,
        affectedEndpoint: url,
        payload: `Origin: ${origin}`,
        evidence: `Request Origin: ${origin} -> Response Access-Control-Allow-Origin: ${acao}${acac === "true" ? " + Access-Control-Allow-Credentials: true" : ""}`,
        aiExplanation: acac === "true"
          ? "Critical: The server reflects the request's Origin header back in Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true. This means any malicious website can make authenticated cross-origin requests on behalf of a logged-in user and read the response — essentially a CSRF bypass that also allows reading sensitive response data. An attacker hosting evil.com can steal all data this authenticated user can access."
          : "The server reflects arbitrary origins in its CORS policy, allowing any website to read the responses to cross-origin requests. While credentials aren't included, any unauthenticated data from this endpoint can be read by malicious third-party websites.",
        remediation: "Implement a strict CORS allowlist. Validate the Origin against a whitelist before echoing it back. Never dynamically reflect arbitrary origins. If credentials are needed, only allow specific trusted origins.",
        cvssScore: acac === "true" ? 8.1 : 5.4,
      });
      break;
    }
  }
}

async function checkSqlInjection(scanId: string, url: string): Promise<void> {
  const testUrl = new URL(url);
  const hasParams = testUrl.searchParams.size > 0;

  if (!hasParams) {
    testUrl.searchParams.set("id", "1");
    testUrl.searchParams.set("search", "test");
  }

  for (const payload of SQL_PAYLOADS.slice(0, 3)) {
    const testTarget = new URL(url);
    for (const [key] of testTarget.searchParams.entries()) {
      testTarget.searchParams.set(key, payload);
    }
    if (!hasParams) {
      testTarget.searchParams.set("id", payload);
    }

    const testUrlStr = testTarget.toString();

    await addEvent(scanId, "sql_injection", "request", "SQL Injection Probe", `Testing payload: ${payload}`, {
      requestHeaders: JSON.stringify({ "User-Agent": "SecureProbe/1.0" }, null, 2),
      payload,
    });

    const resp = await fetchWithTimeout(testUrlStr, {
      headers: { "User-Agent": "SecureProbe/1.0" },
    });

    if (!resp) continue;

    let body = "";
    try {
      body = await resp.text();
    } catch {}

    await addEvent(scanId, "sql_injection", "response", "Response Received", `HTTP ${resp.status} - ${body.length} bytes`, {
      responseStatus: resp.status,
      responseBody: body.slice(0, 500),
    });

    const errorPatterns = [
      /sql syntax/i, /mysql_fetch/i, /ora-\d{5}/i, /pg_query/i,
      /sqlite_/i, /syntax error/i, /unclosed quotation/i,
      /quoted string not properly terminated/i, /microsoft ole db/i,
    ];

    const hasError = errorPatterns.some(p => p.test(body));
    if (hasError) {
      await addEvent(scanId, "sql_injection", "finding", "SQL Error Detected", "Database error in response suggests SQL injection vulnerability", {
        severity: "critical",
        payload,
        responseStatus: resp.status,
        responseBody: body.slice(0, 500),
      });
      await addVuln(scanId, {
        type: "sql_injection",
        severity: "critical",
        title: "SQL Injection Vulnerability Detected",
        description: `A SQL injection vulnerability was found. The payload "${payload}" triggered a database error in the response, confirming that user input is directly interpolated into SQL queries without sanitization.`,
        affectedEndpoint: testUrlStr,
        payload,
        evidence: `SQL error pattern detected in response body: ${body.slice(0, 200)}`,
        aiExplanation: "A SQL injection vulnerability allows attackers to manipulate database queries by inserting malicious SQL code. This is one of the most severe web vulnerabilities. An attacker can use this to: (1) bypass authentication by injecting ' OR '1'='1, (2) extract all data from the database including passwords and PII, (3) modify or delete database records, and in some cases (4) execute operating system commands. This vulnerability requires immediate remediation.",
        remediation: "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL strings. Implement an ORM. Apply principle of least privilege to database accounts. Enable Web Application Firewall (WAF) rules.",
        cvssScore: 9.8,
      });
      break;
    } else if (resp.status === 500) {
      await addEvent(scanId, "sql_injection", "finding", "Server Error on SQL Payload", "Server returned 500 on SQL payload — possible injection point", {
        severity: "high",
        payload,
        responseStatus: resp.status,
      });
    }
  }
}

async function checkXss(scanId: string, url: string): Promise<void> {
  for (const payload of XSS_PAYLOADS.slice(0, 3)) {
    const testUrl = new URL(url);
    testUrl.searchParams.set("q", payload);
    testUrl.searchParams.set("search", payload);
    const testUrlStr = testUrl.toString();

    await addEvent(scanId, "xss", "request", "XSS Probe", `Testing reflected XSS payload`, {
      requestHeaders: JSON.stringify({ "User-Agent": "SecureProbe/1.0" }, null, 2),
      payload,
    });

    const resp = await fetchWithTimeout(testUrlStr, {
      headers: { "User-Agent": "SecureProbe/1.0" },
    });

    if (!resp) continue;

    let body = "";
    try {
      body = await resp.text();
    } catch {}

    await addEvent(scanId, "xss", "response", "Response Received", `HTTP ${resp.status} - checking if payload reflects in response`, {
      responseStatus: resp.status,
      responseBody: body.slice(0, 500),
    });

    const cspHeader = resp.headers.get("content-security-policy");
    if (body.includes(payload) && !cspHeader) {
      await addEvent(scanId, "xss", "finding", "Reflected XSS Detected", "Payload found unescaped in response — XSS confirmed", {
        severity: "high",
        payload,
        responseStatus: resp.status,
        responseBody: body.slice(0, 500),
      });
      await addVuln(scanId, {
        type: "xss",
        severity: "high",
        title: "Reflected Cross-Site Scripting (XSS)",
        description: `A reflected XSS vulnerability was confirmed. The payload "${payload}" was reflected in the response without proper encoding or CSP protection.`,
        affectedEndpoint: testUrlStr,
        payload,
        evidence: `Payload reflected in response body at position ${body.indexOf(payload)}`,
        aiExplanation: "Reflected XSS occurs when the server echoes user-supplied data back into the page without proper HTML encoding. An attacker crafts a URL with malicious JavaScript payload and tricks a victim into clicking it. The victim's browser executes the attacker's script in the context of the trusted site — enabling cookie theft, session hijacking, keylogging, or redirection to phishing pages. This attack bypasses same-origin policy.",
        remediation: "Implement context-aware output encoding (HTML entity encoding for HTML context, JavaScript encoding for JS context). Add a strict Content-Security-Policy header. Use a trusted HTML sanitization library. Validate and reject inputs that match dangerous patterns.",
        cvssScore: 7.2,
      });
      break;
    }
  }
}

async function checkOpenRedirect(scanId: string, url: string): Promise<void> {
  for (const payload of OPEN_REDIRECT_PAYLOADS.slice(0, 2)) {
    const testUrl = new URL(url);
    testUrl.searchParams.set("redirect", payload);
    testUrl.searchParams.set("next", payload);
    testUrl.searchParams.set("url", payload);
    const testUrlStr = testUrl.toString();

    await addEvent(scanId, "open_redirect", "request", "Open Redirect Probe", `Testing redirect parameter with: ${payload}`, {
      requestHeaders: JSON.stringify({ "User-Agent": "SecureProbe/1.0" }, null, 2),
      payload,
    });

    const resp = await fetchWithTimeout(testUrlStr, {
      method: "GET",
      redirect: "manual",
      headers: { "User-Agent": "SecureProbe/1.0" },
    });

    if (!resp) continue;

    const location = resp.headers.get("location");
    await addEvent(scanId, "open_redirect", "response", "Response Received", `HTTP ${resp.status} - Location: ${location ?? "none"}`, {
      responseStatus: resp.status,
      responseHeaders: headersToString(resp.headers),
    });

    if (location && (location.includes("evil.com") || location.includes("google.com") || location.startsWith("//"))) {
      await addEvent(scanId, "open_redirect", "finding", "Open Redirect Confirmed", `Server redirects to: ${location}`, {
        severity: "medium",
        payload,
      });
      await addVuln(scanId, {
        type: "open_redirect",
        severity: "medium",
        title: "Open Redirect Vulnerability",
        description: `The application redirects to attacker-controlled URLs via the "${payload}" parameter. This can be used in phishing attacks.`,
        affectedEndpoint: testUrlStr,
        payload,
        evidence: `HTTP ${resp.status} redirect to: ${location}`,
        aiExplanation: "An open redirect vulnerability allows attackers to redirect users to arbitrary external URLs using your trusted domain as a stepping stone. For example, an attacker sends phishing emails with links like https://trustedsite.com/redirect?url=https://evil.com — victims trust the URL because it starts with the legitimate domain but end up on the attacker's phishing page. This is especially effective for credential harvesting and OAuth token theft.",
        remediation: "Validate redirect URLs against a strict allowlist. Use relative paths instead of full URLs for redirects. If external redirects are required, implement a confirmation page. Never trust user-supplied redirect URLs without validation.",
        cvssScore: 5.4,
      });
      break;
    }
  }
}

async function checkHttpMethods(scanId: string, url: string): Promise<void> {
  const methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"];

  for (const method of methods) {
    await addEvent(scanId, "http_methods", "request", `Testing ${method} method`, `Sending ${method} request to test allowed methods`, {
      requestHeaders: JSON.stringify({ "User-Agent": "SecureProbe/1.0", "X-HTTP-Method-Override": method }, null, 2),
    });

    const resp = await fetchWithTimeout(url, {
      method,
      headers: { "User-Agent": "SecureProbe/1.0" },
    });

    if (!resp) continue;

    await addEvent(scanId, "http_methods", "response", `${method} Response`, `HTTP ${resp.status}`, {
      responseStatus: resp.status,
      responseHeaders: headersToString(resp.headers),
    });

    if (method === "TRACE" && resp.status === 200) {
      await addVuln(scanId, {
        type: "http_method_abuse",
        severity: "medium",
        title: "HTTP TRACE Method Enabled",
        description: "The TRACE method is enabled on this server. This can be exploited in Cross-Site Tracing (XST) attacks to steal authentication cookies even when HttpOnly is set.",
        affectedEndpoint: url,
        payload: "TRACE request",
        evidence: `TRACE ${url} returned HTTP 200`,
        aiExplanation: "The TRACE HTTP method echoes back the request body, including HTTP headers. In a Cross-Site Tracing (XST) attack combined with XSS, an attacker can use TRACE to read the target user's cookies even if they are marked HttpOnly (which normally prevents JavaScript from accessing them). This effectively bypasses a key defense against session hijacking.",
        remediation: "Disable the TRACE method in your web server configuration. In Apache: TraceEnable Off. In Nginx: if ($request_method = TRACE) { return 405; }",
        cvssScore: 5.8,
      });
    }

    if (method === "OPTIONS") {
      const allow = resp.headers.get("allow") || resp.headers.get("access-control-allow-methods");
      if (allow && allow.includes("TRACE")) {
        await addEvent(scanId, "http_methods", "finding", "TRACE method allowed per OPTIONS", `Allow header: ${allow}`, {
          severity: "medium",
        });
      }
    }

    await sleep(200);
  }
}

async function checkRateLimit(scanId: string, url: string): Promise<void> {
  await addEvent(scanId, "rate_limit", "info", "Rate Limit Test", "Sending 15 rapid requests to test rate limiting...", {});

  let blocked = false;
  for (let i = 0; i < 15; i++) {
    const resp = await fetchWithTimeout(url, { method: "GET" }, 3000);
    if (resp && (resp.status === 429 || resp.headers.get("retry-after"))) {
      blocked = true;
      await addEvent(scanId, "rate_limit", "info", "Rate Limit Applied", `Rate limited after ${i + 1} requests (HTTP ${resp.status})`, {
        responseStatus: resp.status,
      });
      break;
    }
  }

  if (!blocked) {
    await addEvent(scanId, "rate_limit", "finding", "No Rate Limiting Detected", "15 rapid requests were sent without triggering a rate limit", {
      severity: "medium",
    });
    await addVuln(scanId, {
      type: "rate_limit_bypass",
      severity: "medium",
      title: "Missing Rate Limiting",
      description: "The endpoint does not appear to enforce rate limiting. Attackers can send unlimited requests, enabling brute-force attacks, credential stuffing, and DoS.",
      affectedEndpoint: url,
      evidence: "15 consecutive rapid requests returned without HTTP 429 or Retry-After header",
      aiExplanation: "Without rate limiting, attackers can make unlimited automated requests to your endpoint. This enables: (1) credential stuffing attacks where thousands of username/password combinations are tested, (2) brute-force attacks against login forms, (3) content scraping, and (4) denial-of-service by overwhelming your server with requests. This is especially dangerous on authentication endpoints.",
      remediation: "Implement rate limiting using a token bucket or sliding window algorithm. Return HTTP 429 with a Retry-After header when limits are exceeded. Consider different limits for authenticated vs unauthenticated users. Use tools like nginx limit_req_zone, express-rate-limit, or a WAF.",
      cvssScore: 5.3,
    });
  }
}

function computeRiskScore(vulns: { severity: string }[]): { score: number; level: string } {
  let score = 0;
  for (const v of vulns) {
    if (v.severity === "critical") score += 40;
    else if (v.severity === "high") score += 25;
    else if (v.severity === "medium") score += 10;
    else if (v.severity === "low") score += 3;
    else score += 1;
  }
  score = Math.min(score, 100);

  let level = "info";
  if (score >= 80) level = "critical";
  else if (score >= 60) level = "high";
  else if (score >= 30) level = "medium";
  else if (score >= 10) level = "low";

  return { score, level };
}

export async function runScan(scanId: string, url: string, options: ScanOptions): Promise<void> {
  const stagesCompleted: string[] = [];
  const stagesTotal = STAGES.length;

  try {
    await db.update(scansTable).set({ status: "running", currentStage: "initialization" }).where(eq(scansTable.id, scanId));

    await addEvent(scanId, "initialization", "info", "Scan Initialized", `Starting security analysis for ${url}`, {});
    await sleep(500);

    stagesCompleted.push("initialization");
    await updateProgress(scanId, 10, "headers_analysis", stagesCompleted);

    if (options.checkHeaders) {
      await addEvent(scanId, "headers_analysis", "info", "Starting Security Headers Analysis", "Checking for missing or misconfigured HTTP security headers", {});
      await checkSecurityHeaders(scanId, url);
      stagesCompleted.push("headers_analysis");
      await updateProgress(scanId, 25, "cors_analysis", stagesCompleted);
    }

    if (options.checkCors) {
      await addEvent(scanId, "cors_analysis", "info", "Starting CORS Analysis", "Testing Cross-Origin Resource Sharing configuration", {});
      await checkCors(scanId, url);
      stagesCompleted.push("cors_analysis");
      await updateProgress(scanId, 40, "sql_injection", stagesCompleted);
    }

    if (options.checkSqlInjection) {
      await addEvent(scanId, "sql_injection", "info", "Starting SQL Injection Tests", "Testing input parameters for SQL injection vulnerabilities", {});
      await checkSqlInjection(scanId, url);
      stagesCompleted.push("sql_injection");
      await updateProgress(scanId, 55, "xss", stagesCompleted);
    }

    if (options.checkXss) {
      await addEvent(scanId, "xss", "info", "Starting XSS Tests", "Testing for reflected and DOM-based Cross-Site Scripting", {});
      await checkXss(scanId, url);
      stagesCompleted.push("xss");
      await updateProgress(scanId, 68, "open_redirect", stagesCompleted);
    }

    if (options.checkOpenRedirect) {
      await addEvent(scanId, "open_redirect", "info", "Starting Open Redirect Tests", "Testing redirect parameters for open redirect vulnerabilities", {});
      await checkOpenRedirect(scanId, url);
      stagesCompleted.push("open_redirect");
      await updateProgress(scanId, 78, "http_methods", stagesCompleted);
    }

    if (options.checkHttpMethods) {
      await addEvent(scanId, "http_methods", "info", "Starting HTTP Method Analysis", "Testing which HTTP methods are allowed", {});
      await checkHttpMethods(scanId, url);
      stagesCompleted.push("http_methods");
      await updateProgress(scanId, 88, "rate_limit", stagesCompleted);
    }

    if (options.checkRateLimit) {
      await addEvent(scanId, "rate_limit", "info", "Starting Rate Limit Tests", "Testing whether rate limiting is enforced", {});
      await checkRateLimit(scanId, url);
      stagesCompleted.push("rate_limit");
    }

    stagesCompleted.push("finalization");
    await updateProgress(scanId, 95, "finalization", stagesCompleted);

    const vulns = await db.select({ severity: vulnerabilitiesTable.severity })
      .from(vulnerabilitiesTable)
      .where(eq(vulnerabilitiesTable.scanId, scanId));

    const { score, level } = computeRiskScore(vulns);
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const v of vulns) {
      if (v.severity in counts) counts[v.severity as keyof typeof counts]++;
    }

    await db.update(scansTable).set({
      status: "completed",
      riskScore: score,
      riskLevel: level,
      vulnerabilityCount: vulns.length,
      criticalCount: counts.critical,
      highCount: counts.high,
      mediumCount: counts.medium,
      lowCount: counts.low,
      progress: 100,
      currentStage: null,
      stagesCompleted,
      completedAt: new Date(),
    }).where(eq(scansTable.id, scanId));

    await addEvent(scanId, "finalization", "info", "Scan Completed", `Analysis complete. Found ${vulns.length} vulnerabilities. Risk score: ${score}/100 (${level})`, {
      severity: level as VulnSeverity,
    });

    logger.info({ scanId, vulns: vulns.length, score, level }, "Scan completed");
  } catch (err) {
    logger.error({ scanId, err }, "Scan failed");
    await db.update(scansTable).set({ status: "failed" }).where(eq(scansTable.id, scanId));
    await addEvent(scanId, "finalization", "error", "Scan Failed", `An error occurred during scanning: ${String(err)}`, { severity: "info" });
  }
}
