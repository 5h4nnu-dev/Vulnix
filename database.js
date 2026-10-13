const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, 'secureprobe.db');

const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Schema ──────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    url             TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    risk_score      REAL,
    risk_level      TEXT,
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    critical_count  INTEGER NOT NULL DEFAULT 0,
    high_count      INTEGER NOT NULL DEFAULT 0,
    medium_count    INTEGER NOT NULL DEFAULT 0,
    low_count       INTEGER NOT NULL DEFAULT 0,
    progress        INTEGER NOT NULL DEFAULT 0,
    current_stage   TEXT,
    stages_completed TEXT NOT NULL DEFAULT '[]',
    options         TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at    TEXT
  );

  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                TEXT PRIMARY KEY,
    scan_id           TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    type              TEXT NOT NULL,
    severity          TEXT NOT NULL,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL,
    affected_endpoint TEXT NOT NULL,
    payload           TEXT,
    evidence          TEXT,
    ai_explanation    TEXT,
    exploitation      TEXT,
    remediation       TEXT NOT NULL,
    cvss_score        REAL,
    discovered_at     TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS scan_events (
    id               TEXT PRIMARY KEY,
    scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stage            TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL,
    payload          TEXT,
    request_headers  TEXT,
    response_status  INTEGER,
    response_headers TEXT,
    response_body    TEXT,
    severity         TEXT,
    timestamp        TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
  CREATE INDEX IF NOT EXISTS idx_events_scan ON scan_events(scan_id);

  CREATE TABLE IF NOT EXISTS ai_payloads (
    id                 TEXT PRIMARY KEY,
    scan_id            TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_type          TEXT NOT NULL,
    param              TEXT,
    endpoint           TEXT,
    payload            TEXT NOT NULL,
    payload_type       TEXT,
    rationale          TEXT,
    expected_behavior  TEXT,
    source             TEXT NOT NULL DEFAULT 'ai',
    model              TEXT,
    accepted           INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS prompt_injection_tests (
    id                TEXT PRIMARY KEY,
    scan_id           TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    endpoint          TEXT NOT NULL,
    technique         TEXT NOT NULL,
    probe             TEXT,
    response_excerpt  TEXT,
    detected          INTEGER NOT NULL DEFAULT 0,
    evidence          TEXT,
    severity          TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS agent_steps (
    id                  TEXT PRIMARY KEY,
    scan_id             TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    step_no             INTEGER NOT NULL,
    action              TEXT NOT NULL,
    args_json           TEXT,
    observation_excerpt TEXT,
    injection_flagged   INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_ai_payloads_scan ON ai_payloads(scan_id);
  CREATE INDEX IF NOT EXISTS idx_pi_tests_scan ON prompt_injection_tests(scan_id);
  CREATE INDEX IF NOT EXISTS idx_agent_steps_scan ON agent_steps(scan_id);
`);

// ── Idempotent column migrations ─────────────────────────────────────────────
// SQLite has no "ADD COLUMN IF NOT EXISTS", so inspect the table first.

function addColumnIfMissing(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

addColumnIfMissing('scans', 'mode', "TEXT NOT NULL DEFAULT 'deterministic'");
addColumnIfMissing('scans', 'use_ai', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('scans', 'llm_model', 'TEXT');
addColumnIfMissing('scans', 'prompt_injection_count', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('scans', 'executive_summary', 'TEXT');
addColumnIfMissing('scans', 'hardening_count', 'INTEGER NOT NULL DEFAULT 0');

addColumnIfMissing('vulnerabilities', 'source', "TEXT NOT NULL DEFAULT 'static'");
addColumnIfMissing('vulnerabilities', 'confidence', 'REAL');
addColumnIfMissing('vulnerabilities', 'ai_rationale', 'TEXT');
addColumnIfMissing('vulnerabilities', 'kind', "TEXT NOT NULL DEFAULT 'vulnerability'");

// ── Prepared Statements ─────────────────────────────────────────────────────

const stmts = {
  insertScan: db.prepare(`
    INSERT INTO scans (id, url, status, options, stages_completed, mode, use_ai, llm_model)
    VALUES (@id, @url, @status, @options, @stages_completed, @mode, @use_ai, @llm_model)
  `),

  getScan: db.prepare(`SELECT * FROM scans WHERE id = ?`),

  listScans: db.prepare(`
    SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?
  `),

  countScans: db.prepare(`SELECT COUNT(*) as count FROM scans`),

  updateScanProgress: db.prepare(`
    UPDATE scans SET progress = @progress, current_stage = @current_stage,
    stages_completed = @stages_completed WHERE id = @id
  `),

  updateScanStatus: db.prepare(`
    UPDATE scans SET status = @status WHERE id = @id
  `),

  updateScanRunning: db.prepare(`
    UPDATE scans SET status = 'running', current_stage = 'initialization' WHERE id = ?
  `),

  completeScan: db.prepare(`
    UPDATE scans SET
      status = 'completed', risk_score = @risk_score, risk_level = @risk_level,
      vulnerability_count = @vulnerability_count,
      critical_count = @critical_count, high_count = @high_count,
      medium_count = @medium_count, low_count = @low_count,
      hardening_count = @hardening_count,
      prompt_injection_count = @prompt_injection_count,
      executive_summary = @executive_summary,
      progress = 100, current_stage = NULL,
      stages_completed = @stages_completed, completed_at = datetime('now')
    WHERE id = @id
  `),

  failScan: db.prepare(`
    UPDATE scans SET status = 'failed' WHERE id = ?
  `),

  deleteScan: db.prepare(`DELETE FROM scans WHERE id = ?`),

  insertVuln: db.prepare(`
    INSERT INTO vulnerabilities
      (id, scan_id, type, severity, title, description, affected_endpoint,
       payload, evidence, ai_explanation, exploitation, remediation, cvss_score,
       source, confidence, ai_rationale, kind)
    VALUES
      (@id, @scan_id, @type, @severity, @title, @description, @affected_endpoint,
       @payload, @evidence, @ai_explanation, @exploitation, @remediation, @cvss_score,
       @source, @confidence, @ai_rationale, @kind)
  `),

  getVulns: db.prepare(`
    SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY discovered_at DESC
  `),

  updateVulnAi: db.prepare(`
    UPDATE vulnerabilities
    SET ai_explanation = @ai_explanation,
        exploitation = @exploitation,
        remediation = @remediation,
        confidence = @confidence
    WHERE id = @id
  `),

  insertEvent: db.prepare(`
    INSERT INTO scan_events
      (id, scan_id, stage, event_type, title, description,
       payload, request_headers, response_status, response_headers, response_body, severity)
    VALUES
      (@id, @scan_id, @stage, @event_type, @title, @description,
       @payload, @request_headers, @response_status, @response_headers, @response_body, @severity)
  `),

  getEvents: db.prepare(`
    SELECT * FROM scan_events WHERE scan_id = ? ORDER BY timestamp ASC
  `),

  insertAiPayload: db.prepare(`
    INSERT INTO ai_payloads
      (id, scan_id, vuln_type, param, endpoint, payload, payload_type,
       rationale, expected_behavior, source, model, accepted)
    VALUES
      (@id, @scan_id, @vuln_type, @param, @endpoint, @payload, @payload_type,
       @rationale, @expected_behavior, @source, @model, @accepted)
  `),

  getAiPayloads: db.prepare(`
    SELECT * FROM ai_payloads WHERE scan_id = ? ORDER BY created_at ASC
  `),

  insertPiTest: db.prepare(`
    INSERT INTO prompt_injection_tests
      (id, scan_id, endpoint, technique, probe, response_excerpt, detected, evidence, severity)
    VALUES
      (@id, @scan_id, @endpoint, @technique, @probe, @response_excerpt, @detected, @evidence, @severity)
  `),

  getPiTests: db.prepare(`
    SELECT * FROM prompt_injection_tests WHERE scan_id = ? ORDER BY created_at ASC
  `),

  insertAgentStep: db.prepare(`
    INSERT INTO agent_steps
      (id, scan_id, step_no, action, args_json, observation_excerpt, injection_flagged)
    VALUES
      (@id, @scan_id, @step_no, @action, @args_json, @observation_excerpt, @injection_flagged)
  `),

  getAgentSteps: db.prepare(`
    SELECT * FROM agent_steps WHERE scan_id = ? ORDER BY step_no ASC
  `),

  statsSummary: db.prepare(`
    SELECT
      COUNT(id) as total_scans,
      COALESCE(SUM(vulnerability_count), 0) as total_vulnerabilities,
      COALESCE(SUM(hardening_count), 0) as hardening_count,
      COALESCE(SUM(critical_count), 0) as critical_count,
      COALESCE(SUM(high_count), 0) as high_count,
      COALESCE(SUM(medium_count), 0) as medium_count,
      COALESCE(SUM(low_count), 0) as low_count,
      COALESCE(AVG(risk_score), 0) as avg_risk_score
    FROM scans WHERE status = 'completed'
  `),

  topVulnTypes: db.prepare(`
    SELECT type, COUNT(*) as count
    FROM vulnerabilities GROUP BY type ORDER BY count DESC LIMIT 10
  `),

  recentScans: db.prepare(`
    SELECT * FROM scans ORDER BY created_at DESC LIMIT 5
  `),

  recentVulns: db.prepare(`
    SELECT * FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 10
  `),
};

module.exports = { db, stmts };
