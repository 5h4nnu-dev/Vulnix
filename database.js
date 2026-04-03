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
`);

// ── Prepared Statements ─────────────────────────────────────────────────────

const stmts = {
  insertScan: db.prepare(`
    INSERT INTO scans (id, url, status, options, stages_completed)
    VALUES (@id, @url, @status, @options, @stages_completed)
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
       payload, evidence, ai_explanation, exploitation, remediation, cvss_score)
    VALUES
      (@id, @scan_id, @type, @severity, @title, @description, @affected_endpoint,
       @payload, @evidence, @ai_explanation, @exploitation, @remediation, @cvss_score)
  `),

  getVulns: db.prepare(`
    SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY discovered_at DESC
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

  statsSummary: db.prepare(`
    SELECT
      COUNT(id) as total_scans,
      COALESCE(SUM(vulnerability_count), 0) as total_vulnerabilities,
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
