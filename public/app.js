// ═══════════════════════════════════════════════════════════════════════════
// SecureProbe v2.0 — Frontend Application
// ═══════════════════════════════════════════════════════════════════════════

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ── State ─────────────────────────────────────────────────────────────────

let currentScanId = null;
let pollInterval = null;

// ── Navigation ────────────────────────────────────────────────────────────

function navigateTo(page, data) {
  $$('.page').forEach((p) => p.classList.remove('active'));
  $$('.nav-item').forEach((n) => n.classList.remove('active'));

  const pageEl = $(`#page-${page}`);
  const navEl = $(`[data-page="${page}"]`);

  if (pageEl) pageEl.classList.add('active');
  if (navEl) navEl.classList.add('active');

  if (page === 'dashboard') loadDashboard();
  if (page === 'history') loadHistory();
  if (page === 'scan-detail' && data?.id) loadScanDetail(data.id);
}

$$('.nav-item').forEach((item) => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    navigateTo(item.dataset.page);
  });
});

// ── API Helpers ───────────────────────────────────────────────────────────

async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(`/api${path}`, opts);
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || err.message || 'Request failed');
  }
  if (resp.status === 204) return null;
  return resp.json();
}

// ── Utility ───────────────────────────────────────────────────────────────

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatDate(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr + (dateStr.includes('Z') || dateStr.includes('+') ? '' : 'Z'));
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) +
    ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
}

function severityBadge(severity) {
  return `<span class="badge badge-${severity}">${severity}</span>`;
}

function statusBadge(status) {
  return `<span class="badge badge-${status}">${status}</span>`;
}

function riskPill(score, level) {
  if (score == null) return '<span class="risk-score-pill" style="background:var(--bg-elevated);color:var(--text-muted)">—</span>';
  const colors = {
    critical: 'rgba(239,68,68,0.15);color:var(--sev-critical)',
    high: 'rgba(249,115,22,0.15);color:var(--sev-high)',
    medium: 'rgba(234,179,8,0.15);color:var(--sev-medium)',
    low: 'rgba(59,130,246,0.15);color:var(--sev-low)',
    info: 'rgba(100,116,139,0.15);color:var(--sev-info)',
  };
  return `<span class="risk-score-pill" style="background:${colors[level] || colors.info}">${Math.round(score)}/100</span>`;
}

function truncateUrl(url, maxLen = 50) {
  if (!url) return '';
  try {
    const u = new URL(url);
    const display = u.hostname + u.pathname;
    return display.length > maxLen ? display.slice(0, maxLen) + '…' : display;
  } catch {
    return url.length > maxLen ? url.slice(0, maxLen) + '…' : url;
  }
}

// ── Dashboard ─────────────────────────────────────────────────────────────

async function loadDashboard() {
  try {
    const [stats, activity] = await Promise.all([
      api('GET', '/stats/summary'),
      api('GET', '/stats/recent-activity'),
    ]);

    $('#stat-total-scans').textContent = stats.total_scans || 0;
    $('#stat-total-vulns').textContent = stats.total_vulnerabilities || 0;
    $('#stat-avg-risk').textContent = stats.avg_risk_score ? Math.round(stats.avg_risk_score) + '/100' : '—';
    $('#stat-critical-count').textContent = stats.critical_count || 0;

    // Recent scans
    const recentList = $('#recent-scans-list');
    if (!activity.recent_scans || activity.recent_scans.length === 0) {
      recentList.innerHTML = '<div class="empty-state">No scans yet. Start your first scan!</div>';
    } else {
      recentList.innerHTML = activity.recent_scans.map((s) => `
        <div class="scan-list-item" onclick="navigateTo('scan-detail', { id: '${s.id}' })">
          <div class="scan-list-url">${escapeHtml(truncateUrl(s.url))}</div>
          <div class="scan-list-meta">
            ${statusBadge(s.status)}
            ${riskPill(s.risk_score, s.risk_level)}
            <span>${formatDate(s.created_at)}</span>
          </div>
        </div>
      `).join('');
    }

    // Vulnerability breakdown
    const breakdown = $('#vuln-breakdown');
    const sevCounts = [
      { label: 'Critical', count: stats.critical_count || 0, color: 'var(--sev-critical)' },
      { label: 'High', count: stats.high_count || 0, color: 'var(--sev-high)' },
      { label: 'Medium', count: stats.medium_count || 0, color: 'var(--sev-medium)' },
      { label: 'Low', count: stats.low_count || 0, color: 'var(--sev-low)' },
    ];
    const maxCount = Math.max(...sevCounts.map((s) => s.count), 1);

    if (stats.total_vulnerabilities === 0) {
      breakdown.innerHTML = '<div class="empty-state">No vulnerabilities found yet.</div>';
    } else {
      breakdown.innerHTML = sevCounts.map((s) => `
        <div class="vuln-bar-item">
          <span class="vuln-bar-label">${s.label}</span>
          <div class="vuln-bar-track">
            <div class="vuln-bar-fill" style="width:${(s.count / maxCount) * 100}%;background:${s.color}"></div>
          </div>
          <span class="vuln-bar-count" style="color:${s.color}">${s.count}</span>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error('Dashboard load failed:', err);
  }
}

// ── New Scan ──────────────────────────────────────────────────────────────

$('#btn-start-scan').addEventListener('click', startScan);
$('#scan-url-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') startScan();
});

async function startScan() {
  const urlInput = $('#scan-url-input');
  const url = urlInput.value.trim();
  if (!url) { urlInput.focus(); return; }

  const options = {
    checkHeaders: $('#opt-headers').checked,
    checkCors: $('#opt-cors').checked,
    checkSqlInjection: $('#opt-sqli').checked,
    checkXss: $('#opt-xss').checked,
    checkOpenRedirect: $('#opt-redirect').checked,
    checkHttpMethods: $('#opt-methods').checked,
    checkRateLimit: $('#opt-ratelimit').checked,
    checkSensitiveFiles: $('#opt-files').checked,
  };

  const btn = $('#btn-start-scan');
  btn.disabled = true;
  btn.innerHTML = `<span class="pulse-dot"></span> Starting…`;

  try {
    const scan = await api('POST', '/scans', { url, options });
    currentScanId = scan.id;

    // Show progress UI
    const progressCard = $('#scan-progress-card');
    progressCard.classList.remove('hidden');
    $('#scan-progress-bar').style.width = '0%';
    $('#scan-progress-percent').textContent = '0%';
    $('#scan-status-text').textContent = 'Scanning…';
    $('#scan-stage-text').textContent = 'Initializing…';
    $('#scan-live-events').innerHTML = '';

    // Start polling
    startPolling(scan.id);
  } catch (err) {
    alert('Failed to start scan: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      Start Scan`;
  }
}

function startPolling(scanId) {
  stopPolling();
  let lastEventCount = 0;

  pollInterval = setInterval(async () => {
    try {
      const status = await api('GET', `/scans/${scanId}/status`);

      $('#scan-progress-bar').style.width = status.progress + '%';
      $('#scan-progress-percent').textContent = status.progress + '%';
      $('#scan-stage-text').textContent = formatStage(status.current_stage || 'finalizing');

      // Fetch recent events
      const { events } = await api('GET', `/scans/${scanId}/events`);
      if (events.length > lastEventCount) {
        const container = $('#scan-live-events');
        const newEvents = events.slice(lastEventCount);
        for (const e of newEvents) {
          const div = document.createElement('div');
          div.className = `live-event ${e.event_type}`;
          div.textContent = `[${e.stage}] ${e.title}`;
          container.prepend(div);
        }
        lastEventCount = events.length;
        // Keep only last 20
        while (container.children.length > 20) {
          container.removeChild(container.lastChild);
        }
      }

      if (status.status === 'completed' || status.status === 'failed') {
        stopPolling();
        $('#scan-status-text').textContent = status.status === 'completed' ? 'Scan Complete!' : 'Scan Failed';
        $('#scan-progress-bar').style.width = '100%';
        $('#scan-progress-percent').textContent = '100%';

        // Navigate to detail after a short delay
        setTimeout(() => {
          navigateTo('scan-detail', { id: scanId });
          // Reset scan form
          $('#scan-progress-card').classList.add('hidden');
          $('#scan-url-input').value = '';
        }, 1500);
      }
    } catch {
      // Silently retry
    }
  }, 1500);
}

function stopPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

function formatStage(stage) {
  return (stage || '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

// ── Scan History ──────────────────────────────────────────────────────────

async function loadHistory() {
  const container = $('#history-list');
  container.innerHTML = '<div class="empty-state">Loading…</div>';

  try {
    const { scans, total } = await api('GET', '/scans?limit=50');

    if (!scans || scans.length === 0) {
      container.innerHTML = '<div class="empty-state">No scans yet. Run your first scan!</div>';
      return;
    }

    container.innerHTML = scans.map((s) => `
      <div class="scan-list-item" onclick="navigateTo('scan-detail', { id: '${s.id}' })">
        <div class="scan-list-url">${escapeHtml(truncateUrl(s.url, 60))}</div>
        <div class="scan-list-meta">
          ${statusBadge(s.status)}
          ${riskPill(s.risk_score, s.risk_level)}
          <span>${s.vulnerability_count} vulns</span>
          <span>${formatDate(s.created_at)}</span>
        </div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<div class="empty-state">Failed to load: ${escapeHtml(err.message)}</div>`;
  }
}

// ── Scan Detail ───────────────────────────────────────────────────────────

async function loadScanDetail(scanId) {
  currentScanId = scanId;
  const infoContainer = $('#detail-scan-info');
  const vulnsContainer = $('#detail-vulns-section');
  const eventsContainer = $('#detail-events-section');

  infoContainer.innerHTML = '<div class="empty-state">Loading…</div>';
  vulnsContainer.innerHTML = '';
  eventsContainer.innerHTML = '';

  try {
    const { scan, vulnerabilities, events } = await api('GET', `/scans/${scanId}`);

    // Info grid
    infoContainer.innerHTML = `
      <div class="detail-info-grid">
        <div class="detail-info-item">
          <div class="detail-info-label">Target URL</div>
          <div class="detail-info-value mono">${escapeHtml(scan.url)}</div>
        </div>
        <div class="detail-info-item">
          <div class="detail-info-label">Status</div>
          <div class="detail-info-value">${statusBadge(scan.status)}</div>
        </div>
        <div class="detail-info-item">
          <div class="detail-info-label">Risk Score</div>
          <div class="detail-info-value">${riskPill(scan.risk_score, scan.risk_level)}</div>
        </div>
        <div class="detail-info-item">
          <div class="detail-info-label">Vulnerabilities</div>
          <div class="detail-info-value">${scan.vulnerability_count || 0}</div>
        </div>
        <div class="detail-info-item">
          <div class="detail-info-label">Scanned</div>
          <div class="detail-info-value" style="font-size:0.85rem">${formatDate(scan.created_at)}</div>
        </div>
        <div class="detail-info-item">
          <div class="detail-info-label">Completed</div>
          <div class="detail-info-value" style="font-size:0.85rem">${formatDate(scan.completed_at)}</div>
        </div>
      </div>

      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
        ${scan.critical_count ? `<span class="badge badge-critical">${scan.critical_count} Critical</span>` : ''}
        ${scan.high_count ? `<span class="badge badge-high">${scan.high_count} High</span>` : ''}
        ${scan.medium_count ? `<span class="badge badge-medium">${scan.medium_count} Medium</span>` : ''}
        ${scan.low_count ? `<span class="badge badge-low">${scan.low_count} Low</span>` : ''}
      </div>
    `;

    // Vulnerabilities
    if (vulnerabilities && vulnerabilities.length > 0) {
      vulnsContainer.innerHTML = `
        <h2 style="font-size:1.1rem;font-weight:700;margin:24px 0 16px;color:var(--text-secondary)">
          Vulnerabilities (${vulnerabilities.length})
        </h2>
        ${vulnerabilities.map((v, i) => renderVulnCard(v, i)).join('')}
      `;
    } else {
      vulnsContainer.innerHTML = `
        <div class="card" style="margin-top:24px">
          <div class="card-body">
            <div class="empty-state" style="color:var(--success)">
              ✅ No vulnerabilities found!
            </div>
          </div>
        </div>
      `;
    }

    // Events timeline
    if (events && events.length > 0) {
      eventsContainer.innerHTML = `
        <div class="events-section">
          <h2>Scan Timeline (${events.length} events)</h2>
          <div class="events-timeline">
            ${events.map((e) => `
              <div class="event-item ${e.event_type}">
                <div class="event-title">${escapeHtml(e.title)}</div>
                <div class="event-desc">${escapeHtml(e.description)}</div>
                <div class="event-time">${e.stage} · ${formatDate(e.timestamp)}</div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    // If still running, poll
    if (scan.status === 'running' || scan.status === 'pending') {
      startDetailPolling(scanId);
    }

  } catch (err) {
    infoContainer.innerHTML = `<div class="empty-state">Failed to load: ${escapeHtml(err.message)}</div>`;
  }
}

function renderVulnCard(v, index) {
  return `
    <div class="vuln-card" id="vuln-${index}">
      <div class="vuln-card-header" onclick="toggleVuln(${index})">
        <div class="vuln-sev-bar ${v.severity}"></div>
        <div class="vuln-card-info">
          <div class="vuln-card-title">${escapeHtml(v.title)}</div>
          <div class="vuln-card-endpoint">${escapeHtml(v.affected_endpoint)}</div>
        </div>
        <div class="vuln-card-badges">
          ${severityBadge(v.severity)}
          ${v.cvss_score != null ? `<span class="badge badge-info">CVSS ${v.cvss_score}</span>` : ''}
        </div>
      </div>
      <div class="vuln-card-body">
        <div class="vuln-section">
          <div class="vuln-section-title">Description</div>
          <div class="vuln-section-content">${escapeHtml(v.description)}</div>
        </div>
        ${v.payload ? `
          <div class="vuln-section">
            <div class="vuln-section-title">Payload</div>
            <div class="vuln-payload">${escapeHtml(v.payload)}</div>
          </div>
        ` : ''}
        ${v.evidence ? `
          <div class="vuln-section">
            <div class="vuln-section-title">Evidence</div>
            <div class="vuln-evidence">${escapeHtml(v.evidence)}</div>
          </div>
        ` : ''}
        ${v.ai_explanation ? `
          <div class="vuln-section">
            <div class="vuln-section-title">Detailed Analysis</div>
            <div class="vuln-section-content">${escapeHtml(v.ai_explanation)}</div>
          </div>
        ` : ''}
        ${v.exploitation ? `
          <div class="vuln-section">
            <div class="vuln-section-title">Possible Exploit</div>
            <div class="vuln-section-content">${escapeHtml(v.exploitation)}</div>
          </div>
        ` : ''}
        <div class="vuln-section">
          <div class="vuln-section-title">Remediation</div>
          <div class="vuln-remediation">${escapeHtml(v.remediation)}</div>
        </div>
      </div>
    </div>
  `;
}

function toggleVuln(index) {
  const card = $(`#vuln-${index}`);
  if (card) card.classList.toggle('open');
}

function startDetailPolling(scanId) {
  stopPolling();
  pollInterval = setInterval(async () => {
    try {
      const status = await api('GET', `/scans/${scanId}/status`);
      if (status.status === 'completed' || status.status === 'failed') {
        stopPolling();
        loadScanDetail(scanId);
      }
    } catch { }
  }, 2000);
}

// ── Report Download ───────────────────────────────────────────────────────

$('#btn-download-report').addEventListener('click', async () => {
  if (!currentScanId) return;

  try {
    const resp = await fetch(`/api/scans/${currentScanId}/report`);
    if (!resp.ok) throw new Error('Failed to generate report');

    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secureprobe-report-${currentScanId.slice(0, 8)}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    alert('Download failed: ' + err.message);
  }
});

// ── Delete Scan ───────────────────────────────────────────────────────────

$('#btn-delete-scan').addEventListener('click', async () => {
  if (!currentScanId) return;
  if (!confirm('Delete this scan and all its data?')) return;

  try {
    await api('DELETE', `/scans/${currentScanId}`);
    navigateTo('history');
  } catch (err) {
    alert('Delete failed: ' + err.message);
  }
});

// ── Back Button ───────────────────────────────────────────────────────────

$('#btn-back-from-detail').addEventListener('click', () => {
  stopPolling();
  navigateTo('history');
});

// ── Init ──────────────────────────────────────────────────────────────────

navigateTo('dashboard');
