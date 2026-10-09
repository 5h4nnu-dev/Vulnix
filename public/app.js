const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let currentScanId = null;
let pollInterval = null;

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
  item.addEventListener('click', (e) => { e.preventDefault(); navigateTo(item.dataset.page); });
});

async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(`/api${path}`, opts);
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || err.message || 'Request failed');
  }
  if (resp.status === 204) return null;
  return resp.json();
}

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
    critical: 'rgba(255,0,60,0.12);color:var(--sev-critical)',
    high: 'rgba(255,102,0,0.12);color:var(--sev-high)',
    medium: 'rgba(255,176,0,0.12);color:var(--sev-medium)',
    low: 'rgba(0,191,255,0.12);color:var(--sev-low)',
    info: 'rgba(51,119,51,0.12);color:var(--sev-info)',
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
  btn.innerHTML = `<span class="pulse-dot"></span> Scanning…`;

  try {
    const scan = await api('POST', '/scans', { url, options });
    currentScanId = scan.id;

    const progressCard = $('#scan-progress-card');
    progressCard.classList.remove('hidden');
    $('#scan-progress-bar').style.width = '0%';
    $('#scan-progress-percent').textContent = '0%';
    $('#scan-status-text').textContent = 'Scanning…';
    $('#scan-stage-text').textContent = 'Initializing…';
    $('#scan-live-events').innerHTML = '';

    startPolling(scan.id);
  } catch (err) {
    alert('Failed to start scan: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Start Scan';
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
        while (container.children.length > 20) {
          container.removeChild(container.lastChild);
        }
      }

      if (status.status === 'completed' || status.status === 'failed') {
        stopPolling();
        $('#scan-status-text').textContent = status.status === 'completed' ? 'Scan Complete!' : 'Scan Failed';
        $('#scan-progress-bar').style.width = '100%';
        $('#scan-progress-percent').textContent = '100%';
        setTimeout(() => {
          navigateTo('scan-detail', { id: scanId });
          $('#scan-progress-card').classList.add('hidden');
          $('#scan-url-input').value = '';
        }, 1500);
      }
    } catch {}
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

async function loadScanDetail(scanId) {
  currentScanId = scanId;
  const infoContainer = $('#detail-scan-info');
  const vulnsContainer = $('#detail-vulns-section');
  const payloadsContainer = $('#detail-payloads-section');
  const eventsContainer = $('#detail-events-section');
  infoContainer.innerHTML = '<div class="empty-state">Loading…</div>';
  vulnsContainer.innerHTML = '';
  payloadsContainer.innerHTML = '';
  eventsContainer.innerHTML = '';

  try {
    const { scan, vulnerabilities, events } = await api('GET', `/scans/${scanId}`);

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
          <div class="detail-info-value" style="font-size:0.8rem">${formatDate(scan.created_at)}</div>
        </div>
        <div class="detail-info-item">
          <div class="detail-info-label">Completed</div>
          <div class="detail-info-value" style="font-size:0.8rem">${formatDate(scan.completed_at)}</div>
        </div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
        ${scan.critical_count ? `<span class="badge badge-critical">${scan.critical_count} Critical</span>` : ''}
        ${scan.high_count ? `<span class="badge badge-high">${scan.high_count} High</span>` : ''}
        ${scan.medium_count ? `<span class="badge badge-medium">${scan.medium_count} Medium</span>` : ''}
        ${scan.low_count ? `<span class="badge badge-low">${scan.low_count} Low</span>` : ''}
      </div>
    `;

    if (vulnerabilities && vulnerabilities.length > 0) {
      vulnsContainer.innerHTML = `
        <h2 style="font-size:0.85rem;font-weight:700;margin:22px 0 14px;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.06em">
          Vulnerabilities (${vulnerabilities.length})
        </h2>
        ${vulnerabilities.map((v, i) => renderVulnCard(v, i)).join('')}
      `;
    } else {
      vulnsContainer.innerHTML = `
        <div class="card" style="margin-top:22px">
          <div class="card-body">
            <div class="empty-state" style="color:var(--success)">No vulnerabilities found!</div>
          </div>
        </div>
      `;
    }

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

    if (scan.status === 'completed' && vulnerabilities && vulnerabilities.length > 0) {
      loadPayloads(scanId, payloadsContainer);
    }

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
    } catch {}
  }, 2000);
}

async function loadPayloads(scanId, container) {
  try {
    const data = await api('GET', `/scans/${scanId}/payloads`);
    if (!data.payload_sets || data.payload_sets.length === 0) {
      container.innerHTML = '';
      return;
    }
    container.innerHTML = `
      <div class="payloads-section">
        <div class="payloads-header">
          <h2>Test Payloads (${data.total_payloads})</h2>
          <span class="payloads-subtitle">Categorized payloads for authorized security testing</span>
        </div>
        <div class="payload-sets" id="payload-sets">
          ${data.payload_sets.map((set, si) => renderPayloadSet(set, si)).join('')}
        </div>
      </div>
    `;
  } catch (err) {
    console.error('Failed to load payloads:', err);
  }
}

function renderPayloadSet(set, setIndex) {
  const categories = groupPayloadsByType(set.payloads);
  const catKeys = Object.keys(categories);
  const severityClass = (set.detected_severity || [])[0] || 'medium';
  return `
    <div class="payload-set card" id="payload-set-${setIndex}">
      <div class="payload-set-header" onclick="togglePayloadSet(${setIndex})">
        <div class="payload-set-info">
          <div class="payload-set-title">
            <span class="payload-set-icon">${getVulnIcon(set.vulnerability)}</span>
            ${escapeHtml(set.name)}
          </div>
          <div class="payload-set-meta">
            <span class="badge badge-${severityClass}">${set.detected_instances} detected</span>
            <span class="payload-count">${set.total_payloads} payloads</span>
          </div>
        </div>
        <svg class="payload-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
      </div>
      <div class="payload-set-body">
        <div class="payload-cat-tabs">
          ${catKeys.map((cat, i) => `
            <button class="payload-cat-tab ${i === 0 ? 'active' : ''}" onclick="switchPayloadCat(${setIndex}, '${cat}', this)">
              ${formatCatName(cat)} <span class="cat-count">${categories[cat].length}</span>
            </button>
          `).join('')}
        </div>
        ${catKeys.map((cat, i) => `
          <div class="payload-cat-content ${i === 0 ? 'active' : ''}" id="pcat-${setIndex}-${cat}">
            ${categories[cat].map((p, pi) => renderPayloadItem(p, setIndex, cat, pi)).join('')}
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderPayloadItem(p, setIndex, cat, pi) {
  const id = `p-${setIndex}-${cat}-${pi}`;
  return `
    <div class="payload-item">
      <div class="payload-item-header">
        <span class="payload-type-badge">${escapeHtml(formatCatName(p.type))}</span>
        <button class="btn-copy" onclick="copyPayload('${id}')" title="Copy payload">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
      </div>
      <pre class="payload-code" id="${id}">${escapeHtml(p.payload)}</pre>
      <div class="payload-desc">${escapeHtml(p.description)}</div>
      <div class="payload-expected"><strong>Expected:</strong> ${escapeHtml(p.expected_behavior)}</div>
    </div>
  `;
}

function groupPayloadsByType(payloads) {
  const groups = {};
  for (const p of payloads) {
    if (!groups[p.type]) groups[p.type] = [];
    groups[p.type].push(p);
  }
  return groups;
}

function formatCatName(cat) {
  return (cat || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function getVulnIcon(vuln) {
  const icons = {
    xss: '💉', sql_injection: '🗃️', open_redirect: '↗️',
    cors_misconfiguration: '🌐', command_injection: '⚡',
    path_traversal: '📂', ssrf: '🔗', csrf: '🔄',
    header_injection: '📋', missing_security_header: '🔓',
    weak_security_header: '🔓', info_disclosure: 'ℹ️',
    http_method_abuse: '🔧', rate_limit_bypass: '⏱️',
    sensitive_file_disclosure: '📁',
  };
  return icons[vuln] || '🔍';
}

function togglePayloadSet(setIndex) {
  const el = $(`#payload-set-${setIndex}`);
  if (el) el.classList.toggle('open');
}

function switchPayloadCat(setIndex, cat, btn) {
  const set = $(`#payload-set-${setIndex}`);
  if (!set) return;
  set.querySelectorAll('.payload-cat-tab').forEach(t => t.classList.remove('active'));
  set.querySelectorAll('.payload-cat-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  const content = $(`#pcat-${setIndex}-${cat}`);
  if (content) content.classList.add('active');
}

function copyPayload(id) {
  const el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => {
    const btn = el.parentElement.querySelector('.btn-copy');
    if (btn) {
      btn.innerHTML = '✓';
      setTimeout(() => {
        btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
      }, 1500);
    }
  });
}

$('#btn-download-report').addEventListener('click', async () => {
  if (!currentScanId) return;
  try {
    const resp = await fetch(`/api/scans/${currentScanId}/report`);
    if (!resp.ok) throw new Error('Failed to generate report');
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `neosec-report-${currentScanId.slice(0, 8)}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    alert('Download failed: ' + err.message);
  }
});

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

$('#btn-back-from-detail').addEventListener('click', () => {
  stopPolling();
  navigateTo('history');
});

const MatrixRain = {
  canvas: null,
  ctx: null,
  drops: [],
  chars: 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<>/{}[]|&^%$#@!',
  _frameId: null,
  _running: false,

  init() {
    this.canvas = document.getElementById('matrix-canvas');
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.resize();
    window.addEventListener('resize', () => this.resize());
    const cols = Math.floor(this.canvas.width / 14);
    this.drops = Array(cols).fill(1).map(() => Math.random() * 100);
    this._running = true;
    this.animate();
  },

  resize() {
    this.canvas.width = window.innerWidth;
    this.canvas.height = window.innerHeight;
  },

  animate() {
    if (!this._running) return;
    this.ctx.fillStyle = 'rgba(10, 14, 10, 0.05)';
    this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
    this.ctx.font = '14px monospace';

    const cols = this.drops.length;
    const spacing = this.canvas.width / cols;

    for (let i = 0; i < cols; i++) {
      const char = this.chars[Math.floor(Math.random() * this.chars.length)];
      const x = i * spacing;
      const y = this.drops[i] * 14;

      const brightness = Math.random() > 0.98 ? '#aaffaa' : '#00ff41';
      this.ctx.fillStyle = brightness;
      this.ctx.shadowColor = brightness;
      this.ctx.shadowBlur = brightness === '#aaffaa' ? 8 : 2;
      this.ctx.fillText(char, x, y);
      this.ctx.shadowBlur = 0;

      if (y > this.canvas.height && Math.random() > 0.975) {
        this.drops[i] = 0;
      }
      this.drops[i] += 0.5 + Math.random() * 0.5;
    }
    this._frameId = requestAnimationFrame(() => this.animate());
  },

  start() {
    if (this._running) return;
    this._running = true;
    if (this.canvas) {
      this.canvas.style.opacity = '0.35';
    }
    if (this.drops.length === 0) {
      const cols = Math.floor(this.canvas.width / 14);
      this.drops = Array(cols).fill(1).map(() => Math.random() * 100);
    }
    this.animate();
  },

  stop() {
    this._running = false;
    if (this._frameId) {
      cancelAnimationFrame(this._frameId);
      this._frameId = null;
    }
    if (this.ctx && this.canvas) {
      this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
      this.canvas.style.opacity = '0';
    }
    this.drops = [];
  }
};

const ParticleNetwork = {
  canvas: null,
  ctx: null,
  particles: [],
  mouseX: -1000,
  mouseY: -1000,

  init() {
    this.canvas = document.getElementById('particle-canvas');
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.resize();
    window.addEventListener('resize', () => this.resize());
    window.addEventListener('mousemove', (e) => { this.mouseX = e.clientX; this.mouseY = e.clientY; });
    this.particles = Array.from({ length: 60 }, () => ({
      x: Math.random() * this.canvas.width,
      y: Math.random() * this.canvas.height,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: 1 + Math.random() * 1.5,
      a: 0.3 + Math.random() * 0.4,
    }));
    this.animate();
  },

  resize() {
    this.canvas.width = window.innerWidth;
    this.canvas.height = window.innerHeight;
  },

  animate() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    for (const p of this.particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > this.canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > this.canvas.height) p.vy *= -1;

      this.ctx.beginPath();
      this.ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      this.ctx.fillStyle = `rgba(0, 255, 65, ${p.a})`;
      this.ctx.fill();
    }

    for (let i = 0; i < this.particles.length; i++) {
      for (let j = i + 1; j < this.particles.length; j++) {
        const dx = this.particles[i].x - this.particles[j].x;
        const dy = this.particles[i].y - this.particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          const alpha = (1 - dist / 120) * 0.15;
          this.ctx.beginPath();
          this.ctx.moveTo(this.particles[i].x, this.particles[i].y);
          this.ctx.lineTo(this.particles[j].x, this.particles[j].y);
          this.ctx.strokeStyle = `rgba(0, 255, 65, ${alpha})`;
          this.ctx.lineWidth = 0.5;
          this.ctx.stroke();
        }
      }
    }

    requestAnimationFrame(() => this.animate());
  }
};

function typeWrite(element, text, speed = 25) {
  return new Promise((resolve) => {
    let i = 0;
    element.textContent = '';
    function tick() {
      if (i < text.length) {
        element.textContent += text[i];
        i++;
        setTimeout(tick, speed + Math.random() * speed);
      } else { resolve(); }
    }
    tick();
  });
}

async function bootSequence() {
  const bootLines = [
    'INITIALIZING NEOSEC SECURITY KERNEL...',
    'LOADING PAYLOAD DATABASE [260 MODULES]... OK',
    'ESTABLISHING SECURE ENCRYPTION CHANNEL... OK',
    'ARMING VULNERABILITY DETECTION ENGINE... OK',
    'CALIBRATING SCAN PROTOCOLS... OK',
    'SYNCHRONIZING THREAT INTELLIGENCE... OK',
    'SYSTEM READY — ENTERING SECURE MODE.',
  ];

  for (let i = 0; i < bootLines.length; i++) {
    const line = document.querySelector(`.boot-line[data-boot="${i + 1}"]`);
    if (!line) continue;
    line.classList.add('visible');
    const textSpan = line.querySelector('.boot-text');
    if (textSpan) {
      await typeWrite(textSpan, bootLines[i], 20 + Math.random() * 10);
    }
    await new Promise(r => setTimeout(r, 150 + Math.random() * 200));
  }

  const progressFill = document.getElementById('boot-progress-fill');
  if (progressFill) {
    progressFill.style.width = '100%';
  }

  await new Promise(r => setTimeout(r, 600));

  const overlay = document.getElementById('boot-overlay');
  if (overlay) {
    overlay.classList.add('boot-done');
  }

  await new Promise(r => setTimeout(r, 900));
  if (overlay) {
    overlay.style.display = 'none';
  }
}

function updateClock() {
  const el = document.getElementById('sidebar-time');
  if (el) {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }
}

async function init() {
  await bootSequence();
  MatrixRain.init();
  ParticleNetwork.init();
  setInterval(updateClock, 1000);
  updateClock();
  navigateTo('dashboard');

  const toggle = document.getElementById('matrix-toggle');
  if (toggle) {
    toggle.addEventListener('change', () => {
      if (toggle.checked) {
        MatrixRain.start();
      } else {
        MatrixRain.stop();
      }
    });
  }
}

init();
