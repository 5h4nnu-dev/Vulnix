const express = require('express');
const path = require('path');
const { v4: uuid } = require('uuid');
const { stmts } = require('./database');
const { runScan } = require('./scanner');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ───────────────────────────────────────────────────────────────

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── API Routes ──────────────────────────────────────────────────────────────

// Create a new scan
app.post('/api/scans', (req, res) => {
    const { url, options } = req.body;

    if (!url || typeof url !== 'string') {
        return res.status(400).json({ error: 'URL is required' });
    }

    let normalizedUrl = url.trim();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
        normalizedUrl = 'https://' + normalizedUrl;
    }

    try { new URL(normalizedUrl); } catch {
        return res.status(400).json({ error: 'Invalid URL' });
    }

    const scanOptions = {
        checkHeaders: true,
        checkCors: true,
        checkSqlInjection: true,
        checkXss: true,
        checkOpenRedirect: true,
        checkHttpMethods: true,
        checkRateLimit: true,
        ...options,
    };

    const id = uuid();

    stmts.insertScan.run({
        id,
        url: normalizedUrl,
        status: 'pending',
        options: JSON.stringify(scanOptions),
        stages_completed: '[]',
    });

    // Fire scan in the background
    runScan(id, normalizedUrl, scanOptions).catch((err) => {
        console.error(`[scan:${id}] runner error:`, err);
    });

    const scan = stmts.getScan.get(id);
    res.status(201).json(scan);
});

// List scans
app.get('/api/scans', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const offset = parseInt(req.query.offset) || 0;
    const scans = stmts.listScans.all(limit, offset);
    const { count: total } = stmts.countScans.get();
    res.json({ scans, total });
});

// Get single scan with vulnerabilities and events
app.get('/api/scans/:id', (req, res) => {
    const scan = stmts.getScan.get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const vulnerabilities = stmts.getVulns.all(scan.id);
    const events = stmts.getEvents.all(scan.id);

    res.json({ scan, vulnerabilities, events });
});

// Delete a scan
app.delete('/api/scans/:id', (req, res) => {
    stmts.deleteScan.run(req.params.id);
    res.sendStatus(204);
});

// Get scan status (for polling)
app.get('/api/scans/:id/status', (req, res) => {
    const scan = stmts.getScan.get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    res.json({
        id: scan.id,
        status: scan.status,
        progress: scan.progress,
        current_stage: scan.current_stage,
        stages_completed: JSON.parse(scan.stages_completed || '[]'),
        stages_total: 9,
    });
});

// Get scan events
app.get('/api/scans/:id/events', (req, res) => {
    const events = stmts.getEvents.all(req.params.id);
    res.json({ events });
});

// Get scan vulnerabilities
app.get('/api/scans/:id/vulnerabilities', (req, res) => {
    const vulnerabilities = stmts.getVulns.all(req.params.id);
    res.json({ vulnerabilities });
});

// Stats summary
app.get('/api/stats/summary', (req, res) => {
    const summary = stmts.statsSummary.get();
    const topTypes = stmts.topVulnTypes.all();
    res.json({ ...summary, top_vulnerability_types: topTypes });
});

// Recent activity
app.get('/api/stats/recent-activity', (req, res) => {
    const recentScans = stmts.recentScans.all();
    const recentVulns = stmts.recentVulns.all();
    res.json({ recent_scans: recentScans, recent_vulnerabilities: recentVulns });
});

// Generate vulnerability report (Markdown)
app.get('/api/scans/:id/report', (req, res) => {
    const scan = stmts.getScan.get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const vulns = stmts.getVulns.all(scan.id);
    const events = stmts.getEvents.all(scan.id);

    let md = `# 🛡️ SecureProbe Security Report\n\n`;
    md += `**Target URL:** ${scan.url}\n`;
    md += `**Scan ID:** \`${scan.id}\`\n`;
    md += `**Status:** ${scan.status}\n`;
    md += `**Scan Date:** ${scan.created_at}\n`;
    md += `**Completed:** ${scan.completed_at || 'N/A'}\n\n`;
    md += `---\n\n`;

    md += `## 📊 Risk Summary\n\n`;
    md += `| Metric | Value |\n`;
    md += `|--------|-------|\n`;
    md += `| **Risk Score** | ${scan.risk_score ?? 0}/100 |\n`;
    md += `| **Risk Level** | ${(scan.risk_level || 'N/A').toUpperCase()} |\n`;
    md += `| **Total Vulnerabilities** | ${scan.vulnerability_count} |\n`;
    md += `| Critical | ${scan.critical_count} |\n`;
    md += `| High | ${scan.high_count} |\n`;
    md += `| Medium | ${scan.medium_count} |\n`;
    md += `| Low | ${scan.low_count} |\n\n`;
    md += `---\n\n`;

    if (vulns.length > 0) {
        md += `## 🔴 Vulnerabilities Found\n\n`;
        for (let i = 0; i < vulns.length; i++) {
            const v = vulns[i];
            const sevEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️' };
            md += `### ${i + 1}. ${sevEmoji[v.severity] || '⚪'} ${v.title}\n\n`;
            md += `| Field | Details |\n`;
            md += `|-------|--------|\n`;
            md += `| **Severity** | ${v.severity.toUpperCase()} |\n`;
            md += `| **Type** | ${v.type} |\n`;
            md += `| **CVSS Score** | ${v.cvss_score ?? 'N/A'} |\n`;
            md += `| **Affected Endpoint** | \`${v.affected_endpoint}\` |\n`;
            md += `| **Discovered** | ${v.discovered_at} |\n\n`;
            if (v.payload) {
                md += `**Payload Used:**\n\`\`\`\n${v.payload}\n\`\`\`\n\n`;
            }
            md += `**Description:**\n${v.description}\n\n`;
            if (v.evidence) {
                md += `**Evidence:**\n\`\`\`\n${v.evidence}\n\`\`\`\n\n`;
            }
            if (v.ai_explanation) {
                md += `**Detailed Analysis:**\n${v.ai_explanation}\n\n`;
            }
            if (v.exploitation) {
                md += `**Possible Exploit:**\n${v.exploitation}\n\n`;
            }
            md += `**Remediation:**\n${v.remediation}\n\n`;
            md += `---\n\n`;
        }
    } else {
        md += `## ✅ No Vulnerabilities Found\n\nThe scan completed without detecting any vulnerabilities.\n\n`;
    }

    md += `## 📋 Scan Timeline (${events.length} events)\n\n`;
    md += `| Time | Stage | Type | Title |\n`;
    md += `|------|-------|------|-------|\n`;
    for (const e of events) {
        md += `| ${e.timestamp} | ${e.stage} | ${e.event_type} | ${e.title} |\n`;
    }
    md += `\n---\n\n`;
    md += `*Report generated by SecureProbe v2.0*\n`;
    md += `*⚠️ Disclaimer: Only scan URLs you own or have explicit permission to test.*\n`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="secureprobe-report-${scan.id.slice(0, 8)}.md"`);
    res.send(md);
});

// SPA fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
    console.log(`\n  🛡️  SecureProbe v2.0`);
    console.log(`  ────────────────────────────`);
    console.log(`  → Running at http://localhost:${PORT}`);
    console.log(`  → Database: secureprobe.db`);
    console.log(`  → Ready to scan!\n`);
});
