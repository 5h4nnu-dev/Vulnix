import { Router, type IRouter } from "express";
import { eq, desc, count, avg, sql } from "drizzle-orm";
import { db, scansTable, vulnerabilitiesTable, scanEventsTable } from "@workspace/db";
import {
  CreateScanBody,
  GetScanParams,
  DeleteScanParams,
  GetScanStatusParams,
  GetScanEventsParams,
  GetScanVulnerabilitiesParams,
  ListScansQueryParams,
  ListScansResponse,
  GetScanResponse,
  GetScanStatusResponse,
  GetScanEventsResponse,
  GetScanVulnerabilitiesResponse,
  GetStatsSummaryResponse,
  GetRecentActivityResponse,
} from "@workspace/api-zod";
import { randomUUID } from "crypto";
import { runScan } from "../lib/scanner";

const router: IRouter = Router();

router.post("/scans", async (req, res): Promise<void> => {
  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "bad_request", message: parsed.error.message });
    return;
  }

  let normalizedUrl = parsed.data.url.trim();
  if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
    normalizedUrl = "https://" + normalizedUrl;
  }

  try {
    new URL(normalizedUrl);
  } catch {
    res.status(400).json({ error: "bad_request", message: "Invalid URL provided" });
    return;
  }

  const id = randomUUID();
  const [scan] = await db.insert(scansTable).values({
    id,
    url: normalizedUrl,
    status: "pending",
    options: parsed.data.options,
    stagesCompleted: [],
  }).returning();

  runScan(id, normalizedUrl, parsed.data.options).catch((err) => {
    req.log.error({ err, scanId: id }, "Scan runner error");
  });

  res.status(201).json({
    id: scan.id,
    url: scan.url,
    status: scan.status,
    riskScore: scan.riskScore,
    riskLevel: scan.riskLevel,
    vulnerabilityCount: scan.vulnerabilityCount,
    criticalCount: scan.criticalCount,
    highCount: scan.highCount,
    mediumCount: scan.mediumCount,
    lowCount: scan.lowCount,
    createdAt: scan.createdAt.toISOString(),
    completedAt: scan.completedAt?.toISOString() ?? null,
  });
});

router.get("/scans", async (req, res): Promise<void> => {
  const params = ListScansQueryParams.safeParse(req.query);
  const limit = params.success ? (params.data.limit ?? 20) : 20;
  const offset = params.success ? (params.data.offset ?? 0) : 0;

  const [scans, [totalResult]] = await Promise.all([
    db.select().from(scansTable).orderBy(desc(scansTable.createdAt)).limit(limit).offset(offset),
    db.select({ count: count() }).from(scansTable),
  ]);

  res.json(ListScansResponse.parse({
    scans: scans.map(s => ({
      ...s,
      createdAt: s.createdAt.toISOString(),
      completedAt: s.completedAt?.toISOString() ?? null,
    })),
    total: totalResult.count,
  }));
});

router.get("/scans/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = GetScanParams.safeParse({ id: raw });
  if (!params.success) {
    res.status(400).json({ error: "bad_request", message: params.error.message });
    return;
  }

  const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, params.data.id));
  if (!scan) {
    res.status(404).json({ error: "not_found", message: "Scan not found" });
    return;
  }

  const [vulns, events] = await Promise.all([
    db.select().from(vulnerabilitiesTable).where(eq(vulnerabilitiesTable.scanId, scan.id)).orderBy(desc(vulnerabilitiesTable.discoveredAt)),
    db.select().from(scanEventsTable).where(eq(scanEventsTable.scanId, scan.id)).orderBy(scanEventsTable.timestamp),
  ]);

  res.json(GetScanResponse.parse({
    scan: {
      ...scan,
      createdAt: scan.createdAt.toISOString(),
      completedAt: scan.completedAt?.toISOString() ?? null,
    },
    vulnerabilities: vulns.map(v => ({
      ...v,
      discoveredAt: v.discoveredAt.toISOString(),
    })),
    events: events.map(e => ({
      ...e,
      timestamp: e.timestamp.toISOString(),
    })),
  }));
});

router.delete("/scans/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = DeleteScanParams.safeParse({ id: raw });
  if (!params.success) {
    res.status(400).json({ error: "bad_request", message: params.error.message });
    return;
  }

  await db.delete(scansTable).where(eq(scansTable.id, params.data.id));
  res.sendStatus(204);
});

router.get("/scans/:id/status", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = GetScanStatusParams.safeParse({ id: raw });
  if (!params.success) {
    res.status(400).json({ error: "bad_request", message: params.error.message });
    return;
  }

  const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, params.data.id));
  if (!scan) {
    res.status(404).json({ error: "not_found", message: "Scan not found" });
    return;
  }

  const stagesCompleted = Array.isArray(scan.stagesCompleted) ? scan.stagesCompleted as string[] : [];

  res.json(GetScanStatusResponse.parse({
    id: scan.id,
    status: scan.status,
    progress: scan.progress,
    currentStage: scan.currentStage,
    stagesCompleted,
    stagesTotal: 9,
  }));
});

router.get("/scans/:id/events", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = GetScanEventsParams.safeParse({ id: raw });
  if (!params.success) {
    res.status(400).json({ error: "bad_request", message: params.error.message });
    return;
  }

  const events = await db.select().from(scanEventsTable)
    .where(eq(scanEventsTable.scanId, params.data.id))
    .orderBy(scanEventsTable.timestamp);

  res.json(GetScanEventsResponse.parse({
    events: events.map(e => ({
      ...e,
      timestamp: e.timestamp.toISOString(),
    })),
  }));
});

router.get("/scans/:id/vulnerabilities", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = GetScanVulnerabilitiesParams.safeParse({ id: raw });
  if (!params.success) {
    res.status(400).json({ error: "bad_request", message: params.error.message });
    return;
  }

  const vulns = await db.select().from(vulnerabilitiesTable)
    .where(eq(vulnerabilitiesTable.scanId, params.data.id))
    .orderBy(desc(vulnerabilitiesTable.discoveredAt));

  res.json(GetScanVulnerabilitiesResponse.parse({
    vulnerabilities: vulns.map(v => ({
      ...v,
      discoveredAt: v.discoveredAt.toISOString(),
    })),
  }));
});

router.get("/stats/summary", async (_req, res): Promise<void> => {
  const [totals] = await db.select({
    totalScans: count(scansTable.id),
    totalVulnerabilities: sql<number>`sum(${scansTable.vulnerabilityCount})`,
    criticalCount: sql<number>`sum(${scansTable.criticalCount})`,
    highCount: sql<number>`sum(${scansTable.highCount})`,
    mediumCount: sql<number>`sum(${scansTable.mediumCount})`,
    lowCount: sql<number>`sum(${scansTable.lowCount})`,
    avgRiskScore: avg(scansTable.riskScore),
  }).from(scansTable).where(eq(scansTable.status, "completed"));

  const typeCounts = await db.select({
    type: vulnerabilitiesTable.type,
    count: count(vulnerabilitiesTable.id),
  }).from(vulnerabilitiesTable).groupBy(vulnerabilitiesTable.type).orderBy(desc(count(vulnerabilitiesTable.id))).limit(10);

  res.json(GetStatsSummaryResponse.parse({
    totalScans: totals.totalScans ?? 0,
    totalVulnerabilities: totals.totalVulnerabilities ?? 0,
    criticalCount: totals.criticalCount ?? 0,
    highCount: totals.highCount ?? 0,
    mediumCount: totals.mediumCount ?? 0,
    lowCount: totals.lowCount ?? 0,
    avgRiskScore: parseFloat(totals.avgRiskScore ?? "0") || 0,
    topVulnerabilityTypes: typeCounts.map(tc => ({ type: tc.type, count: Number(tc.count) })),
  }));
});

router.get("/stats/recent-activity", async (_req, res): Promise<void> => {
  const [recentScans, recentVulns] = await Promise.all([
    db.select().from(scansTable).orderBy(desc(scansTable.createdAt)).limit(5),
    db.select().from(vulnerabilitiesTable).orderBy(desc(vulnerabilitiesTable.discoveredAt)).limit(10),
  ]);

  res.json(GetRecentActivityResponse.parse({
    recentScans: recentScans.map(s => ({
      ...s,
      createdAt: s.createdAt.toISOString(),
      completedAt: s.completedAt?.toISOString() ?? null,
    })),
    recentVulnerabilities: recentVulns.map(v => ({
      ...v,
      discoveredAt: v.discoveredAt.toISOString(),
    })),
  }));
});

export default router;
