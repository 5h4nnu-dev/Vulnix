import { pgTable, text, timestamp, integer, real, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const scansTable = pgTable("scans", {
  id: text("id").primaryKey(),
  url: text("url").notNull(),
  status: text("status").notNull().default("pending"),
  riskScore: real("risk_score"),
  riskLevel: text("risk_level"),
  vulnerabilityCount: integer("vulnerability_count").notNull().default(0),
  criticalCount: integer("critical_count").notNull().default(0),
  highCount: integer("high_count").notNull().default(0),
  mediumCount: integer("medium_count").notNull().default(0),
  lowCount: integer("low_count").notNull().default(0),
  progress: integer("progress").notNull().default(0),
  currentStage: text("current_stage"),
  stagesCompleted: jsonb("stages_completed").notNull().default([]),
  options: jsonb("options").notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
});

export const insertScanSchema = createInsertSchema(scansTable).omit({ createdAt: true });
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scansTable.$inferSelect;

export const vulnerabilitiesTable = pgTable("vulnerabilities", {
  id: text("id").primaryKey(),
  scanId: text("scan_id").notNull().references(() => scansTable.id, { onDelete: "cascade" }),
  type: text("type").notNull(),
  severity: text("severity").notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  affectedEndpoint: text("affected_endpoint").notNull(),
  payload: text("payload"),
  evidence: text("evidence"),
  aiExplanation: text("ai_explanation"),
  remediation: text("remediation").notNull(),
  cvssScore: real("cvss_score"),
  discoveredAt: timestamp("discovered_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilitiesTable).omit({ discoveredAt: true });
export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type Vulnerability = typeof vulnerabilitiesTable.$inferSelect;

export const scanEventsTable = pgTable("scan_events", {
  id: text("id").primaryKey(),
  scanId: text("scan_id").notNull().references(() => scansTable.id, { onDelete: "cascade" }),
  stage: text("stage").notNull(),
  eventType: text("event_type").notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  payload: text("payload"),
  requestHeaders: text("request_headers"),
  responseStatus: integer("response_status"),
  responseHeaders: text("response_headers"),
  responseBody: text("response_body"),
  severity: text("severity"),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull().defaultNow(),
});

export const insertScanEventSchema = createInsertSchema(scanEventsTable).omit({ timestamp: true });
export type InsertScanEvent = z.infer<typeof insertScanEventSchema>;
export type ScanEvent = typeof scanEventsTable.$inferSelect;
