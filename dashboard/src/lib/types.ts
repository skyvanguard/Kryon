/**
 * Core domain types for the Kryon dashboard.
 *
 * These mirror the shapes that FastAPI will return from Kryon's server.
 * During MVP they back the mock fixtures; on Day 7 we swap the mock layer
 * for real HTTP calls without changing any UI component.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

export type FrameworkId =
  | "pci-dss"
  | "iso-27001"
  | "cis"
  | "nist-800-53"
  | "gdpr"
  | "soc2"
  | "hipaa"
  | "owasp"
  | "mitre-attack";

export interface Framework {
  id: FrameworkId;
  name: string;
  shortName: string;
  description: string;
  totalControls: number;
  passedControls: number;
  failedControls: number;
  compliancePercent: number;
  lastEvaluatedAt: string; // ISO
}

export type FindingStatus =
  | "open"
  | "triaging"
  | "confirmed"
  | "remediating"
  | "fixed"
  | "accepted"
  | "false_positive";

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cve?: string;
  cvss?: number; // 0-10
  cwe?: string;
  frameworks: FrameworkId[];
  assetId: string;
  assetName: string;
  status: FindingStatus;
  detectedAt: string; // ISO
  ageDays: number;
  remediation: {
    summary: string;
    effortHours: number;
    automated: boolean; // can Kryon auto-remediate?
  };
  kryonSkill: string;
  exploitable: boolean;
}

export interface Asset {
  id: string;
  name: string;
  type: "server" | "endpoint" | "web" | "database" | "network" | "cloud";
  ip?: string;
  os?: string;
  criticality: "tier-1" | "tier-2" | "tier-3";
  findingsOpen: number;
  lastScanAt: string;
}

export interface ActivityEvent {
  id: string;
  timestamp: string; // ISO
  type:
    | "scan_started"
    | "scan_completed"
    | "scan_failed"
    | "finding_detected"
    | "finding_remediated"
    | "report_generated"
    | "compliance_evaluated"
    | "skill_loaded"
    | "user_action";
  title: string;
  description?: string;
  severity?: Severity;
  actor?: string;
}

export interface KpiTrend {
  direction: "up" | "down" | "flat";
  percentChange: number;
  weekOverWeek: number;
}

export interface OverviewKpis {
  securityScore: {
    value: number; // 0-100
    trend: KpiTrend;
    grade: "A+" | "A" | "B" | "C" | "D" | "F";
  };
  assets: {
    total: number;
    tier1: number;
    monitored: number;
    trend: KpiTrend;
  };
  findings: {
    openTotal: number;
    bySeverity: Record<Severity, number>;
    trend: KpiTrend;
  };
  compliance: {
    averagePercent: number;
    frameworksCovered: number;
    trend: KpiTrend;
  };
}

export interface TimeseriesPoint {
  date: string; // ISO day
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}
