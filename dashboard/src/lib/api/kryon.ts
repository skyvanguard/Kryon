import { kryonFetch, KryonApiError } from "./client";
import type { Finding, FindingStatus, Severity } from "../types";

/**
 * Typed surface for the subset of Kryon FastAPI endpoints the dashboard
 * consumes. Adapters live here too — the backend returns snake_case
 * Pydantic models; the UI wants camelCase typed domain objects. The
 * mapping is intentionally explicit so schema drift fails at compile
 * time instead of silently rendering wrong data.
 */

// ---------- Health ----------

export interface HealthResponse {
  status: "ok" | "degraded" | "unhealthy";
  version: string;
  agents_count: number;
}

export async function getHealth(): Promise<HealthResponse> {
  return kryonFetch<HealthResponse>("/health");
}

// ---------- Findings ----------

interface BackendFinding {
  id: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  cve?: string;
  cvss_score?: number;
  cwe?: string;
  asset_id?: string;
  asset_name?: string;
  target?: string;
  compliance_frameworks?: string[];
  detected_at?: string;
  age_days?: number;
  remediation?: string;
  remediation_effort_hours?: number;
  auto_remediable?: boolean;
  tool_source?: string;
  exploitable?: boolean;
}

interface BackendFindingsList {
  items: BackendFinding[];
  total: number;
  offset: number;
  limit: number;
}

export interface FindingsPage {
  items: Finding[];
  total: number;
  offset: number;
  limit: number;
}

export interface FindingsQuery {
  severity?: Severity;
  status?: FindingStatus;
  client_id?: string;
  tool_source?: string;
  offset?: number;
  limit?: number;
}

const SEVERITY_MAP: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  informational: "info",
};

// Backend ships a broader status vocabulary than the UI. Anything we don't
// recognize maps to "open" so lists still render without blowing up.
const STATUS_MAP: Record<string, FindingStatus> = {
  open: "open",
  triaging: "triaging",
  in_triage: "triaging",
  confirmed: "confirmed",
  remediating: "remediating",
  in_remediation: "remediating",
  remediated: "fixed",
  fixed: "fixed",
  accepted: "accepted",
  accepted_risk: "accepted",
  false_positive: "false_positive",
  fp: "false_positive",
};

function adaptFinding(raw: BackendFinding): Finding {
  const severity =
    SEVERITY_MAP[raw.severity?.toLowerCase() ?? ""] ?? "medium";
  const status = STATUS_MAP[raw.status?.toLowerCase() ?? ""] ?? "open";

  const frameworks =
    (raw.compliance_frameworks ?? []).map((f) => normalizeFrameworkId(f));

  return {
    id: raw.id,
    title: raw.title,
    description: raw.description ?? "",
    severity,
    cve: raw.cve,
    cvss: raw.cvss_score,
    cwe: raw.cwe,
    frameworks,
    assetId: raw.asset_id ?? raw.target ?? "unknown",
    assetName: raw.asset_name ?? raw.target ?? "—",
    status,
    detectedAt:
      raw.detected_at ?? new Date().toISOString(),
    ageDays: raw.age_days ?? 0,
    remediation: {
      summary: raw.remediation ?? "Sin recomendación disponible.",
      effortHours: raw.remediation_effort_hours ?? 2,
      automated: raw.auto_remediable ?? false,
    },
    kryonSkill: raw.tool_source ?? "kryon-vuln-hunter",
    exploitable: raw.exploitable ?? false,
  };
}

function normalizeFrameworkId(raw: string): Finding["frameworks"][number] {
  const slug = raw.toLowerCase().replace(/[\s_]+/g, "-");
  const byId: Record<string, Finding["frameworks"][number]> = {
    "pci-dss": "pci-dss",
    "pci": "pci-dss",
    "iso-27001": "iso-27001",
    "iso27001": "iso-27001",
    "cis": "cis",
    "nist": "nist-800-53",
    "nist-800-53": "nist-800-53",
    "gdpr": "gdpr",
    "soc2": "soc2",
    "soc-2": "soc2",
    "hipaa": "hipaa",
    "owasp": "owasp",
    "mitre": "mitre-attack",
    "mitre-attack": "mitre-attack",
  };
  return byId[slug] ?? "owasp"; // default bucket when unknown
}

export async function listFindings(
  query: FindingsQuery = {}
): Promise<FindingsPage> {
  const raw = await kryonFetch<BackendFindingsList>("/findings", {
    query: {
      severity: query.severity,
      status: query.status,
      client_id: query.client_id,
      tool_source: query.tool_source,
      offset: query.offset ?? 0,
      limit: query.limit ?? 200,
    },
  });

  return {
    items: raw.items.map(adaptFinding),
    total: raw.total,
    offset: raw.offset,
    limit: raw.limit,
  };
}

export async function getFinding(id: string): Promise<Finding> {
  const raw = await kryonFetch<BackendFinding>(`/findings/${encodeURIComponent(id)}`);
  return adaptFinding(raw);
}

export { KryonApiError };
