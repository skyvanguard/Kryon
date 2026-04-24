import type { FrameworkId } from "../types";

export type ReportFormat = "pdf" | "html" | "json";
export type ReportKind =
  | "executive"
  | "technical"
  | "compliance"
  | "incident"
  | "remediation";

export interface Report {
  id: string;
  title: string;
  kind: ReportKind;
  frameworks: FrameworkId[];
  format: ReportFormat;
  generatedAt: string;
  generatedBy: string;
  sizeKb: number;
  pageCount: number;
  hash: string; // sha256 prefix
  scope: string;
}

export const REPORT_KIND_LABELS: Record<ReportKind, string> = {
  executive: "Ejecutivo",
  technical: "Técnico",
  compliance: "Compliance",
  incident: "Incidente",
  remediation: "Remediación",
};

export const REPORT_KIND_TONES: Record<ReportKind, string> = {
  executive: "bg-primary/10 text-primary border-primary/30",
  technical: "bg-[var(--chart-5)]/10 text-[var(--chart-5)] border-[var(--chart-5)]/30",
  compliance:
    "bg-[var(--success)]/10 text-[var(--success)] border-[var(--success)]/30",
  incident:
    "bg-[var(--critical)]/10 text-[var(--critical)] border-[var(--critical)]/30",
  remediation:
    "bg-[var(--warning)]/10 text-[var(--warning)] border-[var(--warning)]/30",
};

export function getReports(): Report[] {
  const now = new Date();
  const minus = (hours: number) => {
    const d = new Date(now);
    d.setHours(d.getHours() - hours);
    return d.toISOString();
  };

  return [
    {
      id: "rpt-2026-q2-exec",
      title: "Resumen ejecutivo Q2 2026",
      kind: "executive",
      frameworks: ["pci-dss", "iso-27001", "cis", "nist-800-53", "gdpr", "soc2", "hipaa", "owasp", "mitre-attack"],
      format: "pdf",
      generatedAt: minus(2),
      generatedBy: "sistema",
      sizeKb: 3420,
      pageCount: 12,
      hash: "9f2a8c73e4b1",
      scope: "Infraestructura completa · 347 activos",
    },
    {
      id: "rpt-pci-2026-q2",
      title: "PCI DSS v4.0 Assessment",
      kind: "compliance",
      frameworks: ["pci-dss"],
      format: "pdf",
      generatedAt: minus(4),
      generatedBy: "admin@kryon.py",
      sizeKb: 5820,
      pageCount: 28,
      hash: "c18ab592f0da",
      scope: "Cardholder Data Environment",
    },
    {
      id: "rpt-swift-csp-2026",
      title: "SWIFT CSP v2024 — Auto-attestación",
      kind: "compliance",
      frameworks: ["iso-27001"],
      format: "pdf",
      generatedAt: minus(8),
      generatedBy: "admin@kryon.py",
      sizeKb: 2740,
      pageCount: 18,
      hash: "4b7c2e91d6af",
      scope: "32 controles · Alliance Access scope",
    },
    {
      id: "rpt-tech-weekly-14",
      title: "Reporte técnico semanal #14",
      kind: "technical",
      frameworks: ["cis", "owasp"],
      format: "pdf",
      generatedAt: minus(24),
      generatedBy: "sistema",
      sizeKb: 4180,
      pageCount: 42,
      hash: "7e05fa2b91c3",
      scope: "Últimos 7 días · 150 findings activos",
    },
    {
      id: "rpt-iso27001-2026",
      title: "ISO/IEC 27001:2022 — Brecha",
      kind: "compliance",
      frameworks: ["iso-27001"],
      format: "pdf",
      generatedAt: minus(48),
      generatedBy: "demo@britimp.com.py",
      sizeKb: 4920,
      pageCount: 34,
      hash: "1d8e3c7092f4",
      scope: "93 controles Anexo A",
    },
    {
      id: "rpt-incident-2026-03",
      title: "Incidente #2026-03: xz-utils",
      kind: "incident",
      frameworks: ["pci-dss", "iso-27001", "nist-800-53"],
      format: "pdf",
      generatedAt: minus(72),
      generatedBy: "admin@kryon.py",
      sizeKb: 1840,
      pageCount: 14,
      hash: "a2f6bc8d4e91",
      scope: "CVE-2024-3094 · 3 hosts afectados",
    },
    {
      id: "rpt-remediation-april",
      title: "Plan de remediación abril 2026",
      kind: "remediation",
      frameworks: ["pci-dss", "cis", "owasp"],
      format: "pdf",
      generatedAt: minus(120),
      generatedBy: "admin@kryon.py",
      sizeKb: 2130,
      pageCount: 16,
      hash: "6c4b9a1e8f03",
      scope: "28 findings abiertos · priorizado por impacto",
    },
    {
      id: "rpt-gdpr-q1",
      title: "GDPR / Ley 6534 — Q1 2026",
      kind: "compliance",
      frameworks: ["gdpr"],
      format: "pdf",
      generatedAt: minus(168),
      generatedBy: "sistema",
      sizeKb: 1920,
      pageCount: 12,
      hash: "3e8d5f2c9b14",
      scope: "Datos personales · 12 flujos auditados",
    },
    {
      id: "rpt-ad-security",
      title: "Active Directory Security Review",
      kind: "technical",
      frameworks: ["cis", "mitre-attack"],
      format: "pdf",
      generatedAt: minus(192),
      generatedBy: "demo@britimp.com.py",
      sizeKb: 3210,
      pageCount: 22,
      hash: "5a7b2d8f4c6e",
      scope: "4 DCs · BloodHound graph exportado",
    },
    {
      id: "rpt-exec-q1",
      title: "Resumen ejecutivo Q1 2026",
      kind: "executive",
      frameworks: ["pci-dss", "iso-27001", "cis", "nist-800-53"],
      format: "pdf",
      generatedAt: minus(336),
      generatedBy: "sistema",
      sizeKb: 3180,
      pageCount: 10,
      hash: "8c1f4a9b3d72",
      scope: "Infraestructura completa Q1",
    },
  ];
}
