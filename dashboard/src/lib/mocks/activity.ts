import type { ActivityEvent } from "../types";

/**
 * Recent activity feed. Events are relative to "now" so the timestamps
 * always feel fresh when the demo runs. The mix is intentionally varied:
 * scans, findings, compliance, remediation and admin actions so the feed
 * showcases the full breadth of the platform in ~10 lines.
 */
export function getRecentActivity(): ActivityEvent[] {
  const now = new Date();
  const minus = (minutes: number): string => {
    const d = new Date(now);
    d.setMinutes(d.getMinutes() - minutes);
    return d.toISOString();
  };

  return [
    {
      id: "act-001",
      timestamp: minus(4),
      type: "finding_detected",
      title: "Nueva vulnerabilidad crítica",
      description:
        "CVE-2024-3094 (xz-utils backdoor) detectada en build-srv-02",
      severity: "critical",
      actor: "kryon-recon-scout",
    },
    {
      id: "act-002",
      timestamp: minus(18),
      type: "scan_completed",
      title: "Escaneo completado: 10.20.0.0/16",
      description: "187 activos analizados · 14 findings nuevos · 8.4 min",
      actor: "kryon-pentest",
    },
    {
      id: "act-003",
      timestamp: minus(42),
      type: "finding_remediated",
      title: "Remediación automática aplicada",
      description:
        "CVE-2024-21413 (Outlook NTLM leak) corregida en 23 endpoints con rollback verificado",
      severity: "high",
      actor: "kryon-safe-modification",
    },
    {
      id: "act-004",
      timestamp: minus(71),
      type: "compliance_evaluated",
      title: "Evaluación PCI-DSS v4.0 completada",
      description:
        "287/312 controles aprobados · hash firmado · reporte disponible",
      actor: "kryon-pci-audit",
    },
    {
      id: "act-005",
      timestamp: minus(96),
      type: "report_generated",
      title: "Reporte ejecutivo Q2 2026 generado",
      description: "9 frameworks · 42 páginas · PDF con firma criptográfica",
      actor: "sistema",
    },
    {
      id: "act-006",
      timestamp: minus(143),
      type: "finding_detected",
      title: "Configuración SSH débil detectada",
      description:
        "PasswordAuthentication=yes y PermitRootLogin=yes en 4 servidores",
      severity: "high",
      actor: "kryon-server-hardening",
    },
    {
      id: "act-007",
      timestamp: minus(203),
      type: "scan_started",
      title: "Escaneo SWIFT CSP iniciado",
      description: "32 controles · alcance Alliance Access + firewall bancario",
      actor: "kryon-swift",
    },
    {
      id: "act-008",
      timestamp: minus(264),
      type: "finding_remediated",
      title: "Patch aplicado y verificado",
      description:
        "CVE-2025-21298 (Windows OLE) — 156 endpoints actualizados sin downtime",
      severity: "critical",
      actor: "kryon-safe-modification",
    },
    {
      id: "act-009",
      timestamp: minus(342),
      type: "skill_loaded",
      title: "Nuevo skill cargado",
      description:
        "Open Banking API audit (FAPI 1.0) · activado para engagement banco-cliente-12",
      actor: "admin@kryon.py",
    },
    {
      id: "act-010",
      timestamp: minus(418),
      type: "finding_detected",
      title: "Exposed credentials en repositorio",
      description:
        "AWS access key hardcoded detectada en api-gateway/.env · ChromaDB indexado",
      severity: "critical",
      actor: "kryon-appsec",
    },
  ];
}
