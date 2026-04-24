export type ScanStatus = "queued" | "running" | "completed" | "failed";

export interface Scan {
  id: string;
  target: string;
  targetType: "network" | "host" | "web" | "code";
  skills: string[];
  startedAt: string;
  finishedAt?: string;
  durationSeconds?: number;
  status: ScanStatus;
  progressPercent?: number;
  findingsCount?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  triggeredBy: string;
  currentStep?: string;
}

export function getScans(): Scan[] {
  const now = new Date();
  const minus = (h: number) => {
    const d = new Date(now);
    d.setHours(d.getHours() - h);
    return d.toISOString();
  };

  return [
    {
      id: "scan-0142",
      target: "10.20.0.0/16",
      targetType: "network",
      skills: ["recon-scout", "vuln-hunter", "server-hardening"],
      startedAt: minus(0.2),
      status: "running",
      progressPercent: 67,
      triggeredBy: "admin@kryon.py",
      currentStep: "nuclei_scan ejecutándose en 47 hosts",
    },
    {
      id: "scan-0141",
      target: "portal-clientes.britimp.com.py",
      targetType: "web",
      skills: ["pentest", "appsec", "ssl-audit"],
      startedAt: minus(2.1),
      finishedAt: minus(1.8),
      durationSeconds: 1080,
      status: "completed",
      findingsCount: { critical: 1, high: 3, medium: 8, low: 4, info: 2 },
      triggeredBy: "admin@kryon.py",
    },
    {
      id: "scan-0140",
      target: "git@github.com:britimp/api-gateway",
      targetType: "code",
      skills: ["appsec", "safe-modification"],
      startedAt: minus(4.5),
      finishedAt: minus(4.3),
      durationSeconds: 720,
      status: "completed",
      findingsCount: { critical: 1, high: 2, medium: 5, low: 3, info: 0 },
      triggeredBy: "ci-pipeline",
    },
    {
      id: "scan-0139",
      target: "confluence.britimp.local",
      targetType: "host",
      skills: ["vuln-hunter"],
      startedAt: minus(8.0),
      finishedAt: minus(7.7),
      durationSeconds: 1080,
      status: "completed",
      findingsCount: { critical: 1, high: 1, medium: 2, low: 1, info: 0 },
      triggeredBy: "admin@kryon.py",
    },
    {
      id: "scan-0138",
      target: "PCI-DSS scope (cardholder env)",
      targetType: "network",
      skills: ["pci-dss-audit", "server-hardening"],
      startedAt: minus(14.0),
      finishedAt: minus(13.1),
      durationSeconds: 3240,
      status: "completed",
      findingsCount: { critical: 0, high: 2, medium: 7, low: 3, info: 1 },
      triggeredBy: "scheduler",
    },
    {
      id: "scan-0137",
      target: "10.20.10.0/24 (DMZ)",
      targetType: "network",
      skills: ["recon-scout", "server-hardening"],
      startedAt: minus(19.0),
      finishedAt: minus(18.7),
      durationSeconds: 1080,
      status: "failed",
      findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      triggeredBy: "scheduler",
    },
    {
      id: "scan-0136",
      target: "www.britimp.com.py",
      targetType: "web",
      skills: ["pentest", "ssl-audit", "wordpress-audit"],
      startedAt: minus(26.0),
      finishedAt: minus(25.5),
      durationSeconds: 1800,
      status: "completed",
      findingsCount: { critical: 0, high: 1, medium: 4, low: 5, info: 3 },
      triggeredBy: "admin@kryon.py",
    },
    {
      id: "scan-0135",
      target: "SWIFT CSP v2024 scope",
      targetType: "network",
      skills: ["swift-network-security"],
      startedAt: minus(42.0),
      finishedAt: minus(40.0),
      durationSeconds: 7200,
      status: "completed",
      findingsCount: { critical: 0, high: 1, medium: 3, low: 2, info: 4 },
      triggeredBy: "admin@kryon.py",
    },
    {
      id: "scan-0134",
      target: "Active Directory (4 DCs)",
      targetType: "network",
      skills: ["vuln-hunter", "server-hardening"],
      startedAt: minus(50.0),
      finishedAt: minus(49.5),
      durationSeconds: 1800,
      status: "completed",
      findingsCount: { critical: 0, high: 2, medium: 4, low: 3, info: 1 },
      triggeredBy: "scheduler",
    },
    {
      id: "scan-0133",
      target: "ISO 27001 full evaluation",
      targetType: "network",
      skills: ["pci-dss-audit", "server-hardening", "ssl-audit"],
      startedAt: minus(72.0),
      finishedAt: minus(70.5),
      durationSeconds: 5400,
      status: "completed",
      findingsCount: { critical: 1, high: 3, medium: 12, low: 8, info: 4 },
      triggeredBy: "demo@britimp.com.py",
    },
    {
      id: "scan-0132",
      target: "jenkins.britimp.local",
      targetType: "host",
      skills: ["appsec", "vuln-hunter"],
      startedAt: minus(96.0),
      finishedAt: minus(95.8),
      durationSeconds: 720,
      status: "completed",
      findingsCount: { critical: 1, high: 1, medium: 1, low: 0, info: 0 },
      triggeredBy: "ci-pipeline",
    },
    {
      id: "scan-0131",
      target: "s3://britimp-backups",
      targetType: "host",
      skills: ["appsec"],
      startedAt: minus(120.0),
      finishedAt: minus(119.9),
      durationSeconds: 360,
      status: "completed",
      findingsCount: { critical: 0, high: 1, medium: 2, low: 0, info: 1 },
      triggeredBy: "admin@kryon.py",
    },
  ];
}

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  queued: "En cola",
  running: "En ejecución",
  completed: "Completado",
  failed: "Fallido",
};

export const SCAN_STATUS_TONES: Record<ScanStatus, string> = {
  queued: "text-muted-foreground bg-muted border-border",
  running: "text-primary bg-primary/10 border-primary/30",
  completed:
    "text-[var(--success)] bg-[var(--success)]/10 border-[var(--success)]/30",
  failed:
    "text-[var(--critical)] bg-[var(--critical)]/10 border-[var(--critical)]/30",
};

export const TARGET_TYPE_LABELS: Record<Scan["targetType"], string> = {
  network: "Red",
  host: "Host",
  web: "Web app",
  code: "Código",
};
