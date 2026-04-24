import type { Finding, FindingStatus, FrameworkId, Severity } from "../types";

// Deterministic PRNG so the findings list is stable across refreshes.
function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Real CVE catalog — mix of high-profile 2021-2026 issues that any security
// professional recognizes immediately. The detection frequency roughly
// mirrors what Kryon actually catches in field engagements.
const CVE_POOL: Array<{
  cve: string;
  title: string;
  cvss: number;
  severity: Severity;
  cwe: string;
  description: string;
  remediation: string;
  effort: number;
  automated: boolean;
  exploitable: boolean;
  frameworks: FrameworkId[];
  skill: string;
}> = [
  {
    cve: "CVE-2024-3094",
    title: "xz-utils 5.6.0/5.6.1 backdoor (liblzma)",
    cvss: 10,
    severity: "critical",
    cwe: "CWE-506",
    description:
      "La biblioteca liblzma de xz-utils contiene código malicioso introducido en los tarballs 5.6.0 y 5.6.1. Permite ejecución remota de código en servidores SSH vía injection en sshd.",
    remediation:
      "Downgrade inmediato a xz-utils 5.4.6 o versión previa. Auditar logs SSH para accesos anómalos desde marzo 2024.",
    effort: 2,
    automated: true,
    exploitable: true,
    frameworks: ["pci-dss", "iso-27001", "cis", "nist-800-53", "owasp"],
    skill: "kryon-supply-chain",
  },
  {
    cve: "CVE-2021-44228",
    title: "Apache Log4j RCE (Log4Shell)",
    cvss: 10,
    severity: "critical",
    cwe: "CWE-502",
    description:
      "Inyección JNDI en Log4j 2.0-2.14.1 permite ejecución remota de código arbitrario vía strings logueadas que contienen ${jndi:ldap://...}.",
    remediation:
      "Actualizar Log4j a 2.17.1+. Si no es posible, setear log4j2.formatMsgNoLookups=true y remover JndiLookup.class del classpath.",
    effort: 4,
    automated: true,
    exploitable: true,
    frameworks: ["pci-dss", "iso-27001", "cis", "owasp", "mitre-attack"],
    skill: "kryon-vuln-hunter",
  },
  {
    cve: "CVE-2024-6387",
    title: "OpenSSH regreSSHion — signal handler race",
    cvss: 8.1,
    severity: "critical",
    cwe: "CWE-364",
    description:
      "Race condition en sshd de OpenSSH 8.5p1-9.7p1 (glibc) permite ejecución remota de código como root sin autenticación. Exploit requiere ~10k intentos pero es viable.",
    remediation:
      "Actualizar OpenSSH a 9.8p1. Como mitigación temporal, ajustar LoginGraceTime a 0 y aplicar rate limiting en el firewall.",
    effort: 3,
    automated: true,
    exploitable: true,
    frameworks: ["pci-dss", "cis", "nist-800-53", "iso-27001"],
    skill: "kryon-server-hardening",
  },
  {
    cve: "CVE-2024-21413",
    title: "Microsoft Outlook NTLM credential leak",
    cvss: 9.8,
    severity: "critical",
    cwe: "CWE-20",
    description:
      "Outlook permite que un attacker lance Outlook con hyperlinks que bypassean Protected View, causando leak de credenciales NTLM v2 hacia servidores SMB remotos.",
    remediation:
      "Aplicar parche KB5034765. Deshabilitar NTLM donde sea posible. Bloquear SMB saliente (puerto 445) en firewall perimetral.",
    effort: 2,
    automated: true,
    exploitable: true,
    frameworks: ["cis", "nist-800-53", "mitre-attack"],
    skill: "kryon-safe-modification",
  },
  {
    cve: "CVE-2025-21298",
    title: "Windows OLE Remote Code Execution",
    cvss: 9.8,
    severity: "critical",
    cwe: "CWE-416",
    description:
      "Use-after-free en OLE de Windows permite RCE vía email malicioso en Outlook/Exchange. Parche de enero 2025.",
    remediation:
      "Aplicar Windows Update de enero 2025 (KB5049624 y variantes). No requiere reboot en la mayoría de hotfixes.",
    effort: 1,
    automated: true,
    exploitable: true,
    frameworks: ["pci-dss", "cis", "iso-27001"],
    skill: "kryon-safe-modification",
  },
  {
    cve: "CVE-2023-44487",
    title: "HTTP/2 Rapid Reset DDoS (nginx/haproxy/envoy)",
    cvss: 7.5,
    severity: "high",
    cwe: "CWE-400",
    description:
      "Abuso del cancel-stream en HTTP/2 permite ataques DDoS con ratios récord (>100M rps). Afecta nginx <1.25.3, haproxy, envoy, cloud LB.",
    remediation:
      "Actualizar nginx a 1.25.3+. Setear http2_max_concurrent_streams 128 y http2_max_requests 1000 como mitigación.",
    effort: 2,
    automated: true,
    exploitable: true,
    frameworks: ["pci-dss", "cis", "owasp"],
    skill: "kryon-pentest",
  },
  {
    cve: "CVE-2024-23897",
    title: "Jenkins CLI arbitrary file read",
    cvss: 9.8,
    severity: "critical",
    cwe: "CWE-22",
    description:
      "Jenkins CLI con argument parser (<2.441 / LTS <2.426.3) permite a un attacker no autenticado leer archivos arbitrarios del filesystem del controller.",
    remediation:
      "Actualizar Jenkins a 2.442 o LTS 2.426.3+. Deshabilitar acceso anónimo al CLI. Rotar todos los secrets de CI/CD.",
    effort: 3,
    automated: true,
    exploitable: true,
    frameworks: ["pci-dss", "iso-27001", "owasp", "nist-800-53"],
    skill: "kryon-appsec",
  },
  {
    cve: "CVE-2023-22515",
    title: "Atlassian Confluence — broken access control",
    cvss: 10,
    severity: "critical",
    cwe: "CWE-285",
    description:
      "Confluence Data Center/Server permite crear cuentas admin sin autenticación vía setup wizard reachable. Explotado in-the-wild desde oct/2023.",
    remediation:
      "Actualizar Confluence a 8.5.2+, 8.4.5+, 8.3.4+. Si no es posible, bloquear /setup/* en el proxy reverso.",
    effort: 2,
    automated: true,
    exploitable: true,
    frameworks: ["iso-27001", "nist-800-53", "cis"],
    skill: "kryon-vuln-hunter",
  },
  {
    cve: "CVE-2024-4577",
    title: "PHP CGI Windows argument injection",
    cvss: 9.8,
    severity: "critical",
    cwe: "CWE-88",
    description:
      "PHP en modo CGI en Windows (con locales chino/japonés) permite a attackers remotos inyectar argumentos vía Best-Fit encoding. RCE no autenticado.",
    remediation:
      "Actualizar PHP a 8.3.8 / 8.2.20 / 8.1.29. Migrar de CGI a FPM. Bloquear encoding Best-Fit en el servidor web.",
    effort: 5,
    automated: false,
    exploitable: true,
    frameworks: ["pci-dss", "owasp", "cis"],
    skill: "kryon-appsec",
  },
  {
    cve: "CVE-2024-21893",
    title: "Ivanti Connect Secure SSRF",
    cvss: 8.2,
    severity: "high",
    cwe: "CWE-918",
    description:
      "SSRF en el componente SAML de Ivanti Connect Secure/Policy Secure permite acceder a recursos restringidos sin autenticación. Cadena con CVE-2024-21887.",
    remediation:
      "Aplicar parches de febrero 2024. Rotar certificados. Factory reset recomendado si hay sospecha de compromiso.",
    effort: 8,
    automated: false,
    exploitable: true,
    frameworks: ["iso-27001", "nist-800-53", "mitre-attack"],
    skill: "kryon-recon-scout",
  },
  {
    cve: "CVE-2024-47176",
    title: "CUPS cups-browsed remote code execution",
    cvss: 9.0,
    severity: "critical",
    cwe: "CWE-78",
    description:
      "cups-browsed de CUPS escucha en UDP/631 y confía en anuncios remotos. Combinado con otros CVE-2024-47076/47175/47177 logra RCE sin auth.",
    remediation:
      "Deshabilitar cups-browsed si no se necesita: systemctl disable --now cups-browsed. Bloquear UDP/631 en firewall.",
    effort: 1,
    automated: true,
    exploitable: true,
    frameworks: ["cis", "nist-800-53"],
    skill: "kryon-server-hardening",
  },
  {
    cve: "CVE-2023-46604",
    title: "Apache ActiveMQ — deserialization RCE",
    cvss: 10,
    severity: "critical",
    cwe: "CWE-502",
    description:
      "ActiveMQ OpenWire protocol deserializa clases arbitrarias permitiendo RCE. Explotado por ransomware (HelloKitty) desde oct/2023.",
    remediation:
      "Actualizar ActiveMQ a 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3. Restringir acceso al puerto 61616 a clientes autorizados.",
    effort: 4,
    automated: true,
    exploitable: true,
    frameworks: ["pci-dss", "iso-27001", "nist-800-53"],
    skill: "kryon-vuln-hunter",
  },
  {
    cve: "CVE-2023-34362",
    title: "Progress MOVEit Transfer SQL injection",
    cvss: 9.8,
    severity: "critical",
    cwe: "CWE-89",
    description:
      "SQL injection en MOVEit Transfer permite a attackers no autenticados ejecutar comandos y robar archivos. Explotado masivamente por Cl0p desde mayo/2023.",
    remediation:
      "Actualizar MOVEit a 2023.0.1+. Auditar logs de acceso desde mayo/2023. Rotar credenciales de servicios que usaban MOVEit.",
    effort: 6,
    automated: false,
    exploitable: true,
    frameworks: ["pci-dss", "gdpr", "iso-27001", "soc2"],
    skill: "kryon-appsec",
  },
  {
    cve: "CVE-2024-30040",
    title: "Windows MSHTML feature bypass",
    cvss: 8.8,
    severity: "high",
    cwe: "CWE-693",
    description:
      "Bypass de feature de seguridad en MSHTML permite ejecución de código vía documentos Office maliciosos. Explotado en phishing dirigido.",
    remediation:
      "Aplicar parche de mayo 2024 (KB5037765). Bloquear macros de Office por defecto. Capacitación anti-phishing.",
    effort: 2,
    automated: true,
    exploitable: true,
    frameworks: ["cis", "nist-800-53", "mitre-attack"],
    skill: "kryon-safe-modification",
  },
  {
    cve: "CVE-2024-55956",
    title: "Cleo Harmony / VLTrader / LexiCom RCE",
    cvss: 9.8,
    severity: "critical",
    cwe: "CWE-22",
    description:
      "Bypass de autenticación + path traversal en productos Cleo MFT permite upload de archivos arbitrarios y RCE. Explotado por Cl0p desde dic/2024.",
    remediation:
      "Actualizar a Harmony/VLTrader/LexiCom 5.8.0.24+. Mover MFT fuera de internet si es posible. Auditar logs de diciembre 2024.",
    effort: 6,
    automated: false,
    exploitable: true,
    frameworks: ["pci-dss", "iso-27001", "gdpr"],
    skill: "kryon-vuln-hunter",
  },
  // Misconfigurations and weak crypto (no specific CVE)
  {
    cve: "",
    title: "SSH permite autenticación por contraseña en servidores críticos",
    cvss: 6.5,
    severity: "high",
    cwe: "CWE-262",
    description:
      "Detectado PasswordAuthentication=yes en 4 servidores tier-1. Compromete principio de least-privilege y facilita brute-force.",
    remediation:
      "Forzar autenticación por llave pública. Setear PasswordAuthentication no y PermitRootLogin no en /etc/ssh/sshd_config.",
    effort: 1,
    automated: true,
    exploitable: false,
    frameworks: ["pci-dss", "cis", "iso-27001"],
    skill: "kryon-server-hardening",
  },
  {
    cve: "",
    title: "Credencial AWS hardcodeada en repositorio",
    cvss: 7.5,
    severity: "high",
    cwe: "CWE-798",
    description:
      "AWS access key AKIA3K8... detectada en api-gateway/.env commiteada al repo interno. Kryon indexó el finding en ChromaDB para correlación.",
    remediation:
      "Rotar credenciales inmediatamente via AWS IAM. Reescribir historia git (BFG Repo-Cleaner). Migrar a AWS Secrets Manager o IAM roles.",
    effort: 3,
    automated: true,
    exploitable: true,
    frameworks: ["pci-dss", "owasp", "soc2", "iso-27001"],
    skill: "kryon-appsec",
  },
  {
    cve: "",
    title: "TLS 1.0 habilitado en endpoint público",
    cvss: 5.3,
    severity: "medium",
    cwe: "CWE-327",
    description:
      "Servidor portal-clientes acepta conexiones TLS 1.0. Deprecado desde 2018, vulnerable a BEAST, POODLE. Incumple PCI-DSS 4.0 desde marzo 2025.",
    remediation:
      "Deshabilitar TLS 1.0/1.1 en nginx/apache. Forzar TLS 1.2+ con suites modernas (Mozilla Modern). Validar con ssllabs.com.",
    effort: 1,
    automated: true,
    exploitable: false,
    frameworks: ["pci-dss", "iso-27001"],
    skill: "kryon-ssl-audit",
  },
  {
    cve: "",
    title: "HSTS no configurado en dominio principal",
    cvss: 4.3,
    severity: "medium",
    cwe: "CWE-319",
    description:
      "El dominio principal no envía header Strict-Transport-Security. Expuesto a ataques de downgrade y SSL stripping.",
    remediation:
      'Agregar header "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" en nginx/apache.',
    effort: 1,
    automated: true,
    exploitable: false,
    frameworks: ["owasp", "pci-dss"],
    skill: "kryon-appsec",
  },
  {
    cve: "",
    title: "Puerto SMB/445 expuesto a internet",
    cvss: 8.2,
    severity: "high",
    cwe: "CWE-200",
    description:
      "Detectado SMB abierto en IP pública. Superficie de ataque masiva (WannaCry, EternalBlue, etc.). Detectado por nmap scan.",
    remediation:
      "Cerrar 445 en firewall perimetral. SMB jamás debe estar expuesto a internet. Usar VPN para acceso remoto.",
    effort: 1,
    automated: true,
    exploitable: false,
    frameworks: ["cis", "pci-dss", "nist-800-53"],
    skill: "kryon-recon-scout",
  },
  {
    cve: "",
    title: "Backup sin cifrado en S3 bucket público",
    cvss: 8.8,
    severity: "high",
    cwe: "CWE-200",
    description:
      "S3 bucket s3://britimp-backups configurado con ACL public-read. Contiene dumps SQL de base de datos de clientes. Confirmado readable sin auth.",
    remediation:
      "Aplicar Block Public Access a nivel de cuenta + bucket. Habilitar SSE-KMS con CMK. Auditar CloudTrail para accesos pasados.",
    effort: 2,
    automated: true,
    exploitable: false,
    frameworks: ["gdpr", "pci-dss", "iso-27001", "soc2"],
    skill: "kryon-appsec",
  },
  {
    cve: "",
    title: "Política de contraseñas no cumple PCI-DSS 4.0",
    cvss: 4.0,
    severity: "medium",
    cwe: "CWE-521",
    description:
      "Active Directory configurado con mínimo 8 caracteres y sin complejidad requerida. PCI-DSS 4.0 exige 12+ y complejidad.",
    remediation:
      "GPO Default Domain Policy: password length 12+, complexity enabled, history 24, max age 90d, lockout después de 5 intentos.",
    effort: 2,
    automated: true,
    exploitable: false,
    frameworks: ["pci-dss", "cis", "iso-27001"],
    skill: "kryon-pci-audit",
  },
  {
    cve: "",
    title: "Logs de auditoría no centralizados (non-compliance)",
    cvss: 3.5,
    severity: "medium",
    cwe: "CWE-778",
    description:
      "7 de 12 servidores tier-1 no están enviando logs a SIEM centralizado. Imposibilita detección de amenazas cross-host y viola SOC 2.",
    remediation:
      "Configurar rsyslog/journald-remote con TLS hacia SIEM (Wazuh, Splunk). Validar retention de 1 año mínimo.",
    effort: 4,
    automated: true,
    exploitable: false,
    frameworks: ["soc2", "pci-dss", "iso-27001", "nist-800-53"],
    skill: "kryon-server-hardening",
  },
  {
    cve: "",
    title: "MFA no exigido en VPN corporativo",
    cvss: 7.0,
    severity: "high",
    cwe: "CWE-308",
    description:
      "VPN gateway acepta login solo con usuario+contraseña. Sin segundo factor. Alto riesgo con credenciales filtradas en dark web.",
    remediation:
      "Habilitar TOTP/FIDO2 en el VPN. Integrar con IdP corporativo (Azure AD / Google Workspace). Deprecar acceso sin MFA en 30 días.",
    effort: 3,
    automated: false,
    exploitable: false,
    frameworks: ["pci-dss", "iso-27001", "cis", "nist-800-53"],
    skill: "kryon-server-hardening",
  },
  {
    cve: "",
    title: "Webapp vulnerable a Reflected XSS",
    cvss: 6.1,
    severity: "medium",
    cwe: "CWE-79",
    description:
      "Parámetro 'q' del buscador refleja input sin sanitizar. Confirmado alert(1) con payload XSS clásico. Afecta sesiones logueadas.",
    remediation:
      "Sanitizar output con DOMPurify o equivalente. Habilitar Content-Security-Policy restrictivo. Cookie httpOnly+Secure+SameSite=Strict.",
    effort: 2,
    automated: false,
    exploitable: true,
    frameworks: ["owasp", "pci-dss"],
    skill: "kryon-appsec",
  },
];

const ASSETS: Array<{
  id: string;
  name: string;
  type: "server" | "endpoint" | "web" | "database" | "network" | "cloud";
}> = [
  { id: "srv-web-01", name: "web-srv-01.britimp.local", type: "server" },
  { id: "srv-web-02", name: "web-srv-02.britimp.local", type: "server" },
  { id: "srv-db-master", name: "db-master.britimp.local", type: "database" },
  { id: "srv-db-replica", name: "db-replica.britimp.local", type: "database" },
  { id: "srv-build-02", name: "build-srv-02.britimp.local", type: "server" },
  { id: "srv-app-03", name: "app-srv-03.britimp.local", type: "server" },
  { id: "srv-mail-01", name: "mail-srv-01.britimp.local", type: "server" },
  { id: "srv-jenkins", name: "jenkins.britimp.local", type: "server" },
  { id: "srv-confluence", name: "confluence.britimp.local", type: "web" },
  { id: "web-portal", name: "portal-clientes.britimp.com.py", type: "web" },
  { id: "web-www", name: "www.britimp.com.py", type: "web" },
  { id: "web-admin", name: "admin.britimp.com.py", type: "web" },
  { id: "ep-cfo", name: "laptop-cfo-marin", type: "endpoint" },
  { id: "ep-tes-03", name: "workstation-tesoreria-03", type: "endpoint" },
  { id: "ep-dev-07", name: "dev-workstation-07", type: "endpoint" },
  { id: "net-fw", name: "fw-perimeter-01", type: "network" },
  { id: "net-vpn", name: "vpn-gw-01", type: "network" },
  { id: "net-switch", name: "switch-core-asu-01", type: "network" },
  { id: "cloud-s3", name: "s3://britimp-backups", type: "cloud" },
  { id: "cloud-ec2", name: "ec2-web-pri-1", type: "cloud" },
];

const STATUSES: readonly FindingStatus[] = [
  "open",
  "open",
  "open",
  "open",
  "triaging",
  "triaging",
  "confirmed",
  "confirmed",
  "remediating",
  "remediating",
  "fixed",
  "accepted",
  "false_positive",
] as const;

export function getFindings(): Finding[] {
  const rng = mulberry32(123);
  const findings: Finding[] = [];
  const now = new Date();

  for (let i = 0; i < 150; i++) {
    const template = CVE_POOL[Math.floor(rng() * CVE_POOL.length)];
    const asset = ASSETS[Math.floor(rng() * ASSETS.length)];
    const status = STATUSES[Math.floor(rng() * STATUSES.length)];
    const ageDays = Math.floor(rng() * 45);

    const detectedAt = new Date(now);
    detectedAt.setDate(detectedAt.getDate() - ageDays);
    detectedAt.setHours(detectedAt.getHours() - Math.floor(rng() * 24));

    findings.push({
      id: `KRY-${String(10000 + i).padStart(5, "0")}`,
      title: template.title,
      description: template.description,
      severity: template.severity,
      cve: template.cve || undefined,
      cvss: template.cvss,
      cwe: template.cwe,
      frameworks: template.frameworks,
      assetId: asset.id,
      assetName: asset.name,
      status,
      detectedAt: detectedAt.toISOString(),
      ageDays,
      remediation: {
        summary: template.remediation,
        effortHours: template.effort,
        automated: template.automated,
      },
      kryonSkill: template.skill,
      exploitable: template.exploitable,
    });
  }

  // Sort by severity desc, then CVSS desc, then age desc
  const severityOrder: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  findings.sort((a, b) => {
    const sev = severityOrder[a.severity] - severityOrder[b.severity];
    if (sev !== 0) return sev;
    const cvss = (b.cvss ?? 0) - (a.cvss ?? 0);
    if (cvss !== 0) return cvss;
    return b.ageDays - a.ageDays;
  });

  return findings;
}

export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Abierto",
  triaging: "En triaje",
  confirmed: "Confirmado",
  remediating: "Remediando",
  fixed: "Resuelto",
  accepted: "Riesgo aceptado",
  false_positive: "Falso positivo",
};

export const STATUS_TONES: Record<FindingStatus, string> = {
  open: "text-[var(--critical)] bg-[var(--critical)]/10 border-[var(--critical)]/30",
  triaging: "text-[var(--warning)] bg-[var(--warning)]/10 border-[var(--warning)]/30",
  confirmed: "text-[var(--critical)] bg-[var(--critical)]/10 border-[var(--critical)]/30",
  remediating: "text-primary bg-primary/10 border-primary/30",
  fixed: "text-[var(--success)] bg-[var(--success)]/10 border-[var(--success)]/30",
  accepted: "text-muted-foreground bg-muted border-border",
  false_positive: "text-muted-foreground bg-muted border-border",
};
