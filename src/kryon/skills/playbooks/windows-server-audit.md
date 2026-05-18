---
name: windows-server-audit
description: "Windows Server + workstation audit — 15 checks deterministicos (SMBv1/LSA/Defender/BitLocker/LLMNR/UAC/RDP/LAPS) via WinRM"
triggers:
  tech: ["windows", "windows-server", "win32", "win64", "windows-10", "windows-11"]
  ports: [135, 139, 445, 3389, 5985, 5986]
  keywords:
    - "windows"
    - "windows server"
    - "windows audit"
    - "windows hardening"
    - "active directory member"
    - "workstation"
    - "puesto de trabajo"
    - "endpoint"
    - "domain controller"
    - "dc"
    - "winrm"
priority: 9
required_tools:
  - run_compliance_audit
  - generate_compliance_pdf
  - nmap
  - nuclei_scan
  - search_vulnerabilities
  - recall_similar_experiences
  - request_approval
pre_hooks:
  - tool: run_compliance_audit
    args:
      framework: windows
      host: "{ctx.host}"
      ssh_user: "{ctx.ssh_user}"
      ssh_key_path: "{ctx.ssh_key_path}"
    inject_as: deterministic_compliance_findings
    required: true
    timeout_s: 180
---

## Status del playbook

**Production-capable (F199).** 15 checks deterministicos
(WIN-1.1..WIN-4.2) cableados a `run_compliance_audit(framework="windows")`.
Los verdicts los produce el detector estático leyendo registry + service
states + Defender / BitLocker / LAPS / firewall via PowerShell remoto
(WinRM, ya implementado por F36). Hash de reproducibilidad estable.

## Pre-requisitos del engagement

- Autorización escrita del responsable de IT / dominio.
- **WinRM habilitado** en los hosts target (puerto 5985 HTTP o 5986 HTTPS).
  Si no está, habilitarlo via GPO:
  - Computer Config → Admin Templates → Windows Components → Windows Remote
    Management → WinRM Service → Allow remote server management through
    WinRM: Enabled
  - Reiniciar `Set-Service WinRM -StartupType Automatic; Start-Service WinRM`
- Credencial de dominio o local con permisos de lectura sobre los registry
  keys auditados. Para auditar GPO + LAPS + AD se necesita Domain User
  como mínimo.
- WinRM ACL: el usuario auditor debe estar en el `Builtin\\Remote Management
  Users` o equivalente.
- Ventana NO requerida — todos los checks son read-only.

## Default behavior

1. **Pre-engagement check**: confirmá autorización, IP/hostname del host
   target, credencial WinRM, ventana, si es DC o member o workstation
   (algunos checks como WIN-1.3 PrintNightmare aplican solo a DCs).
2. **Llamá `run_compliance_audit(host=..., framework="windows")` PRIMERO**.
   Corre los 15 checks F199 sin LLM en el detection path. Aliases válidos:
   `windows`, `win`, `windows-server`.
3. **Narrá los hallazgos** ordenados por severidad. Para cada FAIL cita el
   `evidence_command` exacto (PowerShell / auditpol / Get-Service) y la
   `remediation_static`.
4. Si el operador pide reporte ejecutivo, llamá
   `generate_compliance_pdf(host=..., framework="windows")`.
5. **NUNCA** intentes login con credenciales default. **NUNCA** modifiques
   registry ni servicios — el playbook es defensivo/auditor.

**Compliance mapping**: cada check se mapea a CIS Microsoft Windows Server
2022 / Windows 11 Enterprise Benchmark + PCI-DSS 4.0 controls relevantes.

## 15 Checks deterministicos

Los IDs `WIN-X.Y` corresponden 1:1 con módulos en
`src/kryon/compliance/checks/windows/`. Cada uno emite verdict
PASS / FAIL / N/A / ERROR + evidencia parsed + remediation.

### Vectores de compromiso críticos
| ID | Sev | Detección |
|---|:---:|---|
| WIN-1.1 | CRITICAL | SMBv1 habilitado (`Get-SmbServerConfiguration`) — vector EternalBlue |
| WIN-1.2 | CRITICAL | LSA Protection (RunAsPPL) deshabilitado — Mimikatz / lsass dump |
| WIN-1.3 | CRITICAL | Print Spooler running en DC — PrintNightmare CVE-2021-34527 |

### Defensa en profundidad
| ID | Sev | Detección |
|---|:---:|---|
| WIN-2.1 | HIGH | Defender RTP off (Get-MpComputerStatus) |
| WIN-2.2 | HIGH | Firewall dominio off (Get-NetFirewallProfile) |
| WIN-2.3 | HIGH | BitLocker off en C: (Get-BitLockerVolume) |
| WIN-2.4 | HIGH | LLMNR habilitado (EnableMulticast key) — Responder MITM |
| WIN-2.5 | HIGH | WSUS apuntando a servidor público — supply chain risk |

### Hardening de directiva
| ID | Sev | Detección |
|---|:---:|---|
| WIN-3.1 | MEDIUM | GPO refresh > 24 hrs — policy lag |
| WIN-3.2 | MEDIUM | LAPS no implementado — lateral movement pivot |
| WIN-3.3 | MEDIUM | Audit policy mínima ausente — sin trazas de ataque |
| WIN-3.4 | MEDIUM | RDP sin NLA — BlueKeep / pre-auth surface |
| WIN-3.5 | MEDIUM | UAC ConsentPromptBehaviorAdmin < 2 — elevación silenciosa |

### Higiene de servicios
| ID | Sev | Detección |
|---|:---:|---|
| WIN-4.1 | LOW | Remote Registry corriendo / no disabled |
| WIN-4.2 | MEDIUM | Sin EDR (Defender for Endpoint / CrowdStrike / SentinelOne / Tanium / etc.) |

## Comandos de auditoría (lo que ejecutan los checks)

Todos via WinRM PowerShell remoto:

```powershell
# WIN-1.1
(Get-SmbServerConfiguration).EnableSMB1Protocol
# WIN-1.2
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').RunAsPPL
# WIN-1.3
$pt = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType
$svc = (Get-Service Spooler).Status
# WIN-2.1
Get-MpComputerStatus | Select RealTimeProtectionEnabled
# WIN-2.2
(Get-NetFirewallProfile -Profile Domain).Enabled
# WIN-2.3
(Get-BitLockerVolume -MountPoint C:).ProtectionStatus
# WIN-2.4
(Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient').EnableMulticast
# WIN-2.5
(Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate').WUServer
# WIN-3.1
(Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\System').GroupPolicyRefreshTime
# WIN-3.2
Get-Module -ListAvailable -Name LAPS
# WIN-3.3
auditpol /get /category:*
# WIN-3.4
(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
# WIN-3.5
(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System').ConsentPromptBehaviorAdmin
# WIN-4.1
Get-Service RemoteRegistry
# WIN-4.2
Get-Service -Name @('Sense','CSFalconService','SentinelAgent','TaniumClient','QualysAgent','CarbonBlack',...)
```

No se ejecuta ningún comando de modificación. No se intenta auth a otros
servicios (solo PowerShell remoto sobre WinRM con la credencial del operador).

## Lo que NO está cubierto (roadmap v2)

- Active Directory full audit orquestado (F212 separado).
- IIS / MSSQL / Exchange hardening específicos.
- Sysmon configuration check.
- Audit trail forwarding (WEC / SIEM connection).
- Network share permissions enumeration.
- Local user enumeration + password age.
- Office macros / ASR rules.

## Reporting

Estructura sugerida para el reporte LLM-narrated:

```
Host: WS-OSCAR.britimp.local (Windows 11 Enterprise 22H2)
Role: Workstation (USR segment)
Findings:
  [CRITICAL] WIN-1.2: LSA Protection (RunAsPPL) absent — Mimikatz exposure
  [HIGH] WIN-2.3: BitLocker off on C: — physical theft → data exposure
  [HIGH] WIN-2.4: LLMNR enabled (EnableMulticast=1) — Responder vector
  [MEDIUM] WIN-3.4: RDP NLA disabled
  [MEDIUM] WIN-4.2: No EDR detected (Defender RTP off in WIN-2.1)
Remediation: see remediation_static fields in each result for exact PS commands.
```

Para Britimp POC (segmentos BASE USR 172.19.200.0/24 y TORRE USR
172.18.200.0/24, además de cualquier Windows Server en los segmentos
SVR), el audit corre via WinRM si está habilitado; en hosts donde
WinRM no esté disponible, el operador debe habilitarlo via GPO antes
de la ventana del POC.
