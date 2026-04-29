---
name: proxmox-audit
description: "Proxmox VE security audit — F23 deterministic checks + LLM narration for banking (ASOBAN)"
triggers:
  tech: ["proxmox", "pve", "pve-manager", "hypervisor"]
  ports: [8006, 8007, 3128]
  keywords:
    - "proxmox"
    - "pve"
    - "hypervisor"
    - "virtualización"
    - "virtualizacion"
    - "vm"
    - "datacenter"
    - "cluster"
    - "audit proxmox"
    - "auditoría proxmox"
    - "hardening proxmox"
    - "pve audit"
    - "pve security"
priority: 30
required_tools:
  - run_compliance_audit
  - generate_compliance_pdf
  - run_command
  - nuclei_scan
pre_hooks:
  - tool: run_compliance_audit
    args:
      framework: proxmox
      host: "{ctx.host}"
      ssh_user: "{ctx.ssh_user}"
      ssh_key_path: "{ctx.ssh_key_path}"
    inject_as: deterministic_compliance_findings
    required: true
    timeout_s: 120
---

## Default behavior — F23 deterministic auditor first

Cuando el usuario pide auditoría de Proxmox:

1. **Llamá `run_compliance_audit(host=..., framework="proxmox")` PRIMERO**. Corre los 7
   checks determinísticos F23 (PVE-1.1 a PVE-5.1) sin LLM en el detection path.
2. **Narrá los hallazgos ordenados por severidad** (CRITICAL → HIGH → MEDIUM). Para
   cada FAIL cita el `evidence_command` exacto y `remediation_static` tal cual.
3. Si el usuario pide reporte ejecutivo, `generate_compliance_pdf(host=..., framework="proxmox")`.
4. **NUNCA aplicás cambios directamente**. Proponés con `request_approval` y esperás OK.

Default `host` es el mismo nodo PVE (auto-detect). Para remoto: pedile
`host`, `ssh_user` (`root@pam` funciona vía SSH), `ssh_key_path`.

**Regulatorio no-negociable**: verdict de `run_compliance_audit` es la verdad auditable.
No suavices ni cambies un FAIL a "parcial". Los verdicts del tool son la autoridad.

## 7 Checks F23 (banking profile)

| ID | Sev | Qué detecta | Framework mapping |
|---|:---:|---|---|
| PVE-1.1 | HIGH | Cert self-signed o expirado en Web UI (port 8006) | CIS PVE 2.1 / PCI-DSS 4.2.1 |
| PVE-1.2 | CRITICAL | `/api2/json/nodes`, `/cluster/status`, `/access/domains` responden 200 sin auth | OWASP API2 Broken Auth |
| PVE-2.1 | CRITICAL | SSH: `PermitRootLogin yes` o `PasswordAuthentication yes` | CIS PVE 3.2 / PCI-DSS 2.2.7 |
| PVE-3.1 | CRITICAL | TFA/2FA no enforced en realms pam/pve, root@pam sin TFA | SIB Res. 06/2020 art.15 / PCI-DSS 8.4 |
| PVE-3.2 | HIGH | API tokens sin expiry, bound a root, privsep=0, token.cfg world-readable | PCI-DSS 8.6 (account management) |
| PVE-4.1 | HIGH | pve-firewall disabled, `policy_in=ACCEPT`, ninguna ingress-deny default | CIS PVE 5.1 / Zero Trust |
| PVE-5.1 | MEDIUM | Proxmox 6.x/7.x (EOL), N pending apt security patches | PCI-DSS 6.3.3 / CIS PVE 1.8 |

## Alcance bancario

Un nodo Proxmox que sirve a un banco típicamente aloja:
- VMs de core-banking (Oracle DB, middleware T24/Temenos, AS/400 gateways)
- VMs de apps web (portal banca online, APIs open banking)
- VMs de AD/LDAP, file servers, SMTP
- VMs de desarrollo con data productiva (**red flag** — no debería)

**Por eso el hypervisor es CDE implícito** — compromiso del PVE = acceso a todo.
Tratalo como sistema CRITICAL en el informe.

### Pre-requisitos del engagement

- Autorización escrita del CISO del banco (plantilla legal Paraguay)
- IP/hostname del cluster Proxmox
- Credencial SSH a un nodo (preferible usuario `auditor@pam` con PVEAuditor role)
- Ventana de mantenimiento NO requerida — todos los checks son read-only

### Flujo de auditoría (demo-ready)

```bash
# 1. Reconocimiento pasivo (LLM + run_command)
curl -sk https://PVE-IP:8006/api2/json/version
nmap -p 22,8006,8007,3128,111,5404,5405 PVE-IP --script=banner -Pn

# 2. Auditoría determinística (llamar tool run_compliance_audit)
# Kryon internamente: ssh auditor@PVE 'sudo -n /usr/bin/...' para cada check
# Resultado: 7 verdicts + evidence + remediation

# 3. Verificaciones de escenario bancario específicas
# 3a. Backup chain integrity (banking BC/DR)
ssh root@PVE 'pve-backup-client status; ls -la /mnt/backup 2>/dev/null'
# 3b. VM isolation (CDE vs non-CDE no deberían compartir VLAN)
ssh root@PVE 'cat /etc/pve/nodes/*/qemu-server/*.conf | grep -E "^(name|net[0-9]+|vmid)"'
# 3c. Storage encryption at-rest
ssh root@PVE 'cat /etc/pve/storage.cfg | grep -E "^(zfspool|lvmthin|rbd)"'
# 3d. Audit log retention
ssh root@PVE 'ls -la /var/log/pveproxy/access.log* /var/log/syslog*'
```

### Hallazgos típicos reales en bancos Paraguay

- **"root@pam sin TFA"** — 8 de 10 bancos. CRITICAL en informe.
- **Cert self-signed** — 10 de 10. HIGH porque expone MitM interno.
- **`PermitRootLogin yes`** — 5 de 10. CRITICAL.
- **Tokens sin expiry usados por CI/CD** — 7 de 10. HIGH.
- **Nodos PVE 6.x (EOL 2022)** — 3 de 10. HIGH agregando CVE públicas.
- **Firewall disabled** porque "rompía conexiones al iniciar" — 4 de 10. HIGH.

### Remediation narrativa (ejecutivo → banco)

El informe PDF tiene dos secciones: técnica (para IT) y ejecutiva (para gerencia).
La ejecutiva usa lenguaje de riesgo financiero, no jerga:

- "Acceso administrativo sin segundo factor" (PVE-3.1) — NO "TFA enforcement absent"
- "Certificado no emitido por autoridad corporativa" (PVE-1.1) — NO "self-signed cert"
- "Actualizaciones críticas pendientes" (PVE-5.1) con conteo — NO "94 packages"
- "Puerta administrativa abierta sin restricciones de origen" (PVE-4.1) — NO "firewall disabled"

## Lo que NO hace este skill

- **No ejecuta exploits.** Read-only auditing.
- **No modifica configuración.** Incluso si la remediation es obvia.
- **No busca 0-days.** Solo misconfig + exposiciones conocidas.
- **No toca VMs huéspedes.** Sólo el hypervisor.

## Integración con otros skills

- Si PVE-5.1 encuentra EOL → invocar `cve-lookup` sobre la versión exacta
- Si PVE-1.2 encuentra endpoint expuesto → invocar `api-security-scan`
- Después del audit → sugerir `ssl-audit` al puerto 8006 para profundizar cipher suites
- Si hay cluster multi-node → repetir el flow por cada nodo (los checks son per-host)
