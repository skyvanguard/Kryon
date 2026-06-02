---
name: pci-dss-audit
description: "PCI-DSS v4 compliance audit — F15.1 deterministic engine + LLM narration"
triggers:
  tech: []
  ports: [443, 8443]
  keywords:
    - "pci"
    - "pci-dss"
    - "tarjetas"
    - "cardholder"
    - "cde"
    - "pan"
    - "cardholder data"
    - "compliance"
    - "cumplimiento"
    - "audit"
    - "auditoría"
    - "auditoria"
    - "auditá"
    - "audita"
    - "hardening"
    - "endurecimiento"
    - "regulación"
    - "regulacion"
priority: 25
required_tools:
  - run_compliance_audit
  - generate_compliance_pdf
  - run_command
  - nuclei_scan
pre_hooks:
  - tool: run_compliance_audit
    args:
      framework: pci-dss
      host: "{ctx.host}"
      ssh_user: "{ctx.ssh_user}"
      ssh_key_path: "{ctx.ssh_key_path}"
    inject_as: deterministic_compliance_findings
    required: true
    timeout_s: 180
---

## Coverage — 40 deterministic checks (as of F39.2)

The PCI baseline ships **40 controls** wired into `run_compliance_audit`:

- **6 hand-written Python** in `src/kryon/compliance/checks/section_*`:
  2.2.2, 2.2.7, 6.3.3, 6.4.1, 8.3.6, 10.2.1.
- **34 YAML-based** in `src/kryon/compliance/cis/frameworks/pci-dss-4.0.yaml`,
  registered automatically by the runner. IDs span Req 1, 2, 3, 4, 5,
  8, 10, 11.

The runner deduplicates by `control_id` so the YAML never silently
shadows a Python check (test pinned: `tests/compliance/test_pci_dss_4_0.py
::test_runner_registers_full_pci_baseline`).

Out of scope (organizational / policy-only PCI requirements not
amenable to deterministic ssh checks): training records, signed NDAs,
retention period documents, vendor risk-assessment artifacts. Those
are auditor manual-review items.

## Default behavior — F15.1 deterministic auditor first

Cuando el usuario pide compliance / audit / hardening:

1. **Llamá `run_compliance_audit(host=...)` PRIMERO**. Es determinístico, reproducible,
   sin LLM en el detection path. Output JSON con verdicts + evidence.
2. **Narrá los hallazgos al usuario** ordenados por severidad (FAIL críticos primero,
   después FAIL high, después PASS, finalmente N/A).
3. Para cada FAIL, citá el `evidence_command` exacto y el `remediation_static`
   tal cual — NO inventes comandos alternativos. El operador necesita poder
   reproducir el finding manualmente.
4. Si el usuario pide PDF / reporte / informe, llamá `generate_compliance_pdf(host=...)`.
5. Si el usuario quiere remediar, **NUNCA modificás directamente** — proponés con
   `request_approval` y esperás OK explícito antes de aplicar.

Default `host="localhost"` para self-audit del propio servidor donde corre Kryon.
Para targets remotos: pedile al usuario `host`, `ssh_user`, `ssh_key_path`.

**Boundary regulatorio (no negociable)**: el verdict que reporta `run_compliance_audit`
es la verdad auditable. Vos NUNCA cambiás un FAIL a "parcialmente cumple" o suavizás
lenguaje regulatorio. Si querés agregar contexto, marcalo como tal — los verdicts del
tool son la autoridad.

## PCI-DSS v4.0.1 Audit

Playbook para auditoría de cumplimiento PCI-DSS en entornos bancarios y
procesadores de tarjetas. Cubre las 12 requerimientos mapeados a 6 objetivos.

### Pre-requisitos

- Identificar el **Cardholder Data Environment (CDE)**: qué sistemas tocan PAN
- SAQ level correspondiente (A, A-EP, B, B-IP, C, C-VT, D)
- Alcance: todos los sistemas conectados al CDE son auditables

### Objetivo 1: Build and Maintain Secure Network

**Req 1**: Firewalls — ¿hay inbound/outbound rules restrictivas?
```bash
iptables -L -n --line-numbers | head -40
ufw status verbose
# Verificar que no hay rules 0.0.0.0/0 → CDE
```

**Req 2**: Default passwords y configs
```bash
# Buscar default creds comunes
mysql -u root -pBYPASS -e "SELECT User,Host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL"
# SSH default
grep -i "PermitRootLogin\|PasswordAuth" /etc/ssh/sshd_config
# Default SNMP community
snmpwalk -v2c -c public TARGET 2>/dev/null | head -5
```

### Objetivo 2: Protect Cardholder Data

**Req 3**: Almacenamiento de CHD
```bash
# Buscar PAN patterns en archivos (16-digit numbers matching card BINs)
grep -rE '\b4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b' /var/www /opt /home 2>/dev/null | head -20  # Visa
grep -rE '\b5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b' /var/www /opt /home 2>/dev/null | head -20  # Mastercard
# Validar Luhn check — solo reportar números que pasen Luhn
# NO EXTRAER los PANs completos al informe — usar solo los primeros 6 + últimos 4 (BIN + last4)
```

**Req 4**: Transmisión cifrada
```bash
# SSL/TLS del endpoint
testssl.sh --severity HIGH TARGET:443
# Verificar cipher suites, TLS versions, HSTS
nmap --script ssl-enum-ciphers -p 443 TARGET
```

### Objetivo 3: Maintain Vulnerability Management

**Req 5**: Anti-virus / malware
```bash
# Verificar AV activo en servidores
systemctl status clamav-daemon 2>/dev/null
systemctl status crowdstrike-falcon 2>/dev/null
# Windows: Get-MpComputerStatus
```

**Req 6**: Secure dev — buscar vulns conocidos
```bash
# Escaneo de vulnerabilidades
nuclei -t cves/ -u https://TARGET -severity critical,high
# Audit de dependencias
npm audit --audit-level=high
pip-audit --strict
```

### Objetivo 4: Implement Strong Access Control

**Req 7**: Principio de menor privilegio
```bash
# Users con shell + sudo
cat /etc/passwd | grep -E '/bin/(bash|sh|zsh)'
grep -v '^#\|^$' /etc/sudoers /etc/sudoers.d/*
# RBAC en apps — revisar roles
```

**Req 8**: Autenticación MFA
```bash
# Verificar MFA en SSH
grep -i "ChallengeResponseAuth\|AuthenticationMethods" /etc/ssh/sshd_config
# PAM MFA (Google Authenticator, Duo)
ls /etc/pam.d/ | xargs -I{} grep -l "pam_google_authenticator\|pam_duo" /etc/pam.d/{} 2>/dev/null
```

**Req 9**: Restringir acceso físico (fuera de scope para pentest remoto)

### Objetivo 5: Monitor and Test

**Req 10**: Logging y monitoreo
```bash
# Log forwarding a SIEM
grep -r "@@\|action.*forwardDefault" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
# auditd
systemctl status auditd
auditctl -l | head -20
```

**Req 11**: Pruebas de seguridad regulares
- Internal vuln scan (trimestral)
- External scan by ASV (trimestral)
- Pentest anual (interno + externo)
- Segmentation testing
- Change detection (FIM con AIDE/Tripwire)

**Req 12**: Política de seguridad de la información

### Findings tipo CRÍTICO (auto-fail)

- PAN en claro en archivos, logs, DB
- Default credentials en componentes CDE
- TLS 1.0/1.1 habilitado
- Puertos admin (3306, 5432, 22) abiertos a 0.0.0.0/0
- Sin WAF delante de apps web que manejan PAN
- Falta de FIM en CDE
- Logs sin ingesta a SIEM

### Informe final

Para cada requerimiento: **PASS / FAIL / NOT APPLICABLE / COMPENSATING CONTROL**

Mapear findings a:
- Req específico (1.1.1, 3.4.1, etc.)
- CVSS score
- Remediation timeline (Critical 30 días, High 60, Medium 90)
