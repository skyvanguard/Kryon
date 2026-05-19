# Audit Oficial Britimp — Prerequisites + Playbook

> Documento de trabajo para Osvaldo / operador. Generado a partir del POC
> exploratorio 2026-05-18/19 (43 hosts auditados + 7 con creds + 4 segmentos
> cubiertos). Lo que falta para el **audit oficial completo**.

---

## 0. Pre-flight check

Antes de cualquier engage oficial, correr:

```powershell
powershell -ExecutionPolicy Bypass `
  -File C:/Users/skyva/Documents/Kryon/scripts/audit_oficial_britimp_preflight.ps1
```

Esperás output **STATUS: READY**. Si está NO ESTA LISTO o BLOQUEADO, completar
las secciones siguientes antes de seguir.

---

## 1. Tooling Kryon — requerido en el host del operador

| Tool | Para qué | Cómo instalar |
|---|---|---|
| `uv` | Python deps | https://docs.astral.sh/uv/ |
| `kryon` CLI | engage runner | `uv sync --all-extras` |
| `nmap` | service discovery | `choco install nmap` |
| Ollama | local model (`kryon-gpt-oss`) | `docker compose up kryon-ollama` |
| `dig` | F202.D cache-snoop | opcional — sino correr engage en Docker |
| `smbclient` | F202.Q SMB enum | opcional — sino correr en Docker |

**Recomendación**: para audit oficial, correr todo dentro del **contenedor Docker
kryon-kryon-1** que ya tiene `dig`, `smbclient`, `nmap` y todas las deps. El
host Windows del operador funciona pero pierde F202.D + F202.Q por falta de
herramientas.

---

## 2. Network connectivity — segmentos Britimp

| Segmento | IP gateway | Status POC | Notas para audit oficial |
|---|---|---|---|
| TORRE_SVR | 172.18.201.1 | ✓ UP | 29 hosts UP, todos auditados |
| TORRE_VOIP | 172.18.202.1 | ✓ UP | 3 hosts (Asterisk PBX + IP phone + admin) |
| TORRE_USR/CCTV | 172.18.203.1 | ✓ UP | 2 Hikvision DVRs |
| TORRE_EXTRA | 172.18.204.1 | gateway only | Sin hosts UP confirmados |
| BASE .203 (CCTV) | 172.19.203.1 | ✓ UP | **35 cámaras Hikvision** (BGP TCP/179 expuesto en .1) |
| BASE .202 | 172.19.202.1 | gateway only | Sin hosts UP confirmados |
| **Mgmt VLAN 200** | 172.18.200.1 | ❌ no alcanzable desde VPN | **REQUIERE routeo extra** |

**Acción requerida**: Osvaldo debe coordinar con el equipo de red para que el VPN
del auditor llegue a **172.18.200.0/24** directamente (sin pivot via .115). Sin
esto, los 30+ hosts del segmento mgmt (NAS .26, PBS .10, impresoras Kyocera,
etc.) no se auditan automáticamente.

---

## 3. SSH access — Lo que ya tenemos

`~/.ssh/id_ed25519` (key del jumphost) tiene acceso confirmado a:

| Host | Función |
|---|---|
| .115 (proxmox2, PVE 9.1.4) | Proxmox cluster master |
| .222 (pve-torre-prod, PVE 9.1.8) | Proxmox node 2 |
| .200 (pve-britimp, PVE 8.4.16) | Proxmox node 3 (aislado del cluster) |
| .18 (Odoo Enterprise) | ERP banking workload |
| .121 (Odoo Community) | LXC en cluster |
| .110 (Reporting-itau) | **Cliente Itaú** Docker host |
| .119 (dashboards-hub) | Britos + Giva dashboards |

---

## 4. SSH access — Lo que FALTA

Estos hosts rechazan la key común. **Solicitar creds separadas**:

| Host | Función | Banking impact | Recomendación |
|---|---|---|---|
| **.99 britimp-llavero** | Vault corporativo | **CRITICAL** | Key dedicada del vault — solicitar al admin del Vaultwarden |
| **.117 CentOS 7 + OpenSSH 8.0** | Legacy host | HIGH (regreSSHion CVE-2024-6387) | Creds gssapi/AD-integrated probable |
| **.150 PostgreSQL 9.6 EOL** | DB CRITICAL | **CRITICAL** | Creds + MFA token |
| **.123 DB** | DB sin identificar | HIGH | Creds DB-specific |

**Plantilla de mensaje para solicitar creds**:

```
Asunto: Audit oficial Britimp — creds SSH segmentadas requeridas

Hola Osvaldo,

Para el audit oficial Kryon necesito acceso SSH a los siguientes hosts
del segmento que tienen autenticación diferente del jumphost:

  - 172.18.201.99  (britimp-llavero / vault)
  - 172.18.201.117 (CentOS 7 legacy)
  - 172.18.201.150 (PostgreSQL 9.6 — host critical)
  - 172.18.201.123 (DB)

Para cada host necesito:
  - Usuario SSH (root o user con sudo NOPASSWD)
  - Key SSH (preferible) o password vía canal seguro
  - Si tiene MFA: confirmar mecanismo (TOTP, hardware token, etc.)

El audit es READ-ONLY (dry-run-only, no red team). Banca-safe throttle
activo. La sesión se hace con creds que rotamos después del audit.

Saludos
```

---

## 5. WinRM access — Windows hosts (CRÍTICO faltante)

8 hosts Windows del segmento. **WinRM no se probó con creds en POC** —
requiere autenticación dominio AD `britimp.com.py`.

| Host | Identificación POC |
|---|---|
| .5 (pve-britimp-dc2 probable) | DC secundario `britimp.com.py` |
| .205 (pve-britimp-dc1 probable) | DC primario `britimp.com.py` (DNSSEC OFF + recursion abierta) |
| .13 | Windows + DBs mixed |
| .15 | Windows + SQL Server 2019 |
| .19 | Windows member + IIS + SSH-for-Windows |
| .100 | Windows member + RDP |
| .101 | Windows + IIS:8080 (http-admin-open HIGH) |
| .103 | Windows + SQL Server + IIS |

**Acción requerida**:

1. **Habilitar WinRM** en cada host si no está (esperamos que ya esté para Group Policy management):
   ```powershell
   Enable-PSRemoting -Force
   winrm quickconfig
   winrm set winrm/config/service '@{AllowUnencrypted="false"}'
   ```

2. **Crear cuenta de servicio de auditoría** `audit-kryon@britimp.com.py`:
   - Miembro de **Domain Users** + grupo local **Performance Monitor Users**
   - **Read-only**: NO modify rights
   - Password con MFA si la política lo permite
   - Rotación: deshabilitar/cambiar después del audit

3. **Validar acceso** desde el operador:
   ```powershell
   $cred = Get-Credential audit-kryon@britimp.com.py
   Invoke-Command -ComputerName 172.18.201.5 -Credential $cred -ScriptBlock { hostname; Get-ComputerInfo | Select-Object OsName, OsVersion }
   ```

4. **Wire en Kryon** (cuando se corra el audit oficial):
   ```bash
   uv run kryon engage 172.18.201.5 \
     --framework windows,active_directory \
     --winrm audit-kryon@britimp.com.py \
     --winrm-password $env:WINRM_PASS \
     --client britimp-internal --dry-run-only
   ```

---

## 6. NDAs / Autorización scope

| Cliente / Asset | Status | Pendiente |
|---|---|---|
| **Britimp interno** | ✓ POC autorizado | Confirmar scope final con Osvaldo |
| **Cliente Itaú** (.110 reporting) | ❓ | NDA Itaú si su data está en scope |
| **Cliente Giva** (.111 dashboards, .130 bases) | ❓ | NDA Giva si DBs están en scope |
| **Cliente TEISA** (.200.26 RPA share) | ❓ | NDA TEISA si RPA-share está en scope |
| **Britos** (producto interno) | ✓ (es Britimp propio) | n/a |

**Documento formal recomendado**: Statement of Work (SOW) firmado entre Britimp y
auditor, con:
- Lista explícita de hosts en scope (autorizar específicos vs todo el segmento)
- Tipo de actividades autorizadas (read-only, dry-run-only, NO red-team)
- Ventana horaria (banca-safe horario laboral)
- Notificación pre-audit a stakeholders (operations, ITSM, IDS team)
- Procedimiento de incident-response si el audit dispara alertas

---

## 7. Configuración Kryon — env vars para audit oficial

Crear `audit_oficial_britimp.ps1` con:

```powershell
# Banca-safe throttle obligatorio
$env:KRYON_NMAP_TIMING = 'T2'
$env:KRYON_NMAP_MIN_RATE = '50'
$env:KRYON_NMAP_MAX_PARALLELISM = '10'
$env:KRYON_NUCLEI_RATE_LIMIT = '50'
$env:KRYON_NUCLEI_BULK_SIZE = '10'
$env:KRYON_NUCLEI_CONCURRENCY = '10'

# Safety
$env:KRYON_RED_TEAM = 'false'
$env:KRYON_STREAM = 'false'
$env:KRYON_FORCE_TOOL_TURNS = '8'
$env:KRYON_TELEMETRY = 'false'

# Local model (F162-F189 stack validated)
$env:OPENAI_API_KEY = 'ollama'
$env:OPENAI_BASE_URL = 'http://localhost:11435/v1'
$env:OLLAMA = 'true'
$env:KRYON_MODEL = 'kryon-gpt-oss'
$env:KRYON_TRIAGE_MODEL = 'kryon-gpt-oss'
$env:KRYON_RAG_MODEL = 'kryon-gpt-oss'
$env:KRYON_GUARDRAIL_MODEL = 'kryon-gpt-oss'
$env:KRYON_COMPLIANCE_NARRATOR_MODEL = 'kryon-gpt-oss'
$env:KRYON_EMBEDDING_MODEL = 'nomic-embed-text'
$env:KRYON_EMBEDDING_BASE_URL = 'http://localhost:11435'

# Output directory
$env:KRYON_AUDIT_OUT = 'C:/Users/skyva/Documents/Kryon/.kryon/audit-oficial-britimp'
New-Item -ItemType Directory -Force -Path $env:KRYON_AUDIT_OUT | Out-Null
```

**Cambio importante vs POC**: para audit oficial usar `--nmap-timeout 1800` (30
min) en lugar de 1110s, porque con creds los engages tardan más (compliance
checks SSH + WinRM).

---

## 8. Comandos para el audit oficial

### 8.1 Engage individual por host crítico

```powershell
# Proxmox cluster — los 3 nodos en sucesión
foreach ($node in @('115', '200', '222')) {
    uv run kryon engage 172.18.201.$node `
        --framework proxmox `
        --ssh root@172.18.201.$node `
        --ssh-key C:/Users/skyva/.ssh/id_ed25519 `
        --client britimp-internal `
        --out $env:KRYON_AUDIT_OUT/pve-$node `
        --engagement-id britimp-pve-$node `
        --nmap-timeout 1800 `
        --max-turns 15 `
        --dry-run-only --skip-reaudit
}

# Odoo + Itaú + dashboards (key id_ed25519)
$linuxHosts = @(
    @{ IP='172.18.201.18'; User='root'; Tag='odoo-enterprise' },
    @{ IP='172.18.201.121'; User='root'; Tag='odoo-community' },
    @{ IP='172.18.201.110'; User='ubuntu'; Tag='reporting-itau' },
    @{ IP='172.18.201.119'; User='ubuntu'; Tag='dashboards-hub' }
)
foreach ($h in $linuxHosts) {
    uv run kryon engage $h.IP `
        --ssh "$($h.User)@$($h.IP)" `
        --ssh-key C:/Users/skyva/.ssh/id_ed25519 `
        --client britimp-internal `
        --out "$env:KRYON_AUDIT_OUT/$($h.Tag)" `
        --engagement-id "britimp-$($h.Tag)" `
        --nmap-timeout 1800 `
        --dry-run-only --skip-reaudit
}

# Vault + DBs (creds dedicated — pendiente)
$secureHosts = @(
    @{ IP='172.18.201.99'; User='root'; Tag='britimp-llavero'; KeyVar='LLAVERO_KEY' },
    @{ IP='172.18.201.150'; User='root'; Tag='postgres-150'; KeyVar='PG150_KEY' },
    @{ IP='172.18.201.117'; User='root'; Tag='centos7-legacy'; KeyVar='CENTOS_KEY' },
    @{ IP='172.18.201.123'; User='root'; Tag='db-123'; KeyVar='DB123_KEY' }
)
foreach ($h in $secureHosts) {
    $keyPath = (Get-Item "Env:$($h.KeyVar)" -ErrorAction SilentlyContinue).Value
    if (-not $keyPath) {
        Write-Host "SKIP $($h.Tag): falta env var $($h.KeyVar) con path a la key dedicada"
        continue
    }
    uv run kryon engage $h.IP `
        --ssh "$($h.User)@$($h.IP)" `
        --ssh-key $keyPath `
        --client britimp-internal `
        --out "$env:KRYON_AUDIT_OUT/$($h.Tag)" `
        --engagement-id "britimp-$($h.Tag)" `
        --nmap-timeout 1800 `
        --dry-run-only --skip-reaudit
}

# Windows hosts (WinRM)
$winHosts = @(
    @{ IP='172.18.201.5'; Tag='dc2-britimp' },
    @{ IP='172.18.201.205'; Tag='dc1-britimp' },
    @{ IP='172.18.201.13'; Tag='win13-dbs' },
    @{ IP='172.18.201.15'; Tag='win15-mssql' },
    @{ IP='172.18.201.19'; Tag='win19' },
    @{ IP='172.18.201.100'; Tag='win100' },
    @{ IP='172.18.201.101'; Tag='win101-iis8080' },
    @{ IP='172.18.201.103'; Tag='win103-mssql' }
)
$winrmUser = 'audit-kryon@britimp.com.py'
$winrmPass = Read-Host -AsSecureString "WinRM password"
foreach ($h in $winHosts) {
    uv run kryon engage $h.IP `
        --framework windows,active_directory `
        --winrm $winrmUser `
        --winrm-password $winrmPass `
        --client britimp-internal `
        --out "$env:KRYON_AUDIT_OUT/$($h.Tag)" `
        --engagement-id "britimp-$($h.Tag)" `
        --nmap-timeout 1800 `
        --dry-run-only --skip-reaudit
}
```

### 8.2 Cross-host drift analysis (F202.H + F202.O)

Después de los engages individuales, correr el cross-cluster analysis:

```python
# scripts/audit_oficial_drift_analysis.py
import json
from pathlib import Path
from kryon.cli.engage import (
    diff_dc_dns_posture,
    diff_proxmox_cluster_posture,
)

# Cargar findings de cada engage
audit_dir = Path("C:/Users/skyva/Documents/Kryon/.kryon/audit-oficial-britimp")
findings_by_host = {}
for engagement_dir in audit_dir.iterdir():
    findings_path = engagement_dir / "findings.json"
    if findings_path.exists():
        with open(findings_path) as f:
            data = json.load(f)
        # Asumir mapping host->findings
        findings_by_host[data["target"]] = data["findings"]

# F202.H — DC drift cross-DCs
dc_drift = diff_dc_dns_posture(findings_by_host)
print(f"DC drift findings: {len(dc_drift)}")
for f in dc_drift:
    print(f"  [{f.severity}] {f.rule_id}: {f.message}")

# F202.O — Proxmox cluster drift
pve_drift = diff_proxmox_cluster_posture(findings_by_host)
print(f"Proxmox cluster drift findings: {len(pve_drift)}")
for f in pve_drift:
    print(f"  [{f.severity}] {f.rule_id}: {f.message}")
```

### 8.3 Reporte ejecutivo consolidado

```bash
# Phase 6 PDF — requiere WeasyPrint operativo (Docker recommended)
docker exec kryon-kryon-1 kryon report \
    --client britimp-internal \
    --engagements britimp-pve-115,britimp-pve-200,britimp-pve-222,britimp-odoo-enterprise,... \
    --out /workspace/.kryon/audit-oficial-britimp/reporte-final.pdf
```

---

## 9. Output esperado del audit oficial

### Findings esperados (baseline POC + amplificación con creds):

| Categoría | POC (sin creds) | Audit oficial (con creds) |
|---|---|---|
| **DB exposure** | 7 hosts (network-level) | Confirmation + DB-specific TLS config |
| **nginx 1.18.0 EOL** | 2 hosts | + apt repo state + auto-update config |
| **DC config drift** | F202.H .205 vs .5 (network) | + AD GPO comparison full |
| **Proxmox cluster drift** | manual via inventory | F202.O automatizado 3 nodos |
| **PermitRootLogin yes** | 5+ hosts (sshd-permit-root flag) | + Ansible playbook root cause |
| **SIEM apagado** | manual via VM inventory | F202.R automatizado todos los hosts |
| **Hikvision NVR aislado** | 1 (.12 en data plane) | + firmware version + CVE matrix |
| **BGP TCP/179** | F202.N manual confirm | + peer auth verification (con creds router) |
| **SMB anonymous shares** | F202.Q (.200.26 rpa-teisa) | + access policy review |
| **CIS Linux gaps** | needs_verification | All CONFIRMED + remediation plan |
| **AD compliance** | 0 (sin WinRM) | 9 AD-checks per DC CONFIRMED |
| **Windows compliance** | 0 (sin WinRM) | 15 WIN-checks per Windows CONFIRMED |

### Estimación cantidades:

| Métrica | POC | Audit oficial estimado |
|---|---|---|
| Hosts auditados | 43 | 50+ (incluyendo .200 segment) |
| Findings CONFIRMED | 133 (7 hosts con creds) | 400-600 (estimado) |
| CRITICAL findings | ~25 (POC) | 50-80 |
| HIGH findings | ~70 | 150-200 |

---

## 10. Plan de remediación priorizado (template)

### 24 horas (CRITICAL inmediato)
1. Encender VM-Ubuntu-Wazuh (VM 101 en cluster Proxmox)
2. Kill `python -m http.server` en .200 Proxmox
3. Patch .117 CentOS 7 OpenSSH 8.0 → 9.x (regreSSHion CVE-2024-6387)
4. Aplicar `PermitRootLogin no` en .115/.18/.121/.200/.222 (root cause: Ansible playbook)

### 7 días
5. Upgrade .150 PostgreSQL 9.6 → 16
6. Move .12 Hikvision NVR de seg. servidores (.201) → seg. CCTV (.203)
7. Habilitar DNSSEC validation en .205 (Set-DnsServerSetting -EnableDnsSec $true)
8. Cerrar DNS recursion abierta en .205/.5 (ACL recursion scope)
9. Upgrade .18 + .121 nginx 1.18.0 → 1.26+ (Odoo Enterprise + Community)

### 30 días
10. Upgrade .200 Proxmox PVE 8.4 → 9.x para unir al cluster
11. Configurar `PVE-1.2` 2FA cluster-wide (3 nodos Proxmox)
12. Configurar `PVE-3.1` backup retention + verification (.10 PBS)
13. Segmentación DB: VLAN dedicada para PostgreSQL/MSSQL (7 hosts actuales)
14. Auditar config Ansible/Salt para uniformar hardening cross-flota

### 90 días
15. Migrar Odoo a stack hardened (template .110/.119 — no root, gzip, etc.)
16. Implementar config management central (uniformar Ansible playbook)
17. Configurar SIEM correlation rules (cuando Wazuh manager esté up)
18. RPKI ROV en BGP router edge BASE
19. Auditoría externa de impresoras Kyocera (firmware version + CVE matrix)
20. Penetration test red-team autorizado (post-fixes 1-19)

---

## 11. Riesgos del audit oficial

| Riesgo | Mitigación |
|---|---|
| Audit dispara alertas en SIEM | Wazuh está apagado, así que NO va a generar alertas. **Pero**: si en el audit oficial ya está prendido, coordinar con SOC pre-audit |
| Probe scan satura red | Banca-safe throttle (T2 + min-rate 50) ya validado en POC |
| Engage SSH agota disk en hosts | Engages individuales, no concurrent. Output dir limpia post-engage |
| BGP probe afecta routing | NO se envía BGP OPEN — solo TCP connect. Banca-safe |
| WinRM session timeout | `--max-turns 15 --nmap-timeout 1800` para tolerar latency |
| python http.server en .200 sigue activo | **MATAR antes del audit** (es CRITICAL data exfil vector) |

---

## 12. Checklist final pre-audit

- [ ] Pre-flight script PASS (`audit_oficial_britimp_preflight.ps1`)
- [ ] NDA firmado con Britimp (scope formal)
- [ ] NDAs firmados con clientes en scope (Itaú, Giva, TEISA si aplica)
- [ ] Creds WinRM cuenta `audit-kryon@britimp.com.py` validadas
- [ ] Creds SSH segmentadas obtenidas (.99, .117, .150, .123)
- [ ] Acceso VPN a VLAN 200 confirmado
- [ ] Ventana horaria coordinada (banca-safe horario laboral)
- [ ] SOC team notificado de la ventana de audit
- [ ] python http.server en .200 KILLED (CRITICAL data exfil)
- [ ] Backup config Proxmox `/etc/pve/` antes del audit
- [ ] Documento SOW firmado con scope explícito

---

## 13. Output del POC consolidado

El POC ya generó:
- **39 commits** en producto Kryon (32 features nuevos)
- **43 hosts auditados** end-to-end (4 segmentos)
- **133 hallazgos CONFIRMED** (7 hosts con creds)
- **Memoria persistida**: `~/.claude/projects/.../memory/poc_britimp_findings.md`
- **0 USD** consumidos (todo `gpt-oss-20b` local)
- **0 FPs introducidos** por los 32 features

El audit oficial debe **amplificar** este resultado con creds + alcanzar el
segmento .200, no recomenzar from scratch.

---

**Última actualización**: 2026-05-19 (sesión POC pre-audit)  
**Autor**: Auditor + Osvaldo (Britimp)  
**Próxima revisión**: Después de obtener creds WinRM + VLAN 200 routing
