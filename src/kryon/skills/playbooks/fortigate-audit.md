---
name: fortigate-audit
description: "Auditoría de configuración FortiGate (FortiOS) — CIS Fortinet Benchmark + hardening read-only via SSH/API"
triggers:
  tech: ["fortigate", "fortios", "fortinet", "fortimanager", "fortianalyzer"]
  ports: [443, 8443, 10443, 4433, 22, 541, 542]
  keywords:
    - "fortigate"
    - "fortinet"
    - "fortios"
    - "forti"
    - "ssl vpn"
    - "sslvpn"
    - "firewall fortinet"
    - "audit fortigate"
    - "auditoría fortigate"
    - "auditoria fortigate"
    - "hardening fortigate"
    - "fortimanager"
    - "fortianalyzer"
priority: 10
required_tools:
  - run_compliance_audit
  - generate_compliance_pdf
  - run_command
  - nmap
  - nuclei_scan
  - request_approval
pre_hooks:
  - tool: run_compliance_audit
    args:
      framework: fortigate
      host: "{ctx.host}"
      ssh_user: "{ctx.ssh_user}"
      ssh_key_path: "{ctx.ssh_key_path}"
    inject_as: deterministic_compliance_findings
    required: true
    timeout_s: 120
---

## Status del playbook

**Production-capable (F78).** 21 checks deterministicos (FGT-1.1..FGT-5.3)
cableados a `run_compliance_audit(framework="fortigate")` con hash de
reproducibilidad estable. Los verdicts los produce el detector estático,
NO el LLM — el LLM solamente narra los findings al operador.

## Default behavior — F78 deterministic auditor first

Cuando el operador pide auditoría de FortiGate:

1. **Pre-engagement check**: confirmá autorización escrita, IP del FortiGate,
   credencial (admin con accprofile read-only o API token), ventana.
   SI FALTA AUTORIZACIÓN, parar acá.
2. **Llamá `run_compliance_audit(host=..., framework="fortigate")` PRIMERO**.
   Corre los 21 checks F78 sin LLM en el detection path. Aliases válidos:
   `fortigate`, `fgt`, `fortinet`, `fortios`.
3. **Narrá los hallazgos ordenados por severidad** (CRITICAL → HIGH →
   MEDIUM → LOW). Para cada FAIL cita el `evidence_command` exacto y el
   `remediation_static` tal cual.
4. Si el usuario pide reporte ejecutivo, llamá
   `generate_compliance_pdf(host=..., framework="fortigate")`.
5. **Fase opcional — Recon externo complementario** (sin auth): si el
   operador autoriza, sumá `nmap` + `nuclei_scan` al portal admin/SSL VPN
   para validar exposición desde Internet.
6. **NUNCA** modificar config sin OK explícito vía `request_approval`.
   **NUNCA** correr exploits contra CVEs descubiertos — el rol del skill
   es defensivo/auditor.

**Regulatorio no-negociable**: el verdict de `run_compliance_audit` es la
verdad auditable. No suavices ni cambies un FAIL a "parcial".

## Pre-requisitos del engagement

- Autorización escrita del responsable de red (CISO / IT Manager).
- IP/hostname del FortiGate (typically `firewall.empresa.local` o `10.x.x.1`).
- Credencial: preferible `auditor` profile con permisos `super_admin_readonly`,
  o API token (`config system api-user`) con scope read.
- Acceso de red: VPN del cliente o jump-host autorizado.
- Ventana NO requerida — todos los checks son read-only.
- Confirmar si hay HA cluster (primario + secundario) — auditar ambos.

### Conexión

```bash
# Vía SSH (interfaz CLI nativa)
ssh auditor@FGT-IP                                  # password o key
# Una vez dentro:
get system status
get system performance status
config global / config vdom (si VDOMs habilitados)

# Vía REST API (preferido para automatización)
curl -sk -H "Authorization: Bearer $FGT_API_TOKEN" \
     https://FGT-IP/api/v2/cmdb/system/global

# SSH no-interactivo con session token
sshpass -p "$FGT_PASS" ssh -o StrictHostKeyChecking=no \
     -o KexAlgorithms=+diffie-hellman-group14-sha1 \
     -o HostKeyAlgorithms=+ssh-rsa admin@FGT-IP "get system status"
```

**Nota**: FortiOS antiguos (≤ 6.4) requieren KEX/HostKey legacy explícitos
en SSH client moderno. Si conexión falla, agregá las flags arriba.

## 21 Checks (CIS Fortinet Benchmark v1.x mapped)

Los IDs `FGT-X.Y` corresponden 1:1 con módulos en
`src/kryon/compliance/checks/fortigate/`. Cada uno emite un verdict
PASS / FAIL / N/A / ERROR + evidencia parsed + remediation.

### Acceso administrativo
| ID | Sev | Detección | Mapping |
|---|:---:|---|---|
| FGT-1.1 | CRITICAL | Default password admin (`""`, `admin`, `fortinet`) | CIS 1.2.1 / PCI-DSS 2.2.2 |
| FGT-1.2 | HIGH | `set admin-https-redirect enable` ausente, HTTP admin (port 80) abierto | CIS 1.3.1 |
| FGT-1.3 | HIGH | `trusthost` ausente o `0.0.0.0/0` en cuenta admin | CIS 1.2.4 / Zero Trust |
| FGT-1.4 | CRITICAL | 2FA (FortiToken/email/SMS) NO enforced en admin-profile super_admin | CIS 1.2.6 / PCI-DSS 8.4 |
| FGT-1.5 | MEDIUM | `set admintimeout` > 5 (minutos idle) | CIS 1.2.5 / PCI-DSS 8.1.8 |
| FGT-1.6 | MEDIUM | Multiple cuentas con role `super_admin` (debería ser ≤ 2) | CIS 1.2.2 |

### Servicios management
| ID | Sev | Detección | Mapping |
|---|:---:|---|---|
| FGT-2.1 | HIGH | `config system interface` muestra `allowaccess` con `http telnet` (no-secure) | CIS 1.4.1 |
| FGT-2.2 | HIGH | SNMP v1/v2c habilitado con community `public`/`private`/empty | CIS 1.5.1 / CRITICAL si community trivial |
| FGT-2.3 | MEDIUM | NTP sin authentication (`config system ntp` → `authentication disable`) | CIS 1.6.1 |
| FGT-2.4 | LOW | DNS forwarders apuntan a 8.8.8.8/1.1.1.1 (data exfil concern interno) | Best practice |

### SSL VPN (vector de ataque #1 en FortiGate)
| ID | Sev | Detección | Mapping |
|---|:---:|---|---|
| FGT-3.1 | CRITICAL | SSL VPN con `tlsv1-0` o `tlsv1-1` enable | PCI-DSS 4.2.1 |
| FGT-3.2 | CRITICAL | SSL VPN sin MFA (auth-method local sin 2FA) | PCI-DSS 8.4 / NIST AC-2 |
| FGT-3.3 | HIGH | Portal SSL VPN default expuesto en `/remote/login` sin geo-filter | CVE-2018-13379, CVE-2022-42475, CVE-2023-27997 contexto |
| FGT-3.4 | HIGH | `set source-address` ausente en SSL VPN policy (any source) | Zero Trust |
| FGT-3.5 | MEDIUM | Idle-timeout SSL VPN > 30 min, auth-timeout > 8h | PCI-DSS 8.1.8 |

### Logging y monitoreo
| ID | Sev | Detección | Mapping |
|---|:---:|---|---|
| FGT-4.1 | HIGH | `config log syslogd setting` → status disable (no syslog upstream) | PCI-DSS 10.5.3 / SIB Res. 06/2020 |
| FGT-4.2 | MEDIUM | `set memory-disk-quota` < 5% disco, log-disk overflow likely | PCI-DSS 10.5.4 |
| FGT-4.3 | MEDIUM | Audit log retention configurada < 90 días | PCI-DSS 10.5.1 |

### Software lifecycle
| ID | Sev | Detección | Mapping |
|---|:---:|---|---|
| FGT-5.1 | HIGH | FortiOS minor < N-2 release (e.g. 7.0.x cuando 7.4.x es current) | CIS 1.1.1 / PCI-DSS 6.3.3 |
| FGT-5.2 | HIGH | Licencias FortiGuard (AV/IPS/AppCtrl/WebFilter) expiradas | Defensa en profundidad |
| FGT-5.3 | CRITICAL | Versión vulnerable a CVE crítico no parchado (CVE-2022-42475, CVE-2024-21762, etc.) | Cross-ref con `search_vulnerabilities` |

## Comandos de auditoría (Fase 2)

Pegá esto vía SSH al FortiGate y guardá output. Cada bloque genera evidencia
para uno o más checks. Si hay VDOMs, repetir por VDOM.

```fortios
# === Acceso admin ===
get system admin
config system admin
   show full-configuration | grep -E "trusthost|two-factor|password"
end
get system global | grep -E "admin-https-redirect|admintimeout|admin-port"

# === Servicios management ===
config system interface
   show full-configuration | grep -E "name|allowaccess|status"
end
config system snmp community
   show
end
config system ntp
   show
end

# === SSL VPN ===
config vpn ssl settings
   show full-configuration
end
config vpn ssl web portal
   show
end
config firewall policy
   show full-configuration | grep -B2 -A10 "ssl-vpn"
end

# === Logging ===
config log syslogd setting
   show
end
config log fortianalyzer setting
   show
end
get log eventfilter

# === Software ===
get system status                                  # versión exacta
diagnose autoupdate versions | head -50            # licencias FortiGuard
diagnose hardware sysinfo conserve                 # memoria/CPU pressure

# === Policies (sanity check) ===
config firewall policy
   show full-configuration | grep -E "edit |srcaddr|dstaddr|service|action"
end | grep -B1 -A3 "all"                          # buscar "any-any-any"
```

## Hallazgos típicos en redes corporativas LATAM

- **Default `admin` con password vacío** o `fortinet` — 3 de 10 redes nuevas. CRITICAL.
- **SSL VPN sin MFA** — 7 de 10. CRITICAL en banca.
- **TLS 1.0/1.1 habilitado en SSL VPN** — 6 de 10 (legacy clients). CRITICAL.
- **`trusthost` no configurado en admin** — 9 de 10. HIGH.
- **SNMP `public` v2c** — 5 de 10. CRITICAL.
- **FortiOS 6.x (EOL)** — 2 de 10. HIGH + CVE chain.
- **CVE-2022-42475 / CVE-2023-27997 sin parchar** — 1-2 de 10. CRITICAL,
  exploit público disponible. Cruzar con `search_vulnerabilities`.
- **Logging local-only (sin syslog/FAZ upstream)** — 8 de 10. HIGH para PCI-DSS.

## Remediation narrativa (informe ejecutivo)

Para gerencia, NO usar jerga FortiOS. Traducir:

- "Acceso administrativo sin segundo factor" (FGT-1.4) — NO "admin without 2FA"
- "Acceso remoto VPN sin verificación adicional" (FGT-3.2)
- "Servicios de gestión expuestos sin restricción de origen" (FGT-1.3)
- "Versión del sistema con vulnerabilidades públicas conocidas" (FGT-5.3)
- "Comunicaciones de monitoreo sin protección" (FGT-2.2)

## Lo que NO hace este skill

- **No explota CVEs.** Detecta versión vulnerable, no lanza el exploit.
- **No modifica policies.** Read-only por default. Modificación solo con
  `request_approval` + ventana de mantenimiento confirmada.
- **No cracking de passwords admin.** Brute-force contra portal admin =
  bloqueo automático del FortiGate y ruido al SOC del cliente.
- **No bypass de SSL inspection.** El skill respeta la cadena CA del cliente.
- **No toca FortiAnalyzer/FortiManager profundamente** — eso es otro skill
  futuro (`fortianalyzer-audit`, no creado todavía).

## Integración con otros skills

- **Antes**: `recon-scout` para fingerprint inicial del rango (puerto 10443
  típicamente delata FortiGate SSL VPN).
- **Durante FGT-5.3**: `search_vulnerabilities("FortiOS", version=X.Y.Z)`
  para cruzar versión exacta vs CVE database.
- **Después**: `ssl-audit` contra el portal SSL VPN (puerto 10443/443) para
  análisis profundo de cipher suites + Heartbleed/POODLE residuales.
- **Si encuentra default creds (FGT-1.1)**: NO escalar. Reportar y parar.
  El operador decide si rotar in-situ o documentar para CISO.

## Reglas críticas

- **Brute-force admin** = trigger lockout. No hacer NUNCA, ni en lab.
- **Cambios en SSL VPN settings** = potencial corte para tele-trabajadores.
  Solo con ventana de mantenimiento confirmada.
- **`execute reboot`** o `execute shutdown` = NUNCA. Ni con approval. Ese
  comando va por consola del cliente, no por el auditor.
- **HA cluster**: si auditás el primario y aplicás cambios, el secundario
  sincroniza. Si rompés algo, rompés ambos. Confirmar HA antes de tocar.
- **VDOMs**: cada VDOM puede tener config independiente. Auditar el
  `root` VDOM Y todos los custom VDOMs por separado.
