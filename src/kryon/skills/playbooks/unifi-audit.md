---
name: unifi-audit
description: "Auditoría Unifi (Ubiquiti) Network Controller + WiFi WPA/WPA2/WPA3 — config audit + pentest WiFi asistido"
triggers:
  tech: ["unifi", "ubiquiti", "ubnt", "unifi-controller", "udm", "udm-pro", "uap", "uxg"]
  ports: [8443, 8080, 8843, 8880, 6789, 5514, 27117, 22]
  keywords:
    - "unifi"
    - "ubiquiti"
    - "ubnt"
    - "wifi"
    - "wireless"
    - "wpa"
    - "wpa2"
    - "wpa3"
    - "wps"
    - "ssid"
    - "audit wifi"
    - "auditoría wifi"
    - "auditoria wifi"
    - "pentest wifi"
    - "udm"
    - "unifi audit"
    - "controller unifi"
priority: 10
required_tools:
  - run_compliance_audit
  - generate_compliance_pdf
  - run_command
  - nmap
  - nuclei_scan
  - search_vulnerabilities
  - query_knowledge_base
  - recall_similar_experiences
  - request_approval
pre_hooks:
  - tool: run_compliance_audit
    args:
      framework: unifi
      host: "{ctx.host}"
      ssh_user: "{ctx.ssh_user}"
      ssh_key_path: "{ctx.ssh_key_path}"
    inject_as: deterministic_compliance_findings
    required: true
    timeout_s: 120
---

## Status del playbook

Cubre dos planos con madurez distinta:

1. **Controller audit (production-capable, F79).** 18 checks deterministicos
   (UNF-1.1..UNF-4.2) cableados a `run_compliance_audit(framework="unifi")`.
   Verdicts producidos por detector estático sobre dump de mongo
   (`mongo --port 27117 ace`). Hash de reproducibilidad estable.
2. **WiFi pentest asistido (template guiada).** Flujo airodump-ng /
   hcxdumptool → handshake o PMKID → hashcat offline. El skill guía;
   el operador ejecuta en su host (Kryon NO controla raw 802.11 desde
   el container Docker).

## Default behavior — F79 deterministic controller audit first

1. **Pre-engagement check**: autorización escrita (incluyendo permiso
   explícito para deauth si se va a hacer captura activa), inventario de
   APs/SSIDs, IP del controller, credencial SSH al UDM/Cloud Key (root).
2. **Llamá `run_compliance_audit(host=..., framework="unifi")` PRIMERO**.
   Corre los 18 checks F79 sin LLM en el detection path. Aliases válidos:
   `unifi`, `ubnt`, `ubiquiti`.
3. **Narrá hallazgos ordenados por severidad** (CRITICAL → HIGH → MEDIUM
   → LOW). Para cada FAIL cita `evidence_command` y `remediation_static`.
4. Si el usuario pide reporte ejecutivo, `generate_compliance_pdf(...,
   framework="unifi")`.
5. **Fase opcional — WiFi capture asistido** (SI el operador lo pide y
   tiene autorización para deauth): handshake o PMKID, crack offline.
   Esta fase NO es deterministica — el playbook guía y el operador ejecuta
   comandos en su host con adaptador en monitor mode.

**Default = read-only.** Cambios al controller solo con `request_approval`.
Deauth attacks (active jamming) **prohibidos sin autorización explícita
firmada** — son disruptivos y en muchas jurisdicciones LATAM ilegales contra
redes de terceros.

**Regulatorio no-negociable**: el verdict de `run_compliance_audit` es la
verdad auditable. No suavices ni cambies un FAIL.

## Pre-requisitos del engagement

- **Autorización escrita** firmada por dueño de la red (gerencia / IT lead).
- **IP del Unifi Controller** o UDM (ej. `192.168.1.1` para UDM, custom para
  Cloud Key / self-hosted).
- **Credencial read-only**: super-admin con MFA preferido, o local admin
  creado en `Settings → Admins → Add Admin → Limited Admin (Read Only)`.
- **SSH al UDM/Cloud Key** (opcional, da acceso a archivos config raw):
  user `root` con password de la UI.
- **Para WiFi capture activo**:
  - Adaptador WiFi externo con chipset Atheros/Realtek (Alfa AWUS036ACS,
    Panda PAU09) en monitor mode en el host del operador.
  - Antena con visibilidad al AP target.
  - Permiso explícito para deauth (forzar reconexión = capturar handshake).
- **Modo de auditoría**: confirmar si es read-only (solo controller config)
  o full pentest (incluye captura WPA + crack).

## Conexión al controller

```bash
# UDM/UDM-Pro (default IP 192.168.1.1)
ssh root@192.168.1.1                              # password de la UI
# Una vez dentro (UniFi OS shell):
unifi-os shell                                    # entra al container Unifi
mongo --port 27117 ace --eval "db.setting.find()"  # config dump

# Cloud Key Gen2+ (default 192.168.1.30)
ssh root@CK-IP

# Self-hosted (Linux con paquete unifi)
ssh user@CONTROLLER-IP
sudo cat /usr/lib/unifi/data/system.properties

# REST API (recomendado para automatización)
curl -sk -c cookies.txt -d '{"username":"USER","password":"PASS"}' \
     -H "Content-Type: application/json" \
     https://CTRL-IP:8443/api/login

curl -sk -b cookies.txt \
     https://CTRL-IP:8443/api/s/default/stat/sites
```

## 18 Checks (Unifi + WiFi Best Practice)

Los IDs `UNF-X.Y` corresponden 1:1 con módulos en
`src/kryon/compliance/checks/unifi/`. Cada uno emite un verdict
PASS / FAIL / N/A / ERROR + evidencia parsed + remediation.

### Controller / management
| ID | Sev | Detección | Mapping |
|---|:---:|---|---|
| UNF-1.1 | CRITICAL | Default creds (`ubnt/ubnt`, `admin/admin`) en controller o APs adoptados | CIS Wireless 6.1.1 |
| UNF-1.2 | CRITICAL | Controller expuesto a Internet (puertos 8443, 8080 alcanzables desde WAN) | CIS Wireless 1.1 |
| UNF-1.3 | HIGH | Admin sin 2FA habilitado (`Settings → Admins → 2FA`) | NIST AC-2 |
| UNF-1.4 | HIGH | Controller firmware EOL o vulnerable (CVE-2024-42026, etc.) | PCI-DSS 6.3.3 |
| UNF-1.5 | MEDIUM | Auto-backup deshabilitado o backups en mismo controller (no offsite) | BC/DR |

### SSIDs / WiFi
| ID | Sev | Detección | Mapping |
|---|:---:|---|---|
| UNF-2.1 | CRITICAL | SSID con WEP o WPA1-TKIP (legacy AES-CCMP no enforced) | PCI-DSS 4.2.1 |
| UNF-2.2 | HIGH | WPA2-PSK con passphrase débil (< 12 chars, palabra de diccionario, leaked en HIBP) | NIST 800-63B |
| UNF-2.3 | HIGH | WPS habilitado en cualquier SSID (PIN attack) | CIS Wireless 4.1 |
| UNF-2.4 | MEDIUM | WPA3 disponible en hardware pero solo WPA2 enforced (no transition mode aceptable) | NIST SP 800-97 |
| UNF-2.5 | HIGH | Open SSID broadcasting sin captive portal o sin justificación de negocio | CIS Wireless 4.4 |
| UNF-2.6 | HIGH | Guest SSID sin "Guest Control" / client isolation habilitada | Zero Trust segmentation |
| UNF-2.7 | MEDIUM | "Hide SSID" usado como única medida de seguridad (security by obscurity) | Best practice |

### Segmentación / VLANs
| ID | Sev | Detección | Mapping |
|---|:---:|---|---|
| UNF-3.1 | CRITICAL | Management VLAN compartida con guest VLAN o IoT VLAN | Zero Trust / PCI-DSS 1.2 |
| UNF-3.2 | HIGH | Corp SSID y Guest SSID sin VLAN tag separado | Zero Trust |
| UNF-3.3 | MEDIUM | RADIUS server (si WPA-Enterprise) sin shared secret rotación documentada | NIST AC-2 |
| UNF-3.4 | MEDIUM | AP-controller comm encryption (`set inform encrypt`) deshabilitada | Defense in depth |

### Logging / firmware
| ID | Sev | Detección | Mapping |
|---|:---:|---|---|
| UNF-4.1 | HIGH | Logging a syslog externo deshabilitado (logs solo en controller) | PCI-DSS 10.5.3 |
| UNF-4.2 | MEDIUM | Auto-update firmware AP deshabilitado, APs en versiones < N-2 | PCI-DSS 6.3.3 |

## Comandos de auditoría (Fase 2)

### Vía SSH al UDM/Cloud Key

```bash
# Versión exacta
cat /etc/version 2>/dev/null
unifi-os version 2>/dev/null

# Config dump del controller (MongoDB interno)
mongo --port 27117 ace --quiet --eval '
  db.wlanconf.find({}, {name:1, security:1, wpa_mode:1, wpa_enc:1, x_passphrase:1,
                       wps:1, hide_ssid:1, networkconf_id:1, vlan:1, vlan_enabled:1,
                       is_guest:1, schedule_enabled:1}).pretty()'

mongo --port 27117 ace --quiet --eval '
  db.networkconf.find({}, {name:1, purpose:1, vlan:1, vlan_enabled:1, networkgroup:1}).pretty()'

mongo --port 27117 ace --quiet --eval '
  db.admin.find({}, {name:1, role:1, last_site_name:1, ui_settings:1}).pretty()'

mongo --port 27117 ace --quiet --eval '
  db.setting.find({key:"super_identity"}).pretty()'

mongo --port 27117 ace --quiet --eval '
  db.setting.find({key:"super_mfa"}).pretty()'

# Firmware APs adoptados
mongo --port 27117 ace --quiet --eval '
  db.device.find({}, {name:1, model:1, version:1, adopted:1, state:1, ip:1}).pretty()'

# Logs y syslog
mongo --port 27117 ace --quiet --eval '
  db.setting.find({key:"super_smtp"}).pretty()'
mongo --port 27117 ace --quiet --eval '
  db.setting.find({key:"super_remote_syslog"}).pretty()'
```

### Vía REST API (sin SSH)

```bash
# Login
curl -sk -c /tmp/cookies.txt -X POST \
     -H "Content-Type: application/json" \
     -d '{"username":"USER","password":"PASS","strict":true}' \
     https://CTRL:8443/api/login

# Sites + WLANs
curl -sk -b /tmp/cookies.txt https://CTRL:8443/api/s/default/rest/wlanconf | jq '.data[]
  | {name, security, wpa_mode, wpa_enc, hide_ssid, wps, is_guest, vlan_enabled, vlan}'

# Networks (VLANs)
curl -sk -b /tmp/cookies.txt https://CTRL:8443/api/s/default/rest/networkconf | jq

# Devices (firmware APs)
curl -sk -b /tmp/cookies.txt https://CTRL:8443/api/s/default/stat/device | jq '.data[]
  | {name, model, version, ip, state}'

# Admins
curl -sk -b /tmp/cookies.txt https://CTRL:8443/api/stat/admin | jq

# Logout
curl -sk -b /tmp/cookies.txt https://CTRL:8443/api/logout
```

## WiFi capture asistido (Fase 3 — solo con autorización activa)

**SOLO si el operador tiene firmado el permiso para deauth/capture y un
adaptador WiFi en monitor mode.** Kryon guía, el operador ejecuta en su host.

### 3a. Setup adaptador

```bash
# Identificar interfaz WiFi externa
iwconfig 2>/dev/null | grep -i mode
airmon-ng                                          # listar adaptadores

# Killear procesos que usan WiFi
sudo airmon-ng check kill

# Activar monitor mode
sudo airmon-ng start wlan0                         # → wlan0mon
iwconfig wlan0mon                                  # confirmar Mode:Monitor
```

### 3b. Discovery de SSIDs target

```bash
# Listar todas las redes + clientes asociados
sudo airodump-ng wlan0mon
# Anotar BSSID + canal del SSID target. Ctrl+C cuando lo veas.

# Lock al canal/BSSID + dump captura
sudo airodump-ng -c CHAN --bssid BSSID -w /tmp/cap wlan0mon
```

### 3c. Captura de handshake (WPA/WPA2)

**Opción 1 — pasiva (esperar conexión legítima):**
Mantener airodump corriendo. Cuando un cliente nuevo se conecte, capturás
el 4-way handshake. Indicador: arriba a la derecha aparece `WPA handshake: BSSID`.

**Opción 2 — activa (deauth, requiere autorización):**
```bash
# En otra terminal, deauth a un cliente para forzar reconexión
sudo aireplay-ng --deauth 5 -a BSSID -c CLIENT-MAC wlan0mon
# 5 paquetes es suficiente. NO hacer flood (--deauth 0 = continuo = ilegal en
# muchas jurisdicciones, y rompe la red para usuarios legítimos).
```

### 3d. PMKID attack (NO requiere cliente — preferido para WPA2 moderno)

```bash
# hcxdumptool sniffea PMKID directo del beacon/auth response del AP
sudo hcxdumptool -i wlan0mon -o /tmp/pmkid.pcapng \
     --enable_status=1

# Convertir captura a formato hashcat
hcxpcapngtool -o /tmp/hash.hc22000 /tmp/pmkid.pcapng

# Crack offline con hashcat
hashcat -m 22000 /tmp/hash.hc22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 /tmp/hash.hc22000 /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

**PMKID-only no funciona contra WPA3 ni contra todos los APs WPA2** (el AP
debe enviar el PMKID en el primer mensaje EAPOL). Si falla, fallback a
4-way handshake captura.

### 3e. Crack handshake

```bash
# aircrack (rápido para wordlists chicas)
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b BSSID /tmp/cap-01.cap

# hashcat (preferido para wordlists grandes + GPU)
hcxpcapngtool -o /tmp/hs.hc22000 /tmp/cap-01.cap
hashcat -m 22000 /tmp/hs.hc22000 wordlist.txt

# Si crack > 30 min sin hit con rockyou: parar y reportar como
# "passphrase resistente a wordlist común" — es un FINDING POSITIVO
# (passphrase fuerte). NO es un fail del audit.
```

### Cleanup

```bash
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager              # restaurar conexión normal
```

## Hallazgos típicos LATAM (oficinas medianas/grandes)

- **Default `ubnt/ubnt`** en APs adoptados manualmente — 4 de 10. CRITICAL.
- **WPS habilitado** porque "facilita conectar invitados" — 6 de 10. HIGH.
- **Guest SSID y Corp SSID en mismo VLAN** — 5 de 10. CRITICAL.
- **WPA2 PSK passphrase = "EmpresaNombre2024"** o similar — 4 de 10. HIGH (cracks
  en < 5 min con rockyou + reglas).
- **Controller expuesto a Internet** (admin remoto cómodo) — 2 de 10. CRITICAL.
- **Firmware AP > 18 meses sin update** — 7 de 10. MEDIUM/HIGH según CVE.
- **2FA en admin no habilitada** — 9 de 10. HIGH.
- **Logs solo en controller (sin syslog upstream)** — 9 de 10. HIGH para PCI.

## Remediation narrativa

Para gerencia, traducir:

- "Contraseña WiFi vulnerable a ataques de diccionario" (UNF-2.2)
- "Red de invitados sin separación lógica de la red corporativa" (UNF-3.2)
- "Acceso administrativo del sistema WiFi sin verificación adicional" (UNF-1.3)
- "Equipos WiFi sin actualizaciones de seguridad por más de un año" (UNF-4.2)
- "Configuración legacy WPS que permite saltarse la contraseña" (UNF-2.3)

## Lo que NO hace este skill

- **No deauth sin autorización escrita.** Nunca. Ni en lab si no es propio.
- **No crack online** contra el AP (PIN-WPS bruteforce live = trigger de
  bloqueo automático en Unifi y log al SOC). Solo offline contra captura.
- **No suplanta el AP (evil twin)** salvo que esté en scope explícito firmado.
  Esa fase requiere otro skill futuro (`wifi-redteam`, no creado).
- **No ataca clientes WiFi (KARMA, MITM via fake AP).** Fuera de scope default.
- **No modifica config Unifi** sin `request_approval` + ventana confirmada.
- **No corre desde el contenedor Docker de Kryon** la fase 3 (capture activo
  necesita raw 802.11 → host del operador).

## Integración con otros skills

- **Antes**: `recon-scout` para discovery de IP del controller (8443 + cert
  con CN `UniFi` lo delata).
- **Para UNF-1.4**: `search_vulnerabilities("unifi network", version=X.Y.Z)`.
- **Si encuentra controller expuesto a Internet (UNF-1.2)**: invocar
  `ssl-audit` contra el portal admin.
- **Después de crack exitoso del PSK**: documentar y RECOMENDAR rotación,
  NO usar el PSK para penetrar la red sin autorización adicional firmada
  (el permiso de auditar WiFi ≠ permiso de pivotar a la red interna).
- **Para hardening del controller post-audit**: `server-hardening` si el
  controller corre en Linux self-hosted.

## Reglas críticas

- **Deauth contra red de tercero = delito** (Paraguay: Ley 4439/2011 art. 174
  bis modificado, "acceso indebido a sistemas informáticos"). Nunca asumir
  permiso. El permiso debe estar firmado por escrito antes de tocar
  `aireplay-ng`.
- **Si el cliente reporta degradación de servicio durante el engagement**:
  parar TODA fase activa inmediatamente, restaurar adaptador a managed mode,
  notificar al cliente. Documentar como incidente.
- **PSK crackeado**: no es trofeo. Reportar redactado (`passphrase recovered:
  ✓ — value redacted, see annex A`). El valor real va a un anexo que se
  entrega solo en mano al CISO.
- **Captura WPA = datos de empleados conectándose**. Borrar `.cap` después
  del engagement (NDA + GDPR/Ley 6534/2020 PY).
- **Si encuentra red oculta no-declarada en scope**: STOP. Reportar al
  contacto. Puede ser red de tercero / vecino / IoT olvidado, no tuyo
  para auditar.
