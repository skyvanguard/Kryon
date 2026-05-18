---
name: dvr-audit
description: "DVR / NVR / IP camera audit — fingerprinting Dahua/Hikvision/ONVIF + recon read-only (F197 v1 recon-only)"
triggers:
  tech: ["dvr", "nvr", "hikvision", "dahua", "onvif", "ip-camera", "ipc", "cctv"]
  ports: [554, 80, 443, 8000, 8080, 8081, 8443, 3702, 37777]
  keywords:
    - "dvr"
    - "nvr"
    - "hikvision"
    - "dahua"
    - "ipc"
    - "ip camera"
    - "camara"
    - "cámara"
    - "camera"
    - "cctv"
    - "onvif"
    - "rtsp"
    - "video surveillance"
    - "videovigilancia"
priority: 8
required_tools:
  - dvr_fingerprint
  - onvif_discover
  - nmap
  - nuclei_scan
  - run_command
  - search_vulnerabilities
  - recall_similar_experiences
  - request_approval
---

## Status del playbook

**v1 recon-only template (F197).** Cubre fingerprinting (Dahua / Hikvision
/ ONVIF / generic-DVR) + recon read-only + nuclei CVE templates. **NO
incluye 21 checks deterministicos custom todavía** — están planeados
para una v2 post-validación con ground truth (DVR físicos de la
auditoría real).

Lo que SÍ está production-capable hoy:
- `dvr_fingerprint(target)` — HTTP probes read-only, identifica vendor
  + modelo + firmware sin autenticar.
- `onvif_discover()` — WS-Discovery multicast UDP 3702, lista todos los
  ONVIF devices del broadcast domain en ~5 segundos.
- Nuclei CVE templates ya incluyen detección para:
  - CVE-2017-7921 (Hikvision auth bypass)
  - CVE-2021-33044 / CVE-2021-33045 (Dahua auth bypass)
  - CVE-2021-36260 (Hikvision RCE)
  - CVE-2020-25078 (D-Link IP cam)
  - Default-creds tag para muchos vendors.

Lo que NO está cubierto todavía (roadmap v2):
- Checks deterministicos custom (firmware out-of-date check, UPnP
  enabled, Cloud P2P, RTSP sin auth deterministico).
- Auth attempt automático con credenciales default.
- Parse profundo de respuesta ONVIF GetCapabilities (XML).

## Default behavior

Cuando el operador pide auditoría de DVR/cámara:

1. **Pre-engagement check**: confirmá autorización escrita del
   responsable de CCTV, IP/rango del DVR, ventana (read-only puede
   correr en cualquier momento), si hay cámaras grabando evidencia
   judicial (no tocar).
2. **Discovery activo del segmento** (si target es CIDR):
   - Llamá `onvif_discover(timeout_s=10)` para barrer ONVIF multicast.
   - Si no responde nada (multicast bloqueado): `nmap -p 80,443,8000,
     8080,554,37777 -sV CIDR` para identificar candidatos por puerto.
3. **Fingerprinting por host**: por cada host candidato, llamá
   `dvr_fingerprint(target=IP, ports=...)`. Esto identifica vendor +
   modelo + firmware.
4. **Recon de CVEs conocidos**: por cada host con vendor identificado:
   - `nuclei_scan(target=URL, tags="cve")` con templates filtrados al
     vendor (e.g., tags="hikvision,dahua,cve").
   - Si el modelo/firmware son conocidos, cross-ref con
     `search_vulnerabilities(query="<vendor> <model> CVE")`.
5. **Recon HTTP**: `nmap -sV -p 80,443,8000,8080,554 --script
   http-title,rtsp-methods TARGET` para validar servicios.
6. **Reporte LLM-narrated**: agrupá los findings por host, ordená por
   severidad. **NO inventes CVEs** que no aparezcan en nuclei o en la
   búsqueda — F151 + F183 ya filtran inventos.
7. **NUNCA** intentes login con credenciales default sin `request_approval`
   primero. Eso es offensive — requiere `KRYON_RED_TEAM=true` + autorización.

## Pre-requisitos del engagement

- Autorización escrita del responsable de CCTV o IT.
- Acceso de red: VPN del cliente o conectividad directa al segmento de
  cámaras.
- Ventana: read-only puede correr en cualquier momento. Si se va a
  hacer recon agresivo (nmap con muchos ports), preferir fuera de
  horario de respaldo / consolidación de grabaciones.
- **Confidencialidad importante**: muchos DVRs guardan grabaciones con
  privacidad humana (oficinas, residencias). El reporte NO debe
  incluir capturas de las cámaras, solo evidencia técnica de
  configuración insegura.

## Lo que está cableado (production-capable hoy)

### Vendors detectables

| Vendor | Markers HTTP | Endpoints específicos |
|---|---|---|
| **Hikvision** | `Server: App-WebS`, título Hikvision, modelo DS-XXXX | `/doc/page/login.asp`, `/Security/users` |
| **Dahua** | `Server: Webs`, `Server: Boa/0.94.14`, título Dahua, modelos DHI-*/DH-* | `/RPC2_Login`, `/current_config/passwd` |
| **ONVIF (genérico)** | Respuesta SOAP en `/onvif/device_service` | WS-Discovery UDP 3702 |
| **Generic DVR** | Keywords "dvr", "ipc", "camera", "nvr" en banner | Puertos 80/8000/8080 abiertos |

### Vector de ataque #1: default credentials

Sin auth attempt automático todavía. Documentado para reporte:

- Hikvision: `admin:12345` (más común), `admin:admin`, `admin:111111`
- Dahua: `admin:admin`, `888888:888888`, `666666:666666`
- ONVIF genéricos: `admin:admin`, `root:root`, `user:user`
- Marcas chinas (LongSe / IPCC / Topvision): `admin:` (vacío)

### Vector de ataque #2: CVEs conocidos

Nuclei cubre estos automáticamente cuando se le pasa `tags="cve"`:

| CVE | Vendor | Impact | Detectado por |
|---|---|---|---|
| CVE-2017-7921 | Hikvision | Auth bypass | nuclei templates |
| CVE-2021-36260 | Hikvision | RCE (port 80) | nuclei templates |
| CVE-2021-33044 | Dahua | Auth bypass `/RPC2_Login` | nuclei templates |
| CVE-2021-33045 | Dahua | Auth bypass (login_remote) | nuclei templates |
| CVE-2020-25078 | D-Link | Plaintext password disclosure | nuclei templates |
| CVE-2019-9082 | ThinkPHP cámaras | RCE | nuclei templates |

### Vector de ataque #3: configuración insegura visible sin auth

| Item | Detección read-only | Severidad |
|---|---|---|
| HTTP admin sin TLS | `dvr_fingerprint` reporta port 80 abierto | HIGH |
| Telnet abierto | `nmap -p 23` | HIGH |
| RTSP sin auth | `nmap -p 554 --script rtsp-methods` | HIGH |
| ONVIF sin auth | `onvif_discover` lista el device sin credenciales | HIGH |
| UPnP enabled | `nmap -p 5000,1900 --script upnp-info` | MEDIUM |
| Cloud P2P (Hik-Connect / Dahua DDNS) | Tráfico saliente a `*.hik-connect.com` / `*.dahuaddns.com` | MEDIUM |
| Firmware OOD | Banner Server + `search_vulnerabilities` | MEDIUM-HIGH según CVEs |

## Lo que NO está cableado (esperando v2 post-POC)

- Auth attempt con default-creds (requiere offensive gate).
- Checks deterministicos custom (DVR-1.1 a DVR-4.1 del roadmap).
- Parse del response de ONVIF GetCapabilities para extraer:
  - Streaming URLs
  - Discovery mode (DiscoveryMode=Discoverable es default y es leak).
  - PTZ support exposed.
- Cross-ref con base de datos de modelos EOL.
- Detección de tampering físico via API (algunos DVRs lo exponen).

## Limitaciones conocidas

1. **Multicast WS-Discovery puede fallar** si el operador está en VLAN
   distinta a las cámaras o si switches L3 no propagan 239.255.255.250.
   Fallback: fingerprinting host-by-host con `dvr_fingerprint`.

2. **Algunos DVRs chinos genéricos** (sin marca conocida) no van a ser
   detectados como tales — caerán en "unknown" o "generic-dvr".

3. **CVE freshness**: las templates de nuclei se actualizan vía
   `nuclei -ut`. Si el cache del pod está viejo, podemos perder CVEs
   recientes. F164 ya pinea nuclei v3.8.0 con descarga de templates en
   build, así que esto está mitigado.

4. **Sin ground truth todavía**: F197 v1 sale para el POC Britimp.
   Después de ese POC tendremos data real de los 3 segmentos DVR de
   Britimp para validar y promover esto a "production-capable con
   checks deterministicos custom".

## Reporting

Para el reporte LLM-narrated, agrupar por host y emitir:

```
Host: 192.168.1.50:80
Vendor: Hikvision, modelo DS-7608NI-K2/8P, firmware 4.30.x
Findings:
  [HIGH] CVE-2021-36260 confirmed via nuclei → RCE port 80
  [HIGH] HTTP admin sin TLS
  [HIGH] ONVIF sin auth (xaddr http://192.168.1.50/onvif/device_service)
  [MEDIUM] Firmware 4.30.x (CVE list applicable: ...)
Remediations:
  1. Aplicar firmware 4.62.x o superior (Hikvision security advisory HSRC-202109-08).
  2. Habilitar HTTPS + redirigir HTTP→HTTPS.
  3. Cambiar password default a 14+ caracteres con complejidad.
  4. Aislar VLAN cámaras del segmento de oficinas + bloquear saliente a Hik-Connect.
```
