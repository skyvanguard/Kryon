---
name: voip-asterisk-audit
description: "Asterisk / FreePBX VoIP audit — 8 checks deterministicos (sip.conf + manager.conf + version + SRTP/TLS) + recon SIP/AMI"
triggers:
  tech: ["asterisk", "freepbx", "fpbx", "sip", "voip", "pbx"]
  ports: [5060, 5061, 5038, 8088, 8089]
  keywords:
    - "asterisk"
    - "freepbx"
    - "voip"
    - "sip"
    - "pbx"
    - "central telefonica"
    - "central telefónica"
    - "telefonia"
    - "telefonía"
    - "audit voip"
    - "auditoria voip"
    - "auditoría voip"
    - "telefonia ip"
    - "telefonía ip"
priority: 9
required_tools:
  - run_compliance_audit
  - generate_compliance_pdf
  - asterisk_discover
  - run_command
  - nmap
  - nuclei_scan
  - request_approval
pre_hooks:
  - tool: run_compliance_audit
    args:
      framework: asterisk
      host: "{ctx.host}"
      ssh_user: "{ctx.ssh_user}"
      ssh_key_path: "{ctx.ssh_key_path}"
    inject_as: deterministic_compliance_findings
    required: true
    timeout_s: 120
---

## Status del playbook

**Production-capable (F198).** 8 checks deterministicos
(VOIP-1.1..VOIP-3.3) cableados a `run_compliance_audit(framework="asterisk")`.
Los verdicts los produce el detector estático leyendo `sip.conf` /
`manager.conf` / `pjsip.conf` / `rtp.conf` via SSH al host Asterisk.
Hash de reproducibilidad estable.

Recon liviano (SIP OPTIONS + AMI banner) disponible via `asterisk_discover`
para fingerprinting cuando no hay SSH todavía.

## Default behavior

Cuando el operador pide auditoría de Asterisk / VoIP:

1. **Pre-engagement check**: confirmá autorización del responsable de
   comunicaciones, IP del PBX, credencial SSH al server, ventana
   (read-only puede correr en horario laboral — los archivos de config
   no se tocan). Aclarar que NO se hacen llamadas, NO se prueba auth,
   NO se monitorea tráfico de voz real.
2. **Llamá `run_compliance_audit(host=..., framework="asterisk")` PRIMERO**.
   Corre los 8 checks F198 sin LLM en el detection path. Alias válido:
   `asterisk`, `voip`.
3. **Narrá los hallazgos** ordenados por severidad (CRITICAL → HIGH →
   MEDIUM). Para cada FAIL cita el `evidence_command` exacto y la
   `remediation_static`.
4. **Fase opcional — Recon externo** (sin SSH): si solo tenés IP y
   puerto, llamá `asterisk_discover(target=...)` para confirmar que
   es Asterisk y obtener la versión via AMI banner.
5. Si el operador pide PDF, llamá
   `generate_compliance_pdf(host=..., framework="asterisk")`.
6. **NUNCA** intentes login con credenciales default. **NUNCA** inicies
   llamadas reales. **NUNCA** modifiques config — el playbook es
   defensivo/auditor.

**Regulatorio**: el verdict de `run_compliance_audit` es la verdad
auditable. No suavices ni cambies un FAIL a "parcial".

## Pre-requisitos del engagement

- Autorización escrita del responsable de comunicaciones / IT.
- IP/hostname del Asterisk + credencial SSH (usuario con permisos de
  lectura sobre `/etc/asterisk/`).
- Ventana NO requerida — todos los checks son read-only.
- Confirmar si es Asterisk standalone, FreePBX, o cluster (chan_sip
  vs PJSIP cambia algunos checks).
- Si el PBX está detrás de un SBC (Session Border Controller),
  documentar la topología — los chequeos de exposure (VOIP-2.3) aplican
  al SBC, no al Asterisk interno.

## 8 Checks deterministicos

Los IDs `VOIP-X.Y` corresponden 1:1 con módulos en
`src/kryon/compliance/checks/asterisk/`. Cada uno emite verdict
PASS / FAIL / N/A / ERROR + evidencia parsed + remediation.

### Anonymous / unauthenticated access
| ID | Sev | Detección |
|---|:---:|---|
| VOIP-1.1 | CRITICAL | `[default]` context en `extensions.conf` con Dial/Goto/Exec — toll fraud vector si VOIP-2.1 está mal |
| VOIP-1.2 | CRITICAL | AMI user con secret default (`mysecret`, `amp111`, `manager`, ...) o < 8 chars |

### SIP / AMI hardening
| ID | Sev | Detección |
|---|:---:|---|
| VOIP-2.1 | HIGH | `allowguest=yes` en `[general]` de sip.conf — guest calls permitidas |
| VOIP-2.2 | HIGH | `alwaysauthreject=no` en `[general]` — user enumeration via response timing |
| VOIP-2.3 | HIGH | AMI bound a `0.0.0.0` + interface pública detectada → AMI expuesta a WAN |

### Cifrado y mantenimiento
| ID | Sev | Detección |
|---|:---:|---|
| VOIP-3.1 | MEDIUM | Sin `media_encryption=sdes/dtls` / `encryption=yes` / `srtpcapable=yes` en ningún endpoint — SRTP off |
| VOIP-3.2 | MEDIUM | Sin `tlsenable=yes` / `protocol=tls` / `tlsbindaddr=` — SIP signalling sin TLS |
| VOIP-3.3 | MEDIUM | Asterisk major version < 20 (LTS soportado) — 16 y previos están EOL |

## Comandos de auditoría (lo que ejecutan los checks)

```bash
# Lectura de configs (read-only)
cat /etc/asterisk/sip.conf
cat /etc/asterisk/pjsip.conf
cat /etc/asterisk/manager.conf
cat /etc/asterisk/extensions.conf
cat /etc/asterisk/rtp.conf

# Version
asterisk -V
# → Asterisk 20.5.1

# Interfaces (para detectar exposure pública en VOIP-2.3)
ip -4 -o addr show
```

No se ejecuta ningún comando de modificación. No se intenta auth.

## Lo que NO está cubierto (roadmap v2)

- Asterisk REST Interface (ARI, port 8088) — equivalente a AMI pero
  con auth diferente. Misma lógica de check aplicable.
- Trunk SIP analysis (cuentas con providers tipo Twilio / VozMia)
  — separado del PBX interno.
- Voicemail config (`/etc/asterisk/voicemail.conf`) — passwords default.
- IAX2 protocol (legacy, raro hoy).
- Realtime / database backends (sip_users en MySQL).
- Recording storage encryption.

## Reporting

Estructura sugerida para el reporte LLM-narrated:

```
Host: 172.18.202.10 (PBX-TORRE)
Asterisk version: 16.30.0 (DEAD — EOL October 2025)
Findings:
  [CRITICAL] VOIP-1.2: AMI user 'admin' uses default secret 'amp111'
    Evidence: cat /etc/asterisk/manager.conf
    Remediation: rotate to 14+ char random; restrict permit/deny ACL
  [HIGH] VOIP-2.1: allowguest=yes detected
  [HIGH] VOIP-2.3: AMI bound to 0.0.0.0 with public interface 200.1.1.x
  [MEDIUM] VOIP-3.1: no SRTP markers found in sip.conf or pjsip.conf
  [MEDIUM] VOIP-3.2: SIP-TLS not configured
  [MEDIUM] VOIP-3.3: Asterisk 16 is EOL (use 20 LTS or 22 LTS)
```

Para Britimp POC (segmento TORRE-VOIP 172.18.202.0/24), el audit
corre contra cada host vivo detectado en discovery + identifica el
Asterisk via `asterisk_discover`, después dispara los 8 checks via
`run_compliance_audit(framework="asterisk")`.
