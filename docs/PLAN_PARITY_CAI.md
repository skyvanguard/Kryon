# F77.E — Camino a paridad con CAI + benchmark público

> Source competitive analysis: https://casestudies.aliasrobotics.com/
> Audit date: 2026-04-29
> Status: planning — no code yet

## Objetivo

Alcanzar **paridad técnica con CAI** (Cybersecurity AI de Alias Robotics)
en las áreas donde hoy estamos detrás, agregar **benchmark público dual
HTB + TryHackMe** (CAI publica "100% HTB success" sin score reproducible
de tercero), y abrir tres verticales nuevas (OT/ICS, IoT/SOHO, API
security profunda) sin perder el diferencial **banking-safe + Ollama-
local** que CAI no tiene.

Métrica de éxito al cierre del plan (mes 6):

| Eje | Hoy | Objetivo |
|---|---|---|
| Juice Shop benchmark | 85/111 (76%) | Mantener ≥ 80% |
| HTB Easy/Medium benchmark | 0 | ≥ 60% (de un labset cerrado de 30) |
| TryHackMe Easy benchmark | 0 | ≥ 70% (labset cerrado de 20) |
| Skills counter | 67 | 90+ (con OT/ICS + IoT + API depth) |
| Continuous mode | manual one-shot | scheduled + diff |
| CI/CD integration | 0 | GitHub Action + GitLab CI template publicados |
| Casos públicos | 0 | ≥ 2 con cliente bancario (con permiso) |

## Limitaciones conocidas

- **Ni HTB ni TryHackMe tienen API pública oficial.** Ambas son hostiles a
  automatización (CAPTCHA en submit, ToS prohíbe scraping). El benchmark
  vive contra **labsets clonados localmente** (HTB Active → spawn por
  VPN, TryHackMe → snapshot por subscripción VIP) o contra **VulnHub
  + Damn Vulnerable Web App + OWASP WebGoat** como sustitutos legales y
  reproducibles.
- **Banking pilot trabajo en paralelo** consume ~30% del bandwidth. Las
  estimaciones asumen 1 dev senior con 70% disponible.
- **Modelos de qwen3-14b** no son la frontera — algunos benchmarks
  requieren GPT-4 / Claude Opus para superar a CAI. La estrategia es
  publicar dual-track ("kryon-14b local" + "kryon-claude" cuando haya
  budget de API).

---

## Stage α — Benchmarks públicos (semanas 1-6)

### F81 — HTB benchmark harness

**Goal**: emitir un score reproducible contra una lista cerrada de 30
máquinas HTB Easy + Medium retiradas (las activas violan ToS de HTB
para publicación). Métrica: `% pwned`, `tiempo medio a user/root`,
`tools usadas por máquina`.

**Concrete deliverables**:
- `tests/benchmarks/htb/` con 30 walkthroughs JSON de referencia
  (tools-esperadas, flag-pattern, vuln-class).
- `scripts/htb_bench.py` — orquesta una corrida de Kryon contra cada
  máquina vía VPN OpenVPN; captura cadena de tools + tiempo + flag.
- `scripts/htb_score.py` — compara cadena real vs walkthrough; calcula
  `pwn_rate`, `mean_time_to_user`, `mean_time_to_root`.
- Reporte HTML auto-generado en `reports/htb-YYYY-MM-DD.html` con tabla
  por máquina + comparación contra runs previas.
- CI workflow `htb-benchmark.yml` que corre el harness 1× por semana.

**Effort**: 4 semanas. Trabajo más caro: clonar 30 máquinas localmente
(no se puede correr contra HTB live por ToS) usando VulnHub
equivalentes + 5 propias hechas con Vagrant.

**Dependencies**: F18 Juice Shop harness como referencia
(`scripts/f18/`).

**Riesgo**: HTB ToS prohíbe publicar walkthroughs con tools-usadas para
máquinas activas. Mitigación: usar SOLO máquinas retiradas (>1 año) +
disclaimer.

### F82 — TryHackMe benchmark harness

**Goal**: igual que F81 pero contra 20 rooms TryHackMe Easy (free tier
+ algunos VIP). Score similar.

**Concrete deliverables**:
- `tests/benchmarks/tryhackme/` con 20 walkthroughs JSON.
- `scripts/thm_bench.py` — orquesta runs vía VPN AttackBox.
- Reusa `scripts/htb_score.py` con shape común.
- Tabla comparativa cross-platform (HTB vs THM vs Juice Shop) en
  `reports/benchmarks-YYYY-MM-DD.html`.

**Effort**: 2 semanas (reusa harness de F81; THM más simple porque
muchas rooms ya están autocontenidas en docker compose).

**Dependencies**: F81.

### F83 — Scoreboard dashboard público

**Goal**: una página con scores actuales, históricos y comparación
contra CAI claims (HTB 100%) — fuente única de verdad reproducible.

**Concrete deliverables**:
- `docs/benchmarks/index.md` actualizado por CI tras cada run.
- Página estática en `kryon-bench.britimp.com.py` (subdominio del
  proyecto) renderizada desde GitHub Pages.
- API JSON `/scores.json` para terceros que quieran citar.
- Política de "fair-play": cualquiera puede repetir el benchmark
  siguiendo `docs/benchmarks/HOW_TO_REPRODUCE.md`.

**Effort**: 1 semana.

**Dependencies**: F81 + F82.

---

## Stage β — Diferenciadores técnicos (semanas 5-14)

Nota: empieza solapado con cierre de Stage α — F84 puede arrancar en
semana 5 mientras F83 todavía no terminó.

### F84 — OT/ICS skill set

**Goal**: 5 playbooks deterministicos para protocolos industriales
comunes, con detector pre-hooks (patrón F80) que el LLM no pueda
saltearse.

**Concrete deliverables**:
- `playbooks/ot/modbus-audit.md` (Modbus/TCP por puerto 502).
- `playbooks/ot/dnp3-audit.md` (DNP3 over TCP/UDP 20000).
- `playbooks/ot/s7comm-audit.md` (Siemens S7 protocol, ICS familia).
- `playbooks/ot/iec104-audit.md` (IEC 60870-5-104 — power grid).
- `playbooks/ot/mqtt-industrial-audit.md` (broker SCADA, no general
  IoT — diferenciado del IoT skill).
- Cada playbook: pre_hooks que invoca tool determinístico
  (`modbus_scan`, `dnp3_probe`, etc.); fallback a `nmap NSE` si falta
  el tool.
- Tools nuevos en `tools/ot/`: `modbus_scan`, `dnp3_probe`,
  `s7_enum`, `iec104_probe`, `mqtt_industrial_audit`.
- Compliance map: IEC 62443, NERC CIP, ISA-99 referenciados.
- Tests unit para cada tool con respuesta sintética del protocolo.

**Effort**: 8 semanas (5 protocolos × ~1.5 semanas; el más caro es
S7 por la propietariedad y los implants Siemens-specific).

**Dependencies**: F80 pre-hooks (ya existe).

**Riesgo**: probar contra equipo industrial real en lab requiere PLC
físico o emulator (Conpot, GRFICSv2). Mitigación: usar Conpot para
todos los unit tests + 1-2 emulators dedicados en VM Vagrant.

### F85 — Continuous validation + scheduler

**Goal**: pasar de "operator runs Kryon manualmente" a "Kryon corre
nightly contra fleet definida y emite diff vs run anterior".

**Concrete deliverables**:
- `kryon/scheduler/` — módulo nuevo con cron-style runner.
- `~/.kryon/fleet.yaml` — config: hosts, frameworks compliance,
  cadencia, destinatarios de alertas.
- `kryon/diff/` — engine que compara `EvalReport` entre runs y emite
  `diff.json`.
- `kryon/alerts/` — webhook a Slack/Teams/email cuando se detecta
  nueva finding HIGH/CRITICAL respecto al run anterior.
- CLI nuevo `/schedule` y `/diff <run-id>`.
- Reusa F77.G drafts: cada run guarda en `~/.kryon/runs/YYYY-MM-DD/`
  para histórico.

**Effort**: 5 semanas.

**Dependencies**: F77.G drafts pipeline (ya existe).

**Riesgo**: alertas falsas positivas son veneno (banker se desuscribe
después de 3 alerts vacías). Mitigación: ramp-up por host (primera
semana solo collect, segunda emite diff, tercera alerta).

### F86 — Race condition automation

**Goal**: detector + exploiter automatizado de race conditions (TOCTOU,
double-spend, file upload race) — capacidad que CAI demostró en su
caso "Race Condition Exploitation".

**Concrete deliverables**:
- Tool `race_condition_probe` en `tools/web/race.py`.
- Skill `playbooks/race-conditions.md`.
- Modos: `--mode upload` (file upload TOCTOU), `--mode auth`
  (concurrent login → session race), `--mode payment` (double-charge),
  `--mode coupon` (re-redeem).
- Bajo el capó: `httpx` con `asyncio.gather(N)` con jitter
  configurable; análisis de respuesta para detectar inconsistencia.
- Tests con servidor stub que simula vulnerable + safe.

**Effort**: 2-3 semanas.

**Dependencies**: ninguna específica.

### F87 — API security profunda

**Goal**: superar el playbook actual `api-security-test.md` con
tooling real para BOLA/IDOR systematic, OpenAPI import, GraphQL
introspection.

**Concrete deliverables**:
- Tool `openapi_enumerate` — toma URL de Swagger/OpenAPI/Postman,
  enumera endpoints + permission matrix.
- Tool `bola_probe` — para cada endpoint con `{id}` parameter,
  intenta el cross-tenant access (alice → bob's resource).
- Tool `graphql_introspect` + `graphql_attack` — query introspection,
  intenta queries privilegiadas.
- Skill `playbooks/api-security-deep.md` (reemplaza el básico actual).
- Compliance map: OWASP API Top 10 (2023).

**Effort**: 5-6 semanas.

**Dependencies**: F86 (race conditions) parcialmente — comparten el
patrón de "concurrent requests + diff response".

---

## Stage γ — Verticales + integraciones (semanas 12-22)

### F88 — HackerOne integration (Retester pattern)

**Goal**: connector que importe scope de un programa HackerOne, corra
Kryon en ese scope, deduplique findings contra reports históricos del
programa, emita PoC submit-ready en formato H1.

**Concrete deliverables**:
- `kryon/integrations/hackerone.py` — API client (HackerOne tiene API
  oficial: https://api.hackerone.com/).
- Tool `hackerone_scope_import` (descarga scope + previous reports).
- Skill `playbooks/hackerone-engagement.md` (ya existe placeholder;
  ahora tiene backbone funcional).
- Dedup engine reusa F77.G `findings_library.list()`.

**Effort**: 3 semanas.

**Dependencies**: F77.G findings library.

### F89 — CI/CD plugin (GitHub Action + GitLab CI)

**Goal**: Kryon como step en pipeline de cliente — corre SAST + DAST +
SCA en cada PR/MR.

**Concrete deliverables**:
- `.github/actions/kryon-scan/action.yml` (GitHub composite action).
- `kryon/templates/.gitlab-ci-kryon.yml` (GitLab CI template
  reusable).
- Modo `kryon scan --ci` que respeta exit codes para fail/pass del
  pipeline.
- Reporte SARIF para que GitHub Code Scanning lo entienda.
- Reporte Markdown que se postea como comment en PR.

**Effort**: 3 semanas.

**Dependencies**: appsec.md skill ya existente.

### F90 — Phishing / brand protection

**Goal**: nuevo vertical no offensive — defensive monitoring del
dominio del cliente.

**Concrete deliverables**:
- Tool `typosquat_detector` — para `bcp.com.py` busca `bcp.com.py.X`,
  homoglyphs (`bсp.com.py` con cyrillic с), y dominios similares
  registrados en últimos 90 días via dnstwist + dominio APIs.
- Tool `ct_monitor` — Certificate Transparency log monitoring para el
  dominio (alerta si alguien emite cert para subdominio inesperado).
- Tool `takedown_request_generator` — emite email/queja templated a
  registrar abuse contact.
- Skill `playbooks/brand-protection.md`.
- Modo daemon: `kryon brand watch <domain>` — corre cada hora,
  alerta a Slack.

**Effort**: 4 semanas.

**Dependencies**: F85 scheduler para el modo daemon.

### F91 — Lateral movement orchestrator

**Goal**: dado un foothold inicial, orquestar pivot multi-host con
Bloodhound CE para mapear paths a Domain Admin.

**Concrete deliverables**:
- Skill `playbooks/lateral-movement.md` (ya existe placeholder).
- Tool `pivot_chain` — toma host comprometido + creds, identifica
  next-hop con Bloodhound paths, ejecuta el pivot via SSH/SMB/WinRM.
- Tool `fleet_visibility` — escanea N hosts en paralelo, agrupa por
  cred-reuse, identifica weak links (legacy NTLM, no MFA).
- Integración con `active-directory-recon.md` ya existente.

**Effort**: 6 semanas.

**Dependencies**: active-directory-recon (existe), F87 API depth no
necesario.

**Riesgo**: el orchestrator MUY peligroso para producción. Mitigación:
solo correr con `--allow-lateral` flag explícito + `KRYON_RED_TEAM=true`
gate (mismo gate que `tools/evasion/`).

### F92 — IoT/embedded skills

**Goal**: 4 playbooks para infra de oficina común que un banco
auditaría: cámaras IP, NVRs, routers SOHO, smart locks.

**Concrete deliverables**:
- `playbooks/iot/ip-cameras-audit.md` (Hikvision, Dahua, generic
  ONVIF — credenciales default, RTSP stream auth bypass).
- `playbooks/iot/nvr-audit.md` (Dahua/Synology/QNAP NVR).
- `playbooks/iot/router-soho-audit.md` (Cisco/TPLink/Mikrotik
  SOHO — fw versions vs CVE corpus).
- `playbooks/iot/smart-lock-audit.md` (Bluetooth + WiFi smart locks
  — relay attack, replay).
- Tools: `onvif_probe`, `rtsp_brute`, `bluetooth_le_audit`.

**Effort**: 4 semanas.

**Dependencies**: ninguna.

---

## Stage δ — GTM (semanas 18-26, paralelo a Stage γ)

### F93 — Casos de éxito públicos

**Goal**: 2 casos cuantificables con cliente bancario (con permiso).

**Concrete deliverables**:
- Caso 1: "Kryon contra red interna BCP-style" — 200 hosts, 7 frameworks
  compliance, X findings críticos, Y horas vs Z horas pentest manual.
- Caso 2: "Kryon en pipeline DevSecOps" — N PRs auditados/mes, false
  positive rate, tiempo a remediación.
- Format: `casestudies/<client>-<date>.md` + landing page.
- Aprobación legal del cliente requerida (NDA-aware redaction).

**Effort**: 2 semanas writing + 4-8 semanas waiting on legal.

**Dependencies**: 1 cliente bancario que ya esté usando Kryon en prod
(F77.C banking pilot tiene candidatos).

### F94 — Productización tiers

**Goal**: pricing model público + licensing infrastructure.

**Concrete deliverables**:
- Tier matrix: Kryon Free (community) / Pro (single seat) / Enterprise
  (fleet + SLA).
- Licensing infra: license keys con rotación, feature flags por tier.
- Billing: Stripe + factura paraguaya (RUC). Free + Pro = self-serve;
  Enterprise = sales-led.
- Página `kryon.britimp.com.py/pricing`.

**Effort**: 4 semanas técnico + 4 semanas legal/contable.

**Dependencies**: F93 (casos para vender).

### F95 — Sitio público + docs

**Goal**: equivalent de casestudies.aliasrobotics.com — fuente única
SEO-friendly.

**Concrete deliverables**:
- Next.js + MDX en GitHub Pages (gratis).
- Landing: hero + benchmark dashboard (linkea F83) + casos (F93).
- `/docs` migración de docs internos relevantes (LEARNING_LOOP,
  REPL_DESIGN, PLAYBOOKS) con permalinks estables.
- `/blog` con 1 post/mes mínimo (releases, technical deep-dives).
- SEO: schema.org, sitemap.xml, OpenGraph cards.

**Effort**: 3 semanas técnico + ongoing.

**Dependencies**: F93, F94.

---

## Roadmap consolidado

```
Semana    1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26
α        F81 ===========                                                                
α        F82                 ===                                                            
α        F83                       =                                                          
β        F84                   =================================                                  
β        F85                       ====================                                                  
β        F86                                       =====                                              
β        F87                                                =====================                              
γ        F88                                                                  ============                          
γ        F89                                                                  ============                              
γ        F90                                                                              ================                  
γ        F91                                                                                          ============================  
γ        F92                                                                                                  ================
δ        F93                                                                          ========                              
δ        F94                                                                                          ============                  
δ        F95                                                                                                              ============
```

## Stop conditions

Re-evaluar el plan si:

- En el primer mes (Stage α) NO se llega a HTB 30%+ pwn rate. Indicio
  de que qwen3-14b no es modelo suficiente; pivote a Claude Opus o
  paramos benchmark hasta GPT-5/Sonnet 5.
- Banking pilot consume > 50% del bandwidth durante > 4 semanas.
  Re-priorizar — pilot paga, plan no.
- Algún cambio regulatorio LATAM altera el profile de demanda
  (ej. SEPRELAD requiere algo nuevo, o PCI v5 exige algo distinto).

## Pricing rough total

- Stage α: ~7 semanas (1 dev senior, 70%) → ~250h.
- Stage β: ~10 semanas → ~350h.
- Stage γ: ~10 semanas → ~350h.
- Stage δ: ~6 semanas técnico + 8 semanas legal → ~200h tech.

Total técnico: ~1150h ≈ 6 meses con 1 dev senior dedicado al 70%.

## Recomendación de arranque

**Semana 1 = arrancar F81 (HTB harness)**. Razones:
1. Es el unlock para todo lo demás — sin métrica pública nadie cree
   los Stage γ casos.
2. Bloque más caro al principio fuerza compromiso de scope; si no
   llegamos a HTB 30%+ en mes 1, sabemos el pivot.
3. Reusa infra existente (F18 Juice Shop) — reduce risk de "nuevo
   stack".
4. Da contenido inmediato para F95 (sitio público).

**No empezar por F94 (productización)**. Sin casos (F93) ni
benchmark (F81) no hay nada que vender. Productización sin
demostración real es marketing de humo.
