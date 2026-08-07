---
name: tomcat-audit
description: "Apache Tomcat audit — version EOL + Ghostcat + manager exposure + default webapps (8 checks deterministicos)"
triggers:
  tech: ["tomcat", "apache-tomcat", "apache-coyote", "coyote", "java-servlet", "jsp"]
  # Tomcat fingerprint ports only — 8009 = AJP (Ghostcat), 8005 = shutdown.
  # Generic 8080/8443/8000 matched any app server; keyword 'tomcat'/'ajp' covers intent.
  ports: [8009, 8005]
  keywords:
    - "tomcat"
    - "apache tomcat"
    - "apache-coyote"
    - "ajp"
    - "ghostcat"
    - "jsp app"
    - "java web server"
    - "tomcat audit"
    - "auditoria tomcat"
    - "auditoría tomcat"
priority: 9
required_tools:
  - run_compliance_audit
  - generate_compliance_pdf
  - tomcat_recon
  - nuclei_scan
  - run_command
pre_hooks:
  - tool: run_compliance_audit
    args:
      framework: tomcat
      host: "{ctx.host}"
    inject_as: deterministic_compliance_findings
    required: true
    timeout_s: 120
---

## Status del playbook

**Production-capable (F200.A).** 8 checks deterministicos
(TOMCAT-1.1..TOMCAT-2.4) cableados a `run_compliance_audit(framework="tomcat")`.
Surfaceado en testing interno contra un host Tomcat
(Apache Tomcat 7.0.34 — EOL desde marzo 2021). Hash de
reproducibilidad estable.

Read-only por diseño: probes HTTP + TCP, **sin** intentos de exploit
ni bruteforce de credenciales.

## Default behavior

1. **Pre-engagement check**: confirmá autorización escrita, IP/hostname
   del Tomcat, puerto (default 8080, configurable via
   `KRYON_TOMCAT_PORT`), ventana. Read-only puede correr en horario
   laboral.
2. **Llamá `run_compliance_audit(host=..., framework="tomcat")` PRIMERO**.
   Corre los 8 checks F200.A sin LLM en el detection path. Alias
   válido: `tomcat`, `apache-tomcat`.
3. **Narrá los hallazgos** ordenados por severidad. Para cada FAIL
   cita el `evidence_command` y `remediation_static`.
4. **Fase opcional — Recon adicional**: `tomcat_recon(target=..., port=8080)`
   para inspection manual del fingerprint completo.
5. Si el operador pide PDF, llamá
   `generate_compliance_pdf(host=..., framework="tomcat")`.
6. **NUNCA** intentes credenciales default contra `/manager/html`. Eso
   es offensive — requiere `KRYON_RED_TEAM=true` + autorización
   escrita.

## 8 Checks deterministicos

Los IDs `TOMCAT-X.Y` corresponden 1:1 con módulos en
`src/kryon/compliance/checks/tomcat/`. Verdicts PASS / FAIL / N/A / ERROR.

### Versión y exposición crítica
| ID | Sev | Detección |
|---|:---:|---|
| TOMCAT-1.1 | CRITICAL | Major version EOL (< 9.x = sin patches desde 2021/2024) |
| TOMCAT-1.2 | CRITICAL | AJP 8009 expuesto en interfaz de red — **Ghostcat CVE-2020-1938** |
| TOMCAT-1.3 | HIGH | `/manager/html` reachable (200/401) — bruteforce surface |
| TOMCAT-1.4 | HIGH | `/host-manager/html` reachable (200/401) |

### Information disclosure
| ID | Sev | Detección |
|---|:---:|---|
| TOMCAT-2.1 | MEDIUM | Error page revela `Apache Tomcat/X.Y.Z` |
| TOMCAT-2.2 | MEDIUM | Header `Server: Apache-Coyote/1.1` o `Apache Tomcat/X.Y.Z` |
| TOMCAT-2.3 | MEDIUM | `/docs/` deployed en producción |
| TOMCAT-2.4 | LOW | `/examples/` deployed (XSS pool conocido) |

## Comandos de auditoría

Todos via HTTP probe + TCP probe (sin SSH al host):

```bash
# Fingerprint version
curl http://target:8080/kryon-recon-no-existe  # error page → "<title>Apache Tomcat/X.Y.Z..."

# Endpoint exposure
curl http://target:8080/manager/html       # 200/401 = exposed; 404 = OK
curl http://target:8080/host-manager/html
curl http://target:8080/docs/
curl http://target:8080/examples/

# AJP probe (Ghostcat precondition)
nc -zv target 8009    # TCP open = vulnerable if version < 7.0.100/8.5.51/9.0.31
```

Override de puerto via env:
```bash
export KRYON_TOMCAT_PORT=8090   # si Tomcat escucha en non-default
```

## CVE corpus (cross-ref con `cve_intel`)

Cuando TOMCAT-1.1 detecta version EOL, agregar al reporte la lista
de CVEs públicos aplicables. Top CVEs por major version:

**Tomcat 7 (EOL March 2021)**
- CVE-2020-1938 Ghostcat (CRITICAL, fixed 7.0.100)
- CVE-2017-12617 PUT RCE (CRITICAL)
- CVE-2016-8735 JMX RCE (CRITICAL)
- CVE-2014-7810 SecurityManager bypass (HIGH)

**Tomcat 8 (EOL March 2024)**
- CVE-2020-1938 Ghostcat (fixed 8.5.51)
- CVE-2017-12617 PUT RCE (fixed 8.5.23)
- CVE-2019-12418 RMI privesc (HIGH)
- CVE-2021-25122 Information disclosure (HIGH)

**Tomcat 9 (still LTS)**
- CVE-2020-1938 fixed 9.0.31 (verificar version exacta)
- CVE-2024-50379 race condition file upload (HIGH, fixed 9.0.98)

## Limitaciones conocidas (v1)

- **No prueba credenciales default**: requiere KRYON_RED_TEAM y
  autorización. Sin esa flag, el check solo reporta si Manager está
  reachable, no si las creds son débiles.
- **No analiza WAR deployments arbitrarios**: solo los webapps
  default (manager/host-manager/docs/examples). Apps custom
  (e.g. `/Pages/login.jsp`) quedan al recon manual o al agent loop.
- **No verifica `tomcat-users.xml`**: requiere SSH al host. Roadmap
  v2 podría agregar TOMCAT-3.x para checks que necesiten shell access.

## Reporting

```
Host: 192.0.2.11 (Apache Tomcat 7.0.34, JSP app "Pages/login.jsp")
Findings:
  [CRITICAL] TOMCAT-1.1: Tomcat 7 EOL since March 2021
  [CRITICAL] TOMCAT-1.2: AJP 8009 open (Ghostcat CVE-2020-1938)
  [HIGH]     TOMCAT-1.3: /manager/html exposed (401 Basic auth)
  [MEDIUM]   TOMCAT-2.1: Error page leaks Apache Tomcat/7.0.34
  [MEDIUM]   TOMCAT-2.2: Server: Apache-Coyote/1.1 disclosure
Remediation: see remediation_static of each check + plan migration to
Tomcat 9 LTS.
```
