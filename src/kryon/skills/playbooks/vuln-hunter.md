---
name: vuln-hunter
description: "Búsqueda avanzada de vulnerabilidades, bug bounty, zero-day"
triggers:
  tech: []
  ports: []
  keywords: ["vulnerability", "vuln", "bug bounty", "cve", "zero-day", "exploit"]
priority: 15
required_tools:
  - run_command
  - nuclei_scan
  - search_vulnerabilities
  - query_knowledge_base
  - duckduckgo_search
---

## Metodología de Hunting

1. Fingerprint detallado del stack (versiones exactas)
2. `search_vulnerabilities(technology=TECH, version=VERSION)` para cada componente
3. `nuclei_scan(target=HOST, severity="critical,high")` — templates críticos
4. `duckduckgo_search(query="TECH VERSION exploit CVE site:exploit-db.com")` — exploits públicos
5. Pruebas manuales:
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
