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
