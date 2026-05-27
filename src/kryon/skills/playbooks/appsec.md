---
name: appsec
description: "Application security — SAST, DAST, SCA para web apps"
triggers:
  tech: ["php", "laravel", "django", "node", "react", "angular", "java", "spring"]
  ports: [8080, 8443, 3000, 5000, 8000]
  keywords:
    - "appsec"
    - "owasp"
    - "sast"
    - "dast"
    - "sca"
    - "web app"
    - "application security"
    - "seguridad de aplicación"
    - "seguridad de aplicacion"
    - "seguridad de la aplicación"
    - "seguridad de la aplicacion"
    - "auditoría de aplicación"
    - "auditoria de aplicacion"
priority: 25
required_tools:
  - run_command
  - nuclei_scan
  - search_vulnerabilities
  - query_knowledge_base
pre_hooks:
  # F203.O — nuclei web vuln baseline via run_command (SSTI guard del
  # pre_hook spec NO acepta JSON literal en args, por eso usamos shell).
  # Banca-safe: rate-limit 50, severities high+critical only.
  - tool: run_command
    args:
      command: "nuclei -u {ctx.target} -severity critical,high -rate-limit 50 -bulk-size 10 -c 10 -follow-redirects -silent -j 2>&1 | head -200"
    inject_as: nuclei_appsec_baseline
    required: false
    timeout_s: 180
  # FASE 11.T — web common paths discovery (deterministic recon
  # baseline). Probes /robots.txt, /.git/config, /.env, /admin,
  # /login, /api, etc. Injects findings so the model can't omit
  # well-known paths the way it did against Robots THM (where it
  # never consulted /robots.txt). Banca-safe: pure GET, no payloads,
  # wall-clock-bounded helper.
  - python: ./pre_hooks/web_common_paths_hook.py:run
    inject_as: web_common_paths
    required: false
    timeout_s: 30
---

## OWASP Top 10 Checklist

1. **Injection** (A03): SQLi, NoSQLi, Command injection, LDAP injection
2. **Broken Auth** (A07): Session fixation, credential stuffing, JWT attacks
3. **Sensitive Data** (A02): Exposed API keys, .env files, debug pages
4. **XXE** (A05): XML external entity in SOAP/RSS endpoints
5. **Broken Access** (A01): IDOR, privilege escalation, forced browsing
6. **Security Misconfig** (A05): Default creds, directory listing, stack traces
7. **XSS** (A03): Reflected, stored, DOM-based
8. **Insecure Deserialization** (A08): PHP unserialize, Java ObjectInputStream
9. **Vulnerable Components** (A06): Outdated libraries with known CVEs
10. **Insufficient Logging** (A09): No audit trail for auth events

## Tools por tipo

- DAST: `nuclei_scan`, manual curl probes
- SCA: `run_command(command="retire.js --path .")` o npm audit
- Header analysis: `curl -sI TARGET` → CSP, HSTS, X-Frame-Options
- API testing: `curl -X OPTIONS TARGET/api/` → CORS misconfiguration
