---
name: appsec
description: "Application security — SAST, DAST, SCA para web apps"
triggers:
  tech: ["php", "laravel", "django", "node", "react", "angular", "java", "spring"]
  ports: [8080, 8443, 3000, 5000, 8000]
  keywords: ["appsec", "owasp", "sast", "dast", "sca", "web app", "application security"]
priority: 25
required_tools:
  - run_command
  - nuclei_scan
  - search_vulnerabilities
  - query_knowledge_base
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
