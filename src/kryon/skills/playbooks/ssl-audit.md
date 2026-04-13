---
name: ssl-audit
description: "Auditoría de configuración SSL/TLS"
triggers:
  tech: ["ssl", "tls"]
  ports: [443, 8443, 993, 995, 465]
  keywords: ["ssl", "tls", "certificate", "certificado", "https", "cipher"]
priority: 30
required_tools:
  - run_command
---

## Auditoría SSL/TLS

1. `run_command(command="testssl.sh --severity HIGH HOST:443")` — análisis completo
2. Si testssl no disponible: `run_command(command="openssl s_client -connect HOST:443 -servername HOST </dev/null 2>/dev/null | openssl x509 -noout -text")`
3. Verificar:
   - Protocolo: TLS 1.0/1.1 = FAIL, TLS 1.2+ = OK
   - Cipher suites débiles (RC4, DES, NULL, EXPORT)
   - Certificate chain: CA válida, no self-signed
   - Expiración del certificado
   - Subject Alternative Names (SAN)
   - HSTS header presente y con max-age > 1 año
4. `run_command(command="curl -sI https://HOST | grep -i strict-transport")` — HSTS check

## Clasificación de riesgo

- **CRÍTICO**: TLS 1.0, cipher NULL/EXPORT, cert expirado
- **ALTO**: TLS 1.1, RC4, self-signed en producción
- **MEDIO**: sin HSTS, cipher suites débiles pero no rotas
- **BAJO**: cert expira en <30 días, SAN incompleto
