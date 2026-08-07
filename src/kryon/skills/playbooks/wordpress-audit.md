---
name: wordpress-audit
description: "Auditoría especializada de WordPress"
triggers:
  tech: ["wordpress"]
  ports: []
  keywords: ["wordpress", "wp-content", "wp-login", "wpscan"]
priority: 15
required_tools:
  - run_command
  - nuclei_scan
pre_hooks:
  # F203.O — confirma WordPress + REST API users enum + nuclei WP templates.
  # Banca-safe: rate-limited, read-only enumeration.
  - tool: run_command
    args:
      command: "curl -sI {ctx.target}/wp-login.php 2>&1 | head -10 && echo --- && curl -s '{ctx.target}/?rest_route=/wp/v2/users' 2>&1 | head -120"
    inject_as: wp_confirm_and_users
    required: false
    timeout_s: 30
  - tool: run_command
    args:
      command: "nuclei -u {ctx.target} -tags wordpress -severity critical,high,medium -rate-limit 50 -bulk-size 10 -c 10 -silent -j 2>&1 | head -200"
    inject_as: nuclei_wordpress
    required: false
    timeout_s: 240
---

## WordPress Security Audit

1. Confirmar WordPress: `run_command(command="curl -s <TARGET>/wp-login.php | head -20")`
2. Enumerar usuarios y plugins: `run_command(command="wpscan --url <TARGET> --enumerate u,p,t -t 20 --random-user-agent")`
3. Buscar CVEs del core y plugins: `cve_intel(query="wordpress DETECTED")`
4. Templates específicos: `nuclei_scan(target=<TARGET>, tags="wordpress")`
5. Verificar archivos sensibles:
   - `curl -s <TARGET>/wp-config.php.bak`
   - `curl -s <TARGET>/wp-config.php~`
   - `curl -s <TARGET>/.wp-config.php.swp`
   - `curl -s <TARGET>/debug.log`
   - `curl -s <TARGET>/wp-content/debug.log`
6. Verificar xmlrpc.php: `curl -s -X POST <TARGET>/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'`
7. Verificar REST API: `curl -s <TARGET>/wp-json/wp/v2/users`

## Vectores comunes

- Plugins desactualizados (>60% de vulns WP)
- Credenciales default admin:admin
- File upload via media library con extensión .phtml/.php5
- XML-RPC brute force (sin rate limiting)
- REST API user enumeration
