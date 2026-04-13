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
  - search_vulnerabilities
  - nuclei_scan
---

## WordPress Security Audit

1. Confirmar WordPress: `run_command(command="curl -s HOST/wp-login.php | head -20")`
2. Enumerar usuarios y plugins: `run_command(command="wpscan --url HOST --enumerate u,p,t -t 20 --random-user-agent")`
3. Buscar CVEs del core y plugins: `search_vulnerabilities("wordpress", version=DETECTED)`
4. Templates específicos: `nuclei_scan(target=HOST, tags="wordpress")`
5. Verificar archivos sensibles:
   - `curl -s HOST/wp-config.php.bak`
   - `curl -s HOST/wp-config.php~`
   - `curl -s HOST/.wp-config.php.swp`
   - `curl -s HOST/debug.log`
   - `curl -s HOST/wp-content/debug.log`
6. Verificar xmlrpc.php: `curl -s -X POST HOST/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'`
7. Verificar REST API: `curl -s HOST/wp-json/wp/v2/users`

## Vectores comunes

- Plugins desactualizados (>60% de vulns WP)
- Credenciales default admin:admin
- File upload via media library con extensión .phtml/.php5
- XML-RPC brute force (sin rate limiting)
- REST API user enumeration
