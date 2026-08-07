---
name: forensics
description: "Incident response, análisis forense, investigación de compromiso"
triggers:
  tech: []
  ports: []
  keywords: ["forensic", "incident", "compromiso", "memoria", "volatility", "log analysis", "breach", "malware"]
priority: 25
required_tools:
  - volatility_process_list
  - volatility_find_malware
  - autopsy_analyze
  - run_command
  - execute_code
---

## Incident Response Flow

1. **Triage**: Identificar alcance del compromiso
   - `run_command(command="last -a")` — últimos logins
   - `run_command(command="who")` — sesiones activas
   - `run_command(command="netstat -tlnp")` — conexiones sospechosas
   - `run_command(command="ps aux --sort=-%mem | head -20")` — procesos inusuales

2. **Preservación de evidencia**
   - `run_command(command="date -u")` — timestamp UTC
   - `run_command(command="cp /var/log/auth.log /tmp/evidence/")` — logs de auth
   - `run_command(command="find / -mtime -1 -type f 2>/dev/null | head -50")` — archivos modificados recientemente

3. **Análisis de logs**
   - `run_command(command="grep 'Failed password' /var/log/auth.log | tail -20")` — brute force
   - `run_command(command="grep 'Accepted' /var/log/auth.log | tail -20")` — accesos exitosos
   - `run_command(command="cat /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10")` — top IPs

4. **Búsqueda de persistencia**
   - Crontabs: `crontab -l`, `/etc/cron.d/`, `/var/spool/cron/`
   - Systemd: `systemctl list-units --type=service --state=running`
   - SSH keys: `find / -name authorized_keys 2>/dev/null`
   - Shell rc files: `.bashrc`, `.profile` modificados

5. **Timeline y reporte**
