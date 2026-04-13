---
name: server-hardening
description: "Auditoría y hardening de servidores Linux via SSH"
triggers:
  tech: ["linux", "ubuntu", "debian", "centos", "openssh"]
  ports: [22, 2222]
  keywords: ["hardening", "corregir", "remediar", "fix", "servidor", "server", "ssh", "credenciales", "endurecer"]
priority: 10
required_tools:
  - run_command
  - search_vulnerabilities
  - query_knowledge_base
---

## Conexión SSH

Si el usuario proporciona credenciales (user, host, password o key):
- Usar: `run_command(command="sshpass -p 'PASSWORD' ssh -o StrictHostKeyChecking=no USER@HOST 'COMMAND'")`
- O si hay key: `run_command(command="ssh -i /path/to/key -o StrictHostKeyChecking=no USER@HOST 'COMMAND'")`
- Si las credenciales están en env vars: `$KRYON_SSH_USER`, `$KRYON_SSH_HOST`, `$KRYON_SSH_PASS`

## Fase 1: Diagnóstico (solo lectura)

1. OS info: `cat /etc/os-release`
2. Kernel: `uname -r`
3. Paquetes desactualizados: `apt list --upgradable 2>/dev/null | head -30` o `yum check-update | head -30`
4. SSH config: `cat /etc/ssh/sshd_config | grep -E "PermitRoot|PasswordAuth|Port|Protocol|MaxAuth|X11|AllowUsers"`
5. Firewall: `ufw status` o `iptables -L -n | head -30` o `firewalld --state`
6. Usuarios con shell: `cat /etc/passwd | grep -E '/bin/(bash|sh|zsh)'`
7. SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
8. Crontabs: `crontab -l 2>/dev/null; ls /etc/cron.d/`
9. Servicios corriendo: `systemctl list-units --type=service --state=running`
10. Puertos abiertos: `ss -tlnp`
11. Permisos de archivos sensibles: `ls -la /etc/shadow /etc/passwd /etc/sudoers`
12. Logs de auth: `tail -20 /var/log/auth.log 2>/dev/null`

## Fase 2: Informe de Findings

Después del diagnóstico, producir tabla:

| Finding | Severidad | Estado Actual | Recomendación |
|---|---|---|---|
| Root login SSH | CRÍTICO | PermitRootLogin yes | Cambiar a no |
| Packages desactualizados | ALTO | 15 pendientes | apt upgrade |
| No firewall | ALTO | ufw inactive | Activar con reglas |
| Password auth SSH | MEDIO | yes | Cambiar a key-only |

## Fase 3: Remediation (solo con autorización explícita)

Si el usuario dice "corregí todo" o "aplicá las correcciones":

### SSH Hardening
```
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
systemctl restart sshd
```

### Firewall
```
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
```

### Updates
```
apt update && apt upgrade -y
```

### File Permissions
```
chmod 640 /etc/shadow
chmod 644 /etc/passwd
chmod 440 /etc/sudoers
```

## Fase 4: Verificación post-remediation

Después de aplicar correcciones, re-ejecutar Fase 1 para confirmar
que los findings se resolvieron. Producir tabla antes/después.

## Reglas

- SIEMPRE hacer diagnóstico (Fase 1) ANTES de corregir
- NUNCA corregir sin que el usuario diga explícitamente "corregí" o "fix"
- Hacer backup antes de modificar configs: `cp file file.bak.$(date +%s)`
- Si no hay credenciales, pedirlas UNA vez
- Loggear cada cambio realizado
