---
name: server-hardening
description: "Auditoría y hardening de servidores Linux via SSH (3-fase: diagnose → propose → apply)"
triggers:
  tech: ["linux", "ubuntu", "debian", "centos", "openssh"]
  ports: [22, 2222]
  keywords: ["hardening", "corregir", "remediar", "fix", "servidor", "server", "ssh", "credenciales", "endurecer", "asegurar", "audita"]
priority: 10
required_tools:
  - run_command
  - search_vulnerabilities
  - query_knowledge_base
---

## Flujo de hardening (ESTRICTO — 3 fases)

### Conexión SSH

Si el usuario proporciona credenciales:
- Con password: `run_command(command="sshpass -p 'PASSWORD' ssh -o StrictHostKeyChecking=no USER@HOST 'COMMAND'")`
- Con key: `run_command(command="ssh -i /path/to/key -o StrictHostKeyChecking=no USER@HOST 'COMMAND'")`
- Env vars: usar `$KRYON_SSH_USER`, `$KRYON_SSH_HOST`, `$KRYON_SSH_PASS`

Si el usuario menciona "dry-run" en su mensaje, informale:
> "Activá dry-run con `/dry-run on` antes de que ejecute comandos destructivos."

---

## FASE 1: Diagnóstico (SOLO LECTURA)

Ejecutar SIEMPRE primero, **sin modificar nada**. Comandos seguros únicamente:

1. `cat /etc/os-release` — OS + versión
2. `uname -r` — kernel
3. `apt list --upgradable 2>/dev/null | head -30` — paquetes desactualizados
4. `cat /etc/ssh/sshd_config | grep -iE "permitroot|passwordauth|port|protocol|maxauth|x11|allowusers"` — config SSH
5. `ufw status` o `iptables -L -n | head -30` — firewall
6. `cat /etc/passwd | grep -E '/bin/(bash|sh|zsh)'` — usuarios con shell
7. `find / -perm -4000 -type f 2>/dev/null | head -20` — SUID binaries
8. `crontab -l 2>/dev/null; ls /etc/cron.d/ 2>/dev/null` — crontabs
9. `systemctl list-units --type=service --state=running --no-pager` — servicios activos
10. `ss -tlnp 2>/dev/null | head -20` — puertos abiertos
11. `ls -la /etc/shadow /etc/passwd /etc/sudoers` — permisos
12. `tail -20 /var/log/auth.log 2>/dev/null` — auth logs
13. `last -a | head -10` — últimos logins

---

## FASE 2: Propuesta (NUNCA MODIFICAR AÚN)

Después del diagnóstico, producir:

```
## Findings detectados

| # | Finding | Severidad | Estado actual | Remediation propuesto |
|---|---------|-----------|---------------|----------------------|
| 1 | Root login SSH enabled | CRÍTICO | PermitRootLogin yes | sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config |
| 2 | Firewall inactivo | ALTO | ufw inactive | ufw enable + reglas base |
| 3 | 15 packages desactualizados | ALTO | apt outdated | apt upgrade -y |
| 4 | Password auth SSH | MEDIO | yes | Cambiar a key-only |

## ¿Aplico estas correcciones?
Respondé **"apply"** para ejecutar (con backups automáticos).
Respondé **"dry-run"** para preview sin cambios reales.
Respondé **"skip #1 #3"** para aplicar solo algunas.
```

**DETENÉ la cadena aquí.** No ejecutés nada destructivo hasta que el usuario confirme.

---

## FASE 3: Remediation (SOLO con OK explícito)

Si el usuario dice "apply", "sí", "adelante", "procedé":

### Regla de oro: BACKUP antes de modificar

Antes de CADA comando que modifica un archivo de config:
```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)
```

### SSH Hardening

```bash
# Backup
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)

# Apply changes
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
grep -q "^MaxAuthTries" /etc/ssh/sshd_config || echo "MaxAuthTries 3" >> /etc/ssh/sshd_config

# Test config BEFORE restart (critical!)
sshd -t || (echo "SSH config invalid, restoring backup"; cp /etc/ssh/sshd_config.bak.* /etc/ssh/sshd_config)

# Apply
systemctl restart sshd
systemctl status sshd --no-pager
```

### Firewall (UFW)

```bash
# Set defaults
ufw default deny incoming
ufw default allow outgoing

# Allow essential ports (ASK user which ports to keep)
ufw allow 22/tcp     # SSH
ufw allow 80/tcp     # HTTP
ufw allow 443/tcp    # HTTPS

# Enable
ufw --force enable
ufw status verbose
```

### Package updates

```bash
apt update
apt upgrade -y
apt autoremove -y
```

### File permissions

```bash
chmod 640 /etc/shadow
chmod 644 /etc/passwd
chmod 440 /etc/sudoers
```

### Verificación post-apply

Después de aplicar, re-ejecutar Fase 1 (diagnóstico) y producir tabla **antes/después**:

```
| Finding | Antes | Después | Estado |
|---------|-------|---------|--------|
| Root login SSH | yes | no | ✅ CORREGIDO |
| Firewall | inactive | active | ✅ CORREGIDO |
| Packages | 15 outdated | 0 | ✅ CORREGIDO |
```

---

## REGLAS CRÍTICAS (nunca las saltees)

1. **NUNCA modificar sin Fase 2 completada** y confirmación explícita del usuario
2. **SIEMPRE hacer backup** antes de `sed -i`, overwrites, deletes
3. **SIEMPRE testear config** antes de `systemctl restart` (especialmente sshd — si rompés sshd, perdiste acceso)
4. **Si un comando falla, DETENER la cadena** y reportar al usuario
5. **Si el usuario menciona "dry-run"**, informale que active `/dry-run on` primero
6. **NUNCA** correr `rm -rf`, `dd`, `mkfs`, `systemctl stop sshd` sin confirmación explícita de triple-check
7. **SIEMPRE** verificar con `systemctl status` o `ufw status` después de cada cambio
