---
name: server-hardening
description: "Auditoría y hardening de servidores Linux via SSH"
triggers:
  tech: ["linux", "ubuntu", "debian", "centos", "openssh"]
  ports: [22, 2222]
  keywords: ["hardening", "endurecer", "asegurar", "audita servidor", "server", "ssh credentials", "pentest defensivo"]
priority: 10
required_tools:
  - run_command
---

## Server Hardening

Playbook específico de hardening de servidores Linux. Seguí SIEMPRE los
principios del skill `safe-modification` (diagnóstico → propuesta → apply
con backups → verificación).

## Hardening Flow (estricto — NO saltar fases)

### Fase 1: Diagnóstico (solo lectura, SIEMPRE primero)
Ejecutá los comandos del checklist más abajo. Solo lectura. NUNCA modificar
nada en esta fase. Recopilá toda la evidencia antes de pasar a Fase 2.

### Fase 2: Propuesta (NUNCA modificar todavía)
Después del diagnóstico:
1. Producí una tabla de findings con severidad (CRITICAL/HIGH/MEDIUM/LOW).
2. Para cada finding, listá el comando de remediation propuesto.
3. Preguntá explícitamente al usuario: "¿Aplico estas correcciones?".
4. ESPERÁ la respuesta. No procedas sin OK explícito.

### Fase 3: Remediation (solo con confirmación explícita)
Si el usuario dice "apply", "sí", "adelante", "ok":
1. Backup antes de cada modificación: `cp file file.bak.$(date +%s)`.
2. Aplicá un comando a la vez.
3. Verificá tras cada cambio (service status, restart OK, syntax check).
4. Re-auditá al final con el checklist de Fase 1.

### Reglas críticas
- NUNCA modificar sin Fase 2 completada y confirmación del usuario.
- SIEMPRE backup antes de `sed -i`, redirecciones a archivos del sistema, o overwrites.
- Si el usuario pide "dry-run" o "preview", setear `KRYON_DRY_RUN=true` ANTES de Fase 3 — el tool `run_command` simulará comandos destructivos sin ejecutarlos.
- Si un comando falla, DETENER la cadena y reportar (no seguir aplicando).
- Comandos clasificados como `destructive` (rm -rf, mkfs, systemctl stop sshd, dd a disco, DROP TABLE, etc.) reciben un prefijo de warning automático del tool — leélo y reconfirmá si vas a aplicarlo.

### Conexión SSH

- Con password: `sshpass -p "$KRYON_SSH_PASS" ssh -o StrictHostKeyChecking=no $KRYON_SSH_USER@$KRYON_SSH_HOST 'CMD'`
- Con key: `ssh -i KEYFILE -o StrictHostKeyChecking=no USER@HOST 'CMD'`

## Checklist de Fase 1 (Diagnóstico, solo lectura)

Ejecutá cada comando y guardá el resultado para la tabla de findings:

```bash
cat /etc/os-release                                    # OS + version
uname -r                                                # kernel
apt list --upgradable 2>/dev/null | wc -l              # count de paquetes outdated
grep -iE "permitroot|passwordauth|x11|maxauth" /etc/ssh/sshd_config
ufw status verbose 2>/dev/null || iptables -L -n | head -20
cat /etc/passwd | grep -c '/bin/\(bash\|sh\|zsh\)'    # count de usuarios con shell
find / -perm -4000 -type f 2>/dev/null | wc -l        # SUID count
crontab -l 2>/dev/null; ls /etc/cron.d/ 2>/dev/null
ss -tlnp 2>/dev/null | grep LISTEN                     # puertos abiertos
ls -la /etc/shadow /etc/passwd /etc/sudoers            # permisos
grep -c "Failed password" /var/log/auth.log 2>/dev/null # brute force count
```

## Checklist de Fase 2 (Propuesta con tabla)

Producir esta tabla con los findings del diagnóstico:

| # | Finding | Severidad | Estado actual | Remediation | Reversible? |
|---|---------|-----------|---------------|-------------|-------------|
| 1 | Root login SSH habilitado | CRÍTICO | yes | sed en sshd_config | Sí (backup) |
| 2 | Firewall inactivo | ALTO | inactive | ufw enable + reglas | Sí (ufw disable) |
| 3 | 15 packages desactualizados | ALTO | 15 | apt upgrade | No trivial |
| 4 | Password auth SSH | MEDIO | yes | key-only | Sí (backup) |
| 5 | Shadow permissions 644 | MEDIO | 644 | chmod 640 | Sí |

Pedí confirmación explícita antes de continuar: **"¿Procedo con estos cambios?"**

## Playbook de Fase 3 (Remediation con backups)

Cuando el usuario confirma, aplicar en este orden (menor riesgo primero):

### 3a. File permissions (trivial, reversible)

```bash
chmod 640 /etc/shadow
chmod 644 /etc/passwd
chmod 440 /etc/sudoers
```

### 3b. Package updates

```bash
# Backup list de paquetes actual
dpkg -l > /tmp/packages_before_update.txt

apt update
apt upgrade -y
apt autoremove -y
```

### 3c. Firewall (con cuidado — podés lockearte)

```bash
# Guardar reglas actuales por si acaso
iptables-save > /tmp/iptables_before.rules
ufw status verbose > /tmp/ufw_before.txt

# Aplicar DEFAULTS primero (sin enable aún)
ufw default deny incoming
ufw default allow outgoing

# Reglas ESENCIALES antes de enable (crítico!)
ufw allow 22/tcp   # SSH — SIN ESTO TE LOCKEÁS
# Preguntar al usuario qué otros puertos abrir: HTTP 80, HTTPS 443, custom?

# Enable
ufw --force enable
ufw status verbose
```

### 3d. SSH hardening (MÁXIMO cuidado — si rompés sshd perdés acceso)

```bash
# BACKUP OBLIGATORIO
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)

# Cambios
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
grep -q "^MaxAuthTries" /etc/ssh/sshd_config || echo "MaxAuthTries 3" >> /etc/ssh/sshd_config

# TEST config ANTES de restart (sino te quedás sin SSH)
sshd -t
# Si sshd -t falla, RESTAURAR backup inmediatamente

# ANTES de restart: avisar al usuario "voy a reiniciar sshd, mantené esta sesión abierta
# y probá una segunda conexión desde otra ventana antes de cerrar esta"

systemctl restart sshd
systemctl status sshd --no-pager
```

## Fase 4: Verificación

Producir tabla antes/después:

| Finding | Antes | Después | Estado |
|---------|-------|---------|--------|
| Root login SSH | yes | no | ✅ |
| Firewall | inactive | active | ✅ |
| Packages | 15 outdated | 0 | ✅ |
| Shadow perms | 644 | 640 | ✅ |

## Reglas específicas de server-hardening

- **Antes de reiniciar sshd**, pedir al usuario que abra una segunda sesión SSH
  en otra ventana para no perder acceso si falla
- **Nunca deshabilitar el puerto SSH** sin antes haber configurado una vía alternativa
- **Nunca flush iptables sin reglas de recovery cargadas** (`iptables-save` antes)
- **Si es servidor de producción**, siempre preguntar en qué ventana de mantenimiento
  aplicar cambios
- **Si no hay backups de config**, el primer paso es CREARLOS (`cp -a /etc /root/etc.backup.$(date +%s)`)
