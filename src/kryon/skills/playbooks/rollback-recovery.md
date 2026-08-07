---
name: rollback-recovery
description: "Deshacer cambios cuando algo sale mal"
triggers:
  tech: []
  ports: []
  keywords: ["rollback", "revertir", "deshacer", "restaurar", "undo", "se rompio", "broken", "no funciona"]
priority: 2
required_tools:
  - run_command
---

## Protocolo de rollback

Cuando el usuario reporta que algo se rompió después de un cambio:

### 1. Identificar qué se modificó

Si hay session_memory: revisá `## Tools Executed` y `## Key Findings` para
reconstruir la secuencia de cambios.

Sino, preguntá: **"¿Qué comando/cambio aplicaste último antes del problema?"**

### 2. Buscar backups

```bash
# Backups que Kryon haya creado
ls -la /etc/ssh/sshd_config.bak.* 2>/dev/null
ls -la /etc/*.bak.* 2>/dev/null
find /etc /home -name "*.bak.*" -mmin -60 2>/dev/null   # últimos 60 min

# Para DB
ls -la /tmp/*_backup_*.sql 2>/dev/null
```

### 3. Restaurar

**Config files:**
```bash
# Encontrar el backup más reciente
LATEST=$(ls -t /etc/ssh/sshd_config.bak.* | head -1)
cp "$LATEST" /etc/ssh/sshd_config

# Verificar + restart
sshd -t && systemctl restart sshd
```

**Firewall bloqueó acceso:**
```bash
ufw disable                        # apagar firewall primero
iptables -F                         # limpiar reglas
# Luego reaplicar una regla mínima correcta
```

**Servicio no arranca:**
```bash
journalctl -u <service> -n 50      # ver qué error hay
systemctl status <service>
# Restaurar config previa
cp /etc/<service>/<config>.bak.* /etc/<service>/<config>
systemctl restart <service>
```

**Paquete roto:**
```bash
apt install --reinstall <pkg>
# O si apt está roto
dpkg --configure -a
apt-get install -f
```

**DB corrupta:**
```bash
# Parar apps que usan la DB
systemctl stop <app>
# Restaurar
mysql -u root -p DB < /tmp/DB_backup_*.sql
# Reiniciar apps
systemctl start <app>
```

### 4. Verificar recovery

Después del rollback:
- El servicio volvió? `systemctl status <service>`
- El sistema está accesible? (SSH, HTTP, etc.)
- Los datos están intactos? (count de filas, checksum de archivos)

### 5. Reportar y aprender

Producir un resumen:
```
## Rollback completado

**Qué se rompió:** <descripción>
**Causa raíz:** <qué comando / config la causó>
**Cómo se corrigió:** <backup restaurado + acciones>
**Lecciones:** <qué habría prevenido esto>
```

Guardar en session_memory para que futuras sesiones eviten el mismo error.

## Si NO hay backup disponible

Situación grave. Opciones:

1. **Reinstalar paquete** (para configs que vienen con paquetes):
   ```bash
   apt install --reinstall openssh-server
   dpkg -L openssh-server | grep sshd_config
   ```

2. **Usar la config default del paquete**:
   ```bash
   apt download openssh-server
   dpkg-deb -x openssh-server*.deb /tmp/fresh
   cp /tmp/fresh/etc/ssh/sshd_config /etc/ssh/
   ```

3. **Buscar copia del template en /usr/share**:
   ```bash
   find /usr/share -name "sshd_config" 2>/dev/null
   ```

4. **Último recurso**: reinstalar el sistema (documentar todo lo que aprendiste).

## Regla de oro

Si vas a cambiar algo, **tené el rollback listo ANTES** de aplicar el cambio.
No es opcional.
