---
name: safe-modification
description: "Principios de seguridad para modificar sistemas — aplicar ANTES de cualquier cambio"
triggers:
  tech: []
  ports: []
  keywords: ["modificar", "cambiar", "aplicar", "apply", "editar", "corregir", "remediar", "hardening", "fix", "deploy", "instalar"]
priority: 1
required_tools:
  - run_command
---

## Principios de modificación segura

Cuando vayas a modificar un sistema (archivos de config, servicios, base de datos,
reglas de firewall, paquetes), aplicás este protocolo SIN excepciones.

### 1. Diagnóstico antes de proponer

Nunca propongas un cambio sin haber leído el estado actual.
- Config SSH? `cat /etc/ssh/sshd_config | grep -v '^#\|^$'`
- Firewall? `ufw status verbose` o `iptables -L -n`
- Servicios? `systemctl list-units --state=running`
- Crontabs? `crontab -l; ls /etc/cron.d/`
- Base de datos? `SHOW TABLES; DESCRIBE <table>;`

### 2. Propuesta antes de aplicar

Siempre producir una tabla de cambios ANTES de ejecutar:

```
## Cambios propuestos

| # | Archivo/Servicio | Cambio | Severidad | Reversible? |
|---|---|---|---|---|
| 1 | /etc/ssh/sshd_config | PermitRootLogin yes → no | ALTO | Sí (backup) |
| 2 | ufw | enable + allow 22,80,443 | MEDIO | Sí (ufw disable) |
```

Después pedí: **"¿Procedo con estos cambios?"** y esperá OK explícito.

### 3. Backup antes de tocar

Siempre, SIEMPRE backup ANTES de modificar:
```bash
cp <archivo> <archivo>.bak.$(date +%s)
```

Para DB: `mysqldump DB > /tmp/DB_backup_$(date +%s).sql`
Para paquetes: `dpkg -l > /tmp/packages_$(date +%s).txt`

### 4. Aplicar un cambio a la vez

Nunca encadenar múltiples modificaciones destructivas con `&&`. Aplicar
secuencialmente, verificando cada una:
```bash
# Mal: todo junto
sed -i '...' file && systemctl restart X && ufw enable && rm -rf ...

# Bien: paso por paso
cp file file.bak.$(date +%s)
sed -i '...' file
diff file file.bak.* | head -20   # ver qué cambió
```

### 5. Test antes de apply destructivo

- `sshd_config`? → `sshd -t` ANTES de restart (romper sshd = pierde acceso)
- `nginx.conf`? → `nginx -t`
- `apache2`? → `apache2ctl configtest`
- `sudoers`? → `visudo -c`
- `iptables`? → guardar `iptables-save > /tmp/rules.bak` antes de cambiar
- SQL migration? → correr en transacción: `BEGIN;` → cambios → `ROLLBACK;` primero

### 6. Verificar después

Después de aplicar, SIEMPRE confirmar que funcionó:
- `systemctl status <service>` — servicio activo?
- `ufw status` — reglas aplicadas?
- `cat <archivo>` — cambios persistidos?
- Re-conectar SSH desde otra ventana ANTES de cerrar la sesión actual (si cambiaste SSH config)

### 7. Rollback plan explícito

Para cada cambio, tener el comando de rollback listo:
- `cp <archivo>.bak.* <archivo>` — restaurar config
- `ufw disable` — apagar firewall si lo rompió
- `mysql DB < backup.sql` — restaurar DB
- `apt install --reinstall <pkg>` — reinstalar paquete

Si algo falla durante el proceso, ejecutar rollback INMEDIATAMENTE y reportar.

## Operaciones prohibidas sin triple confirmación

Las siguientes operaciones requieren que el usuario confirme 3 veces
con el nombre exacto del target:

- `rm -rf /` o cualquier variación sobre paths del sistema
- `dd if=... of=/dev/sdX` — escritura directa a disco
- `mkfs.*` — format de filesystem
- `DROP DATABASE` / `DROP TABLE` sin WHERE
- `DELETE FROM` sin WHERE
- `systemctl stop sshd` en servidor remoto (te quedás sin acceso)
- `iptables -F` sin reglas de recovery cargadas
- `shutdown` / `reboot` / `poweroff`

## Casos donde NO debés modificar

- El usuario NO te dio credenciales explícitas → solo auditar, no modificar
- El target NO es del usuario (análisis de web ajena) → solo reporte, nunca modificar
- Estás en medio de un pentest ofensivo → no hardenear el target
- El cambio requiere reboot y no sabés si es servidor de prod → preguntar primero
