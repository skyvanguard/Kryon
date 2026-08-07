---
name: proxmox-hardening
description: "Hardening Proxmox VE por fases — diagnóstico → propuesta → apply con backups + approval explícito"
triggers:
  tech: ["proxmox", "pve", "pve-manager"]
  ports: [8006, 8007]
  keywords:
    - "hardening proxmox"
    - "endurecer proxmox"
    - "pve hardening"
    - "remediate proxmox"
    - "proxmox remediation"
    - "proxmox fix"
    - "pve harden"
priority: 20
required_tools:
  - run_command
  - request_approval
  - run_compliance_audit
---

## Proxmox VE hardening por fases

Seguí SIEMPRE el contrato `safe-modification`: diagnóstico → propuesta → apply con backups
→ verificación → re-audit. Nunca modificás sin confirmación explícita del operador.

### Fase 1 — Diagnóstico (read-only)

Ejecutá `run_compliance_audit(host=<PVE>, framework="proxmox")`. Se corren los 7 checks F23
(PVE-1.1 a PVE-5.1). Tiempo estimado < 10s/nodo.

Complementá con read-only extra:

```bash
# Identificación del nodo
ssh root@PVE 'pveversion --verbose; hostname; cat /etc/pve/.members 2>/dev/null'

# Servicios corriendo
ssh root@PVE 'systemctl status pveproxy pvedaemon pve-firewall corosync pve-cluster --no-pager | head -60'

# Usuarios y tokens
ssh root@PVE 'pveum user list; pveum token list 2>/dev/null'

# Storage (busca unencrypted at-rest)
ssh root@PVE 'pvesm status; cat /etc/pve/storage.cfg'
```

**NO** ejecutes nada que modifique estado todavía.

### Fase 2 — Propuesta (estructurada, NUNCA auto-apply)

Presentá tabla con:
- `control_id` (PVE-x.x)
- severidad
- evidence actual
- remediation propuesta (comando literal + explicación 1 línea)
- riesgo de aplicar (puede cortar conexión si SSH ya está activa, etc)

Pedí OK con `request_approval`. **Esperá respuesta**. Si el usuario dice "no" o duda,
**no apliques ninguna**, documentá la decisión y segui con los demás.

### Fase 3 — Apply (sólo con OK explícito)

Orden recomendado — de menor a mayor riesgo de rompimiento:

#### 1. PVE-5.1 — Actualizaciones pendientes
Riesgo: reinicio servicios. Bajo si es patch nivel.
```bash
# Backup de snapshot del estado actual (si el nodo corre VMs críticas, pedí mantenimiento)
ssh root@PVE 'apt-get update && apt-get -s upgrade | grep -c "^Inst "'  # confirma N
ssh root@PVE 'DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" dist-upgrade'
ssh root@PVE 'pveversion'  # re-verify
```

#### 2. PVE-1.1 — Certificado Web UI
Riesgo: bajo si tenés ACME configurado, alto si upload custom sin backup del viejo.
```bash
# Backup cert actual
ssh root@PVE 'cp /etc/pve/local/pve-ssl.pem /root/pve-ssl.pem.bak.$(date +%s)'
ssh root@PVE 'cp /etc/pve/local/pve-ssl.key /root/pve-ssl.key.bak.$(date +%s)'

# Opción ACME (prod público)
ssh root@PVE 'pvenode acme account register default admin@bank.com.py'
ssh root@PVE 'pvenode config set --acme domains=pve.bank.com.py'
ssh root@PVE 'pvenode acme cert order'

# Opción Custom CA corporativa (prod interno)
scp bank-ca-cert.pem root@PVE:/tmp/
scp bank-ca-key.pem root@PVE:/tmp/
ssh root@PVE 'pvenode cert set --force /tmp/bank-ca-cert.pem /tmp/bank-ca-key.pem'
ssh root@PVE 'systemctl restart pveproxy'
```

#### 3. PVE-3.2 — Tokens hygiene
Riesgo: medio — si CI/CD usa un token vencido, pipeline rompe. Coordinar con DevOps.
```bash
# Backup token.cfg
ssh root@PVE 'cp /etc/pve/priv/token.cfg /root/token.cfg.bak.$(date +%s)'

# Rotar permisos
ssh root@PVE 'chmod 640 /etc/pve/priv/token.cfg; chown root:www-data /etc/pve/priv/token.cfg'

# Re-emitir tokens con expiry (ejemplo)
ssh root@PVE 'pveum user token remove root@pam oldtoken'  # PREGUNTAR ANTES
ssh root@PVE 'pveum user add ci@pve --password $(pwgen -s 32 1)'
ssh root@PVE 'pveum aclmod / --role PVEAdmin --users ci@pve'
ssh root@PVE 'pveum user token add ci@pve prod --privsep 1 --expire $(date -d "+1 year" +%s)'
# Entregar nuevo token al equipo DevOps en canal seguro
```

#### 4. PVE-3.1 — Enforce 2FA
Riesgo: medio — si te quedás sin backup token, perdés acceso.
```bash
# Verificar que al menos 2 admins tienen TFA configurado ANTES
ssh root@PVE 'cat /etc/pve/user.cfg | grep -E "^user:.*@pam"'

# Enforce en realm pam
ssh root@PVE 'cp /etc/pve/domains.cfg /root/domains.cfg.bak.$(date +%s)'
ssh root@PVE "sed -i 's/^pam: pam$/pam: pam\n\tdefault-tfa oath/' /etc/pve/domains.cfg"

# Per-user TFA enrollment: guiar al admin via Web UI → Username → TFA
# CLI alternativo si ya tenés TOTP secret:
ssh root@PVE 'pveum user tfa add admin@pam totp "Bank Auditor" --secret <BASE32>'
```

#### 5. PVE-4.1 — Firewall enable
Riesgo: **ALTO** — si la default policy ya DROP y no añadiste allow rules para SSH/8006,
**te desconectás**. Fase obligatoria: validar rules ANTES de enable.
```bash
# Backup
ssh root@PVE 'cp -r /etc/pve/firewall /root/firewall.bak.$(date +%s)'

# Preparar reglas mínimas ANTES de enable. Agregá tu IP de administración:
ssh root@PVE 'cat >> /etc/pve/firewall/cluster.fw <<EOF
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: ACCEPT

[RULES]
IN ACCEPT -source YOUR_ADMIN_IP -p tcp -dport 22 -log info
IN ACCEPT -source YOUR_ADMIN_IP -p tcp -dport 8006 -log info
IN ACCEPT -source CLUSTER_SUBNET -p udp -dport 5404:5405  # corosync
EOF'

# Verificar sintaxis ANTES de activar
ssh root@PVE 'pve-firewall compile'

# Activar
ssh root@PVE 'pve-firewall start; pve-firewall status'
```

#### 6. PVE-2.1 — SSH hardening
Riesgo: **MUY ALTO** si no validaste auth key-only previamente.

**CHECK ANTES**: que tu propia sesión SSH usa llave y el nuevo admin (no root) también.

```bash
# Validar login sin password con llave desde otra terminal
ssh -i /path/admin_key admin@PVE 'echo "key-auth OK"'

# Backup sshd_config
ssh root@PVE 'cp /etc/ssh/sshd_config /root/sshd_config.bak.$(date +%s)'

# Aplicar hardening
ssh root@PVE "sed -i -e 's/^#*PermitRootLogin.*/PermitRootLogin no/' \
                     -e 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' \
                     -e 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' \
                     -e 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' \
                     /etc/ssh/sshd_config"

# Test config syntax antes de restart
ssh root@PVE 'sshd -t && echo OK'

# Restart (cierra sesiones activas → asegurate que tenés backdoor)
ssh root@PVE 'systemctl restart ssh'

# Verificar desde tu terminal secundaria que podés entrar
```

#### 7. PVE-1.2 — Endpoints expuestos
Si detectó 200 donde debe 401, la causa típica es un proxy mal config o ACL tampered.
**No se arregla con comandos atómicos**, requiere investigación forense (¿quién tocó
/etc/pve/datacenter.cfg?). Escalar a equipo de seguridad interno del banco.

### Fase 4 — Verificación

Re-ejecutá `run_compliance_audit`. Cada PVE-x.x que hayas remediado debe pasar a PASS.
Cualquiera que siga FAIL: reportá + revertí desde backup + investigá.

```bash
# Rollback de emergencia
ssh root@PVE 'cp /root/sshd_config.bak.* /etc/ssh/sshd_config && systemctl restart ssh'
ssh root@PVE 'cp -r /root/firewall.bak.*/* /etc/pve/firewall/ && pve-firewall restart'
```

### Reglas no negociables

- **Ventana de mantenimiento** para PVE-4.1 (firewall) y PVE-2.1 (SSH) — podés cortarte.
- **Evidencia antes y después** para cada remediation aplicada (log completo al informe).
- **Una remediation a la vez**: si se rompe algo, sabés exactamente cuál.
- **Nunca aplicar en nodo secundario de cluster primero**: corosync puede kickout el nodo.
- **Documentar todo** en el ticket de la auditoría — requisito regulatorio.

## Lo que este skill NO hace

- **No investiga compromise**. Si sospechás intrusión, escalá a IR — este skill solo
  arregla misconfigs conocidos.
- **No reconstruye cluster**. Si hay corruption de /etc/pve, llamá soporte Proxmox.
- **No escala a root desde una cuenta sin sudo**. El operador debe traer credenciales.
