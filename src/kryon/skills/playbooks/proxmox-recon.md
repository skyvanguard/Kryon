---
name: proxmox-recon
description: "Reconocimiento pasivo + fingerprinting de Proxmox VE antes de audit/hardening"
triggers:
  tech: ["proxmox", "pve"]
  ports: [8006, 8007, 3128, 5900, 5901]
  keywords:
    - "fingerprint proxmox"
    - "detect proxmox"
    - "identify hypervisor"
    - "enumerate proxmox"
    - "scan proxmox"
    - "proxmox recon"
priority: 15
required_tools:
  - run_command
  - nuclei_scan
---

## Proxmox recon — identificar y mapear antes de auditar

Read-only. Sirve cuando no tenés credenciales SSH todavía y necesitás confirmar
target, versión, y alcance antes de pedir autorización para auditoría profunda.

### Etapa 1 — Fingerprinting externo (sin credenciales)

```bash
# Confirma si es Proxmox (Web UI port 8006 → HTTPS obligatorio)
curl -sk -m 5 https://TARGET:8006/ | grep -oE 'pve-[0-9]+\.[0-9]+' | head -1
# Si responde redirect a /#v=, es PVE
curl -skI -m 5 https://TARGET:8006/ | grep -i "location\|server\|set-cookie"
# La cookie PVEAuthCookie es la huella definitiva

# Versión exacta (sin auth por diseño)
curl -sk -m 5 https://TARGET:8006/api2/json/version | python3 -m json.tool
# Output: {"data":{"version":"8.2.4","release":"8.2","repoid":"..."}}

# Banner SSH — check si es banner default PVE
nc -w3 TARGET 22 </dev/null | head -1
# "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3" → Debian 12 → PVE 8
```

### Etapa 2 — Superficie de red expuesta (port scan mgmt)

```bash
# Puertos canónicos Proxmox
nmap -Pn -sS -p 22,8006,8007,3128,5404,5405,5900-5910,16509 TARGET --script=banner
# 8006 = Web UI + API
# 8007 = Proxmox Backup Server (si coinstalado)
# 3128 = SPICE proxy
# 5404/5405 = corosync (cluster) — NUNCA deben ser públicos
# 5900-5910 = VNC console (VMs)
# 16509 = libvirt (si expone)

# Detección de cluster multi-nodo (corosync udp)
nmap -sU -p 5404,5405 TARGET
# Si abiertos desde internet externo → CRITICAL leak del cluster
```

### Etapa 3 — Endpoints API públicos sin auth

```bash
# /version  (expected: 200 OK)
curl -sk https://TARGET:8006/api2/json/version
# /access/ticket  (expected: 401 o 200 con prompt de auth)
curl -sk https://TARGET:8006/api2/json/access/ticket

# Endpoints que NO deberían responder 200 sin auth
for ep in nodes cluster/status cluster/resources access/domains access/users; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "https://TARGET:8006/api2/json/$ep")
  echo "$ep → $code"
done
# Todos deben devolver 401. Cualquier 200 → leak → check PVE-1.2.
```

### Etapa 4 — Detección de realm y método de auth

```bash
# Realms disponibles (OFTEN leak sin auth en versiones viejas)
curl -sk https://TARGET:8006/api2/json/access/domains
# Expected: 401. Si 200, versión vulnerable o misconfig.
```

### Etapa 5 — Nuclei para CVE públicas específicas Proxmox

```bash
# Nuclei tiene templates específicos PVE
nuclei -u https://TARGET:8006 -tags proxmox,pve -silent
# CVEs recientes típicas:
#   CVE-2023-22815 (pve-manager XSS pre-auth)
#   CVE-2021-44144 (pve-firewall priv esc)
#   CVE-2020-11651/11652 (saltstack si usan Salt)
```

### Qué reportar después del recon

Tabla breve:

| Campo | Valor ejemplo |
|---|---|
| Confirmado como PVE | SI / NO |
| Versión | 8.2.4 |
| EOL status | supported / EOL-soon / EOL |
| Puertos mgmt expuestos | 22, 8006 (expected) + 5404 (LEAK) |
| Endpoints pre-auth 200 | `/version` (ok), `/nodes` (CRITICAL si 200) |
| CVE match | CVE-2023-22815 si versión < 7.3-6 |
| Cluster detectado | SI (N nodos) / NO |

Con esto alcanza para:
1. Pedir autorización escrita específica al CISO del banco
2. Agendar ventana de acceso SSH con el equipo IT
3. Correr `proxmox-audit` skill con credenciales

### Integraciones downstream

- Confirmado PVE → skill `proxmox-audit` (F23 checks)
- Versión EOL → skill `cve-lookup` + reporte ejecutivo
- Endpoint 200 pre-auth → escalar CRITICAL antes de audit formal
- Cluster multi-nodo → repetir audit por cada nodo (los checks son per-host)

### Lo que NO hace este skill

- **No intenta login ni brute force.** Solo banner + API pública.
- **No ejecuta exploits** aun si detecta CVE. Reporta, no explota.
- **No se conecta a VMs huéspedes.** El perímetro es el nodo Proxmox.
- **No reporta falsos positivos de Nuclei sin verificación manual.**
