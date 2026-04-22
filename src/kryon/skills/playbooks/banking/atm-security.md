---
name: atm-security
description: "ATM security assessment — jackpotting, skimming, black box, network-level attacks"
triggers:
  tech: []
  ports: [80, 443, 3389, 445]
  keywords: ["atm", "cajero", "cajero automatico", "jackpotting", "skimming", "ncr", "diebold", "wincor", "hyosung"]
priority: 18
required_tools:
  - run_command
  - nuclei_scan
---

> **Estado: TEMPLATE — requiere acceso físico + lab del vendor.**
> ATM testing es hands-on con hardware (NCR, Diebold Nixdorf,
> Wincor): black-box attacks, jackpotting, card skimming detection.
> Kryon puede guiar metodología y levantar el informe, pero no
> reemplaza un pentest físico con equipo certificado PCI-PTS.

## ATM Security Assessment

Testing de seguridad para ATMs. Alto riesgo físico y financiero.

### Pre-engagement

- **Autorización por escrito** del banco + proveedor del ATM
- Ubicación específica del ATM (una unidad, NO producción)
- Horarios acordados (ATMs fuera de uso durante test)
- Presencia física del security officer del banco
- Plan de rollback si se "brickea" el ATM

### Arquitectura típica

```
[Hardware]
├── CPU (típicamente Windows XP/7/10 embedded)
├── Dispenser (cash)
├── Card Reader (magstripe + chip)
├── PIN Pad (EPP — Encrypted PIN Pad)
├── Receipt Printer
├── Camera
└── Network interface (Ethernet o 4G)

[Software]
├── Multivendor Software (XFS standard)
├── ATM application (NCR APTRA, Diebold Agilis, Wincor ProTopas)
├── Monitoring (Ncr Edge, SHP, Solidcore)
└── Antivirus / EDR

[Network]
├── ATM ↔ Switch (ISO 8583 mensajes)
├── Switch ↔ Acquirer ↔ Issuer
└── Connection vía VPN (IPsec) al host del banco
```

### Fase 1: Physical + USB ports

```bash
# ¿Hay USB ports expuestos? (top/bottom cabinet)
# Test: conectar USB con payload
# Rubber Ducky / Bash Bunny → inyectar comandos si Autorun habilitado

# Boot from USB? Si el BIOS no tiene password:
# Arrancar con Kali USB → montar disco → dumpear hashes
# mimikatz sekurlsa::logonpasswords
```

### Fase 2: Network-level attacks

**1. MITM en el cable Ethernet del ATM**

```bash
# Si el cable sale de la cabeceracarpeta sin protección
# Conectar un switch + capture con Wireshark
tshark -i eth0 -f "host ATM_IP" -w atm_traffic.pcap

# ISO 8583 messages son binarios — usar iso8583parse
# Si no hay cifrado (MAC pero no encryption) → modificar requests
```

**2. Comunicación con el switch**

```bash
# Puertos típicos
nmap -sV -p 1414,2030,5000,5001,8583,9999 ATM_IP

# Inyección de mensajes ISO 8583
# Message types:
# - 0100/0110 Authorization
# - 0200/0210 Financial transaction
# - 0400/0410 Reversal
# - 0800/0810 Network management
```

### Fase 3: Jackpotting

**Objetivo**: hacer que el ATM despache efectivo sin autorización real.

```bash
# Via XFS directamente (requiere código en el ATM)
# Malware típicos: Tyupkin, GreenDispenser, Ripper, Alice, Ploutus
# Técnica: inyectar dll que hable con dispenser.dll

# Via red (black box attack)
# Desconectar ATM del switch real → conectar un Raspberry Pi
# Enviar comandos XFS válidos al ATM
# El ATM cree que habla con el switch legítimo
```

### Fase 4: Skimming detection (defensivo)

Para audit de ATMs ya desplegados:

```bash
# Visual inspection (photo analysis)
# Verificar:
# - Card slot: ¿hay doble grosor o aditamento?
# - PIN pad: ¿está rígido/firme o tiene holgura?
# - Cámara adicional apuntando al pin pad
# - Teclado con piezas flojas
```

### Fase 5: Anti-malware stack audit

```bash
# Desde consola remota autorizada:
# Windows ATM
Get-MpComputerStatus | Select AntivirusEnabled, RealTimeProtectionEnabled
Get-Service | Where {$_.Name -match "SHP|Solidcore|Bit9|CrowdStrike"}

# Verificar whitelisting activo (application control)
# ATMs deben tener whitelist mode, no blacklist
```

### Findings típicos (severidad CRÍTICA)

- USB ports accesibles sin FLAG_SECURE
- BIOS sin password
- Boot order permite USB first
- Autorun habilitado
- Windows sin parches (common: MS17-010, CVE-2019-0708)
- ATM application corre con privilegios de SYSTEM
- No hay application whitelisting
- Red plana (ATM ve otros ATMs en la misma VLAN)
- Comunicación ATM↔Switch sin TLS
- MAC key estática por largos períodos

### Cumplimiento

- **PCI PTS** (POI Security) para el hardware
- **PCI P2PE** si hay Point-to-Point Encryption
- **PCI DSS Req 9.9** para monitoreo de tampering físico
- **ISO 8583** para mensajes transaccionales
- **BCP (PY)** Resolución específica para ATMs

### Reporting

Para bancos el informe debe incluir:
- Fotos de la inspección física
- PCAP de la sesión de red
- CVSS + riesgo financiero estimado por ATM afectado
- Recomendaciones por categoría (HW, SW, Red, Procesos)
- Comparación con MITRE ATT&CK for ICS (si aplica)
