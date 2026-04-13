---
name: swift-network-security
description: "Auditoría de seguridad SWIFT — CSP controls, Alliance Access, BIC validation, MT/MX messages"
triggers:
  tech: []
  ports: [443, 2701, 2702, 48002, 48003]
  keywords: ["swift", "csp", "alliance access", "alliance gateway", "bic", "iban", "mt103", "mt202", "iso20022", "customer security programme"]
priority: 18
required_tools:
  - run_command
  - nuclei_scan
---

## SWIFT Network Security Assessment

Auditoría de la infraestructura SWIFT de un banco. El programa **Customer
Security Programme (CSP)** define 32 controles obligatorios que SWIFT audita
cada año. Un breach SWIFT = pérdida real (ver Bangladesh Bank 2016, $81M).

### Alcance típico

Componentes SWIFT en un banco:
1. **SWIFT Alliance Access / Entry**: el software que envía/recibe mensajes
2. **SWIFT Alliance Gateway**: conexión al SWIFTNet
3. **HSM**: almacena llaves criptográficas (firma de mensajes)
4. **Operator workstations**: PCs que operadores usan para crear/aprobar mensajes
5. **Conexión a core banking**: feed de mensajes MT/MX

### CSP Controls — priorizar estos

CSCF (Customer Security Controls Framework) v2024:

**Mandatory — 23 controles**:
- 1.1 SWIFT Environment Protection (segregation)
- 1.2 OS Privileged Account Control
- 1.3 Virtualisation Platform Protection
- 2.1 Internal Data Flow Security
- 2.2 Security Updates
- 2.3 System Hardening
- 2.4A Back Office Data Flow Security
- 2.5A External Transmission Data Protection
- 2.6 Operator Session Confidentiality and Integrity
- 2.7 Vulnerability Scanning
- 2.8 Critical Activity Outsourcing
- 2.9 Transaction Business Controls
- 2.10 Application Hardening
- 2.11A RMA Business Controls
- 3.1 Physical Security
- 4.1 Password Policy
- 4.2 Multi-factor Authentication
- 5.1 Logical Access Control
- 5.2 Token Management
- 5.3A Personnel Vetting Process
- 5.4 Physical and Logical Password Storage
- 6.1 Malware Protection
- 6.2 Software Integrity
- 6.3 Database Integrity
- 6.4 Logging and Monitoring
- 6.5A Intrusion Detection

**Advisory — 9 controles adicionales**:
- 1.4A Restriction of Internet Access
- 1.5A Customer Environment Protection
- 2.11B RMA Business Controls (Advanced)
- 5.3B Personnel Vetting Process (Advanced)
- etc.

### Fase 1: Environment discovery

```bash
# Encontrar servidores SWIFT en la red (con autorización)
nmap -sV -p 443,2701,2702,48002,48003 SWIFT_SUBNET

# Puertos típicos:
# - 2701/2702: Alliance Access (SWIFTNet Link)
# - 48002/48003: Alliance Gateway
# - 443: Web interface (Alliance Web Platform)
```

### Fase 2: Segregation check (CSCF 1.1)

El entorno SWIFT debe estar **completamente segregado** del corporate network.

```bash
# Desde un host del corporate network:
# ¿Puede pingear el Alliance Access?
ping ALLIANCE_IP
# Esperado: no (segregated)

# ¿Qué puertos están reachable desde corporate?
nmap -sV -p 1-10000 ALLIANCE_IP
# Esperado: timeout en todos (salvo los necesarios para feed del core)

# Verificar jump server / PAM entre corporate y SWIFT
# Acceso debe ser solo vía CyberArk, BeyondTrust, etc.
```

### Fase 3: Operator workstation hardening (CSCF 6.1-6.5)

```bash
# En una Windows operator workstation (con autorización):

# AV/EDR activo?
Get-MpComputerStatus
Get-Service | Where {$_.Name -match "Carbon|CrowdStrike|Defender|Sentinel"}

# Application whitelisting?
Get-AppLockerPolicy -Effective -Xml
# O Device Guard
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard

# Internet access restricted?
# Verificar proxy forzado + whitelist de URLs SWIFT
Get-NetFirewallRule | Where {$_.DisplayName -match "SWIFT|Proxy"}

# Local admin disabled?
Get-LocalGroupMember Administrators
```

### Fase 4: MFA para operadores (CSCF 4.2)

```bash
# Verificar que login a Alliance requiere MFA:
# - Smartcard + PIN (más común)
# - Token hardware (RSA SecurID, Gemalto)
# - Biometric + PIN

# Test: intentar login con solo password
# Esperado: bloqueo o step-up a MFA
```

### Fase 5: Message tampering (el ataque Bangladesh)

El attack-chain de Bangladesh Bank (2016):
1. Phishing → malware en operator WS
2. Malware borra SWIFT messages outgoing del printer y log
3. Atacantes usan credenciales robadas para enviar MT103s fraudulentos
4. $81M transferidos antes de detección

**Tests a hacer**:

```bash
# ¿El sistema imprime TODOS los messages al printer?
# ¿Backup inmutable del log de mensajes enviados/recibidos?
# ¿Hay reconciliación diaria con la contraparte?

# ¿4-eyes principle?
# Creación + aprobación de mensaje por 2 personas distintas
# Ningún operador individual puede enviar un MT103

# ¿Transaction business controls? (CSCF 2.9)
# - Lista de beneficiarios permitidos
# - Montos máximos por operador
# - Horarios permitidos
# - Países permitidos
```

### Fase 6: Feed del core banking

```bash
# El core banking envía al SWIFT Alliance un archivo con los pagos a procesar
# Formato típico: XML o texto plano (MT format)
# Transport: MQ, SFTP, o shared folder

# Test:
# ¿El feed está firmado digitalmente?
# ¿El feed está cifrado en transit?
# ¿Hay validación de BIC, IBAN, amount format antes de Alliance?
# ¿Hay un log del feed recibido para reconciliación?
```

### Fase 7: RMA (Relationship Management Application)

RMA = lista de BICs con los que el banco se comunica.

```bash
# Verificar:
# - Lista RMA está actualizada
# - Hay aprobación requerida para agregar nuevo BIC
# - Alertas si se envía a BIC no-RMA (CSCF 2.11)
```

### Findings críticos

- Operator workstation sin application whitelisting → CRÍTICO
- Alliance accesible desde corporate network → CRÍTICO
- MFA no enforced para operators → CRÍTICO
- Un solo operator puede enviar MT103 (no 4-eyes) → CRÍTICO
- Log de mensajes mutable → ALTO
- Reconciliación manual sin frecuencia definida → ALTO
- Internet access desde operator WS → ALTO
- Local admin privileges en operator WS → ALTO

### Reporting

SWIFT CSP requiere **attestation anual**. El reporte debe:
- Mapear cada finding a control CSCF específico
- Indicar si el control es Mandatory o Advisory
- Remediation plan con deadline
- Compliance con CSP Self-Attestation form

### Compliance

- **SWIFT CSP (CSCF)** — obligatorio, anual
- **PCI-DSS** si procesan tarjetas además
- **Basel III** operational risk
- **BCP (PY) Resolución específica** para bancos en SWIFT
