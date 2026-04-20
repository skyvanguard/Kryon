# Cuestionario de Alcance Pre-Engagement

Este cuestionario se completa en conjunto con el CISO y el responsable
de infraestructura del banco durante la reunión técnica inicial. Su
objetivo es fijar el alcance, los frameworks aplicables y los
prerequisitos operativos del engagement. **Sin este documento firmado,
no se inicia trabajo técnico.**

---

## Sección 1 — Identificación del cliente

| Campo | Valor |
|---|---|
| Razón social completa | |
| RUC | |
| Representante legal | |
| Dirección de notificación | |
| CISO responsable (nombre + correo) | |
| CTO / Gerente de Infraestructura | |
| Oficial de Cumplimiento | |

## Sección 2 — Perfil regulatorio

Marcar con X los marcos que aplican al banco:

- [ ] **BCP Paraguay Res. 12/2021** (ciberseguridad — obligatorio)
- [ ] **BCP Paraguay disposición ATM 2024** (si opera red de cajeros)
- [ ] **PCI-DSS v4.0.1** (si procesa, almacena o transmite PAN)
  - SAQ level: ☐ A  ☐ A-EP  ☐ B  ☐ B-IP  ☐ C  ☐ C-VT  ☐ D
- [ ] **SWIFT CSP v2024** (si el banco es miembro de SWIFT)
  - Architecture: ☐ A1  ☐ A2  ☐ A3  ☐ A4  ☐ B
- [ ] **SEPRELAD** (prevención de lavado — informativo, no técnico)
- [ ] **ISO 27001** (si tiene certificación vigente o en proceso)

## Sección 3 — Inventario técnico

### 3.1 Core bancario

- [ ] Temenos T24 / Transact — versión: ________
- [ ] Infosys Finacle — versión: ________
- [ ] Oracle Flexcube (FCUBS) — versión: ________
- [ ] Otro / propietario: ________

### 3.2 Red de cajeros (ATMs)

- [ ] No opera ATMs propios
- [ ] Opera ATMs — cantidad aproximada: ________
  - Proveedor: ☐ NCR  ☐ Diebold Nixdorf  ☐ Otro: ______
  - Sistema operativo: ☐ Win 10 IoT LTSC  ☐ Win 7  ☐ Otro: ______
  - Middleware: ☐ APTRA Advance NDC  ☐ Vynamic  ☐ Otro: ______

### 3.3 Infraestructura servidor

| Componente | Cantidad aproximada | Sistema operativo |
|---|---|---|
| Hosts Linux (RHEL/Ubuntu/Debian) | | |
| Hosts Windows Server | | |
| Bases de datos Oracle | | |
| Bases de datos DB2 / MS SQL | | |
| Clusters Kubernetes / Docker | | |
| Hosts Proxmox / VMware | | |
| Active Directory (dominios) | | |

### 3.4 Conectividad entrante

- [ ] Banking web / aplicación cliente pública
- [ ] Mobile banking (iOS + Android)
- [ ] Open Banking API (PSD2-like)
- [ ] Integraciones payment gateway (Bancard, Infonet, etc.)

## Sección 4 — Acceso para auditoría

Kryon audita vía **read-only**. El banco provee:

- [ ] Cuenta SSH con sudo read-only a hosts Linux — usuario: ________
- [ ] Cuenta WinRM / AD con privilegios de lectura a hosts Windows
- [ ] Cuenta Oracle con rol `SELECT_CATALOG_ROLE` (si aplica)
- [ ] VPN site-to-site o bastion host — proveer credenciales en bóveda cifrada
- [ ] IP desde la cual se autoriza el auditor (whitelist): ________

## Sección 5 — Ventanas operativas

- Horario preferido de ejecución: ☐ Hábil  ☐ Nocturno  ☐ Fin de semana
- Ventana de mantenimiento mensual: ________ día, ________ horas
- Carga máxima aceptada durante auditoría (% de CPU/RAM en el host): ____
- **Congelamiento de cambios antes de:** EOD / EOM / cierre trimestral

## Sección 6 — Entregables esperados

Marcar lo que el banco espera recibir:

- [ ] Reporte PDF bilingüe ES/EN consolidado
- [ ] Reporte por framework individual
- [ ] Plan de remediación priorizado con estimación de esfuerzo
- [ ] Dashboard HTML interactivo
- [ ] Evidencia bruta (JSON) para que auditor externo la reproduzca
- [ ] Presentación ejecutiva para Comité de Riesgo / Directorio
- [ ] Entrenamiento al equipo interno (cantidad de sesiones: ___)

## Sección 7 — Datos sensibles

- [ ] El banco **confirma** que no se entregarán a Kryon:
  - PANs reales de tarjetas
  - PINs de clientes
  - Credenciales de clientes (banking web, mobile)
  - Información de pruebas con datos sintéticos o de ambiente UAT

- [ ] El banco **autoriza** que Kryon acceda a:
  - [ ] Logs de sistemas de producción (redactados)
  - [ ] Configuraciones de red (no credenciales)
  - [ ] Archivos de política de seguridad
  - [ ] Metadatos de transacciones (no montos ni cuentas)

## Sección 8 — Cláusulas especiales

- [ ] Requiere acompañamiento de auditor interno del banco durante todas
      las sesiones técnicas
- [ ] Todas las pruebas deben ser **no-intrusivas** (solo lectura)
- [ ] Hallazgos deben comunicarse primero al banco antes de documentarse
- [ ] Backup de evidencia debe retenerse ____ meses según política local

## Firmas

| Rol | Nombre | Firma | Fecha |
|---|---|---|---|
| CISO del banco | | | |
| Representante Kryon | | | |
