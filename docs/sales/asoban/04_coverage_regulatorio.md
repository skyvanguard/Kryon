# Matriz de Cobertura Regulatoria

Este documento muestra cómo los controles deterministas de Kryon
cubren los marcos aplicables a bancos paraguayos. Se entrega al
Oficial de Cumplimiento del prospecto.

## Marcos cubiertos

| Marco | ID | Controles | CRITICAL | Actualización |
|---|---|---|---|---|
| CIS Ubuntu 22.04 LTS L1 | `cis-ubuntu-22.04-l1` | 73 | 5 | 2025-04 |
| CIS Debian 12 L1 | `cis-debian-12-l1` | 47 | 2 | 2025-04 |
| CIS RHEL 9 L1 | `cis-rhel-9-l1` | 54 | 4 | 2025-04 |
| CIS Docker Benchmark 1.6 | `cis-docker-1.6` | 54 | 3 | 2025-04 |
| PCI-DSS v4.0.1 | `pci-dss-4.0` | 31 | 8 | 2024 |
| SWIFT CSP v2024 | `swift-csp-2024` | 17 | 5 | 2024 |
| **BCP Paraguay Res. 12/2021** | `bcp-py-res-12-2021` | 18 | 3 | 2021 |
| Core Banking (T24/Finacle/Flexcube) | `core-banking-hardening` | 36 | 8 | 2025-04 |
| **ATM Security BCP 2024** | `atm-security-bcp-2024` | 25 | 5 | 2024 |
| **TOTAL** | | **355** | **43** | |

## Cross-mapping regulatorio

Un mismo requisito de seguridad suele exigirse por varios marcos bajo
vocabularios distintos. Kryon registra el vínculo, de modo que un solo
hallazgo sirva como evidencia ante múltiples auditores.

### Registro centralizado de auditoría

| Marco | Referencia |
|---|---|
| PCI-DSS v4.0.1 | 10.5 — Protección de logs de auditoría |
| BCP PY Res. 12/2021 | Art. 25 — Retención centralizada de registros |
| SWIFT CSP v2024 | 6.4 — Loggeo y monitoreo de cuentas |
| Core Banking | CBH-6.1 — rsyslog a SIEM |

### Cifrado de datos en tránsito

| Marco | Referencia |
|---|---|
| PCI-DSS v4.0.1 | 4.2.1 — TLS en canales abiertos |
| BCP PY Res. 12/2021 | Art. 19 — Protección de comunicaciones |
| SWIFT CSP v2024 | 2.5 — Encriptación punto a punto |
| Core Banking | CBH-5.5 — TCPS / SERVER_ENCRYPT |
| ATM BCP 2024 | ATM-3.1 — mTLS / IPsec al switch |

### Segregación de ambientes (producción vs. no-producción)

| Marco | Referencia |
|---|---|
| BCP PY Res. 12/2021 | Art. 21 — Segregación de ambientes |
| SWIFT CSP v2024 | 1.1 — Asegurar el entorno SWIFT |
| Core Banking | CBH-6.3 — UAT en VLAN separada |

### Control de acceso privilegiado / break-glass

| Marco | Referencia |
|---|---|
| PCI-DSS v4.0.1 | 7.2 — Acceso por rol basado en necesidad |
| BCP PY Res. 12/2021 | Art. 23 — Gestión de cuentas privilegiadas |
| SWIFT CSP v2024 | 5.1 — Autenticación fuerte para operadores |
| Core Banking | CBH-6.4 — Cuentas admin bloqueadas entre engagements |

### Respaldo cifrado fuera de sitio

| Marco | Referencia |
|---|---|
| PCI-DSS v4.0.1 | 3.4 — Datos almacenados cifrados |
| BCP PY Res. 12/2021 | Art. 24 — Continuidad operativa + respaldos |
| Core Banking | CBH-6.7 — Backups cifrados en sitio alterno |

### Autenticación multifactor para administradores

| Marco | Referencia |
|---|---|
| PCI-DSS v4.0.1 | 8.4 — MFA para accesos administrativos |
| SWIFT CSP v2024 | 4.2 — MFA para cuentas SWIFT |
| BCP PY Res. 12/2021 | Art. 22 — Mecanismos multifactor |

## Perfiles recomendados de engagement

Según el perfil del banco, se sugiere un subconjunto de frameworks
para un primer engagement. Los demás pueden añadirse en fases
posteriores.

### Perfil A — Banco pequeño (activos < USD 100M, sin ATMs)

- BCP PY Res. 12/2021 (obligatorio)
- CIS Ubuntu / Debian / RHEL (según OS)
- PCI-DSS (si procesa tarjetas)

**Total:** ~170 controles · 3-4 semanas de engagement.

### Perfil B — Banco mediano (USD 100M-1B, con ATMs)

Todo lo de perfil A, más:
- ATM Security BCP 2024
- CIS Docker Benchmark (si usa contenedores)
- Core Banking Hardening (si usa T24/Finacle/Flexcube)

**Total:** ~290 controles · 5-6 semanas de engagement.

### Perfil C — Banco grande (USD 1B+, SWIFT-conectado)

Todo lo de perfil B, más:
- SWIFT CSP v2024

**Total:** 355 controles · 8-10 semanas de engagement.

## Nota sobre actualizaciones

Los marcos se actualizan siguiendo el ciclo de vida del regulador o
estándar. Kryon ejecuta regression harness semanal para garantizar
que ningún control se pierda entre versiones y que todo cambio quede
reflejado en el baseline del repositorio público.

**Última verificación de integridad:** ver
[tests/compliance/baselines/regression_baseline.json](../../../tests/compliance/baselines/regression_baseline.json).
