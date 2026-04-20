# Propuesta Ejecutiva — Kryon para Banca

## Problema

Los bancos paraguayos enfrentan un escenario de cumplimiento
superpuesto donde cada auditoría suele tratarse por separado:

- **BCP Paraguay** exige la Resolución 12/2021 sobre ciberseguridad y
  la disposición 2024 sobre red de cajeros automáticos.
- **PCI-DSS v4.0.1** es obligatorio para procesar tarjetas.
- **SWIFT CSP v2024** es anual para miembros SWIFT.
- **Auditorías internas** (comité de riesgo, SIB) piden evidencia
  defendible trimestral o semestralmente.

El costo típico de estas auditorías en LATAM oscila entre
**USD 40.000 y USD 150.000 por framework al año**, más el tiempo del
equipo de TI. La evidencia es manual, se pierde entre PDFs, y no es
reproducible — el siguiente auditor la rehace desde cero.

## Solución — Kryon

Kryon es un **agente autónomo de ciberseguridad** que ejecuta
controles deterministas en infraestructura bancaria (core bancario,
ATMs, Active Directory, bases de datos, hosts Linux/Windows) y genera
reportes PDF bilingües (ES/EN) con:

- Veredicto por control (PASS / FAIL / N/A / ERROR)
- Comando crudo ejecutado + stdout/stderr
- Hash SHA-256 de reproducibilidad
- Mapeo del hallazgo a múltiples marcos (PCI 10.5 ↔ BCP Art. 25 ↔ SWIFT 6.4)
- Narrativa explicativa opcional en lenguaje natural (LLM local —
  nunca envía datos del cliente a proveedores externos)

## Por qué Kryon frente a alternativas

| | Consultora tradicional | Herramientas globales | **Kryon** |
|---|---|---|---|
| Evidencia reproducible | No | Parcial | Sí, hash SHA-256 |
| BCP PY específico | Caso por caso | No existe | Framework nativo |
| Core bancario T24/Finacle/Flexcube | Manual | No cubre | 36 controles dedicados |
| ATM BCP 2024 | Manual | No cubre | 25 controles dedicados |
| Multi-framework consolidado | No | Costo por módulo | Incluido |
| Modelo LLM local | N/A | Cloud (expone datos) | **100% local** |
| Costo/año típico | USD 40-150K | USD 60-200K | Licencia fija + implementación |

## Cobertura actual (al día de hoy)

**9 frameworks registrados · 355 controles deterministas · 43 controles CRITICAL**

- CIS Ubuntu 22.04 LTS L1 (73)
- CIS Debian 12 L1 (47)
- CIS RHEL 9 L1 (54)
- CIS Docker Benchmark 1.6 (54)
- PCI-DSS v4.0.1 (31)
- SWIFT CSP v2024 (17)
- **BCP Paraguay Res. 12/2021** (18) — específico del regulador local
- **Core banking hardening** T24/Finacle/Flexcube (36)
- **ATM Security BCP Paraguay 2024** (25) — específico del regulador local

## Resultado esperado en el primer engagement (60 días)

1. **Diagnóstico consolidado** — PDF bilingüe cubriendo los 3-5
   frameworks relevantes al perfil del banco.
2. **Plan de remediación priorizado** — ranking por criticidad,
   esfuerzo y cita regulatoria.
3. **Dashboard de cumplimiento** — reporte ejecutivo trimestral
   automatizable.
4. **Entrenamiento al equipo interno** — traspaso para que el banco
   corra Kryon entre auditorías.

## Próximos pasos

1. Llamada de descubrimiento (30 min, sin compromiso)
2. Firma de NDA
3. Relevamiento técnico (cuestionario de alcance)
4. SOW con plazos y precio cerrado
5. Kick-off

**Contacto:** [ventas@kryon-security.com](mailto:ventas@kryon-security.com)
