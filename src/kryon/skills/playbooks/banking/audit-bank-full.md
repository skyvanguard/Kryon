---
name: audit-bank-full
description: "Auditoría bancaria integral — orquestador multi-framework (F46). Ejecuta perfil A/B/C cubriendo PCI-DSS, SWIFT CSP, BCP PY, CIS OS, Core Banking T24/Finacle/Flexcube, ATMs, Docker, Windows Server. Genera PDF consolidado."
triggers:
  tech: []
  ports: [22, 443, 1433, 1521, 3389, 5985, 5986, 7001, 8443]
  keywords:
    - "auditoría completa"
    - "auditoria completa"
    - "audit full"
    - "audit bank-full"
    - "audit bancario"
    - "auditoría bancaria"
    - "auditoría integral"
    - "cumplimiento integral"
    - "compliance full"
    - "engagement completo"
    - "asoban"
    - "banco completo"
    - "perfil bancario"
    - "multi-framework"
    - "todos los frameworks"
    - "all frameworks"
    - "sib"
    - "superintendencia"
priority: 40
required_tools:
  - run_compliance_audit
  - generate_compliance_pdf
  - run_command
  - query_knowledge_base
  - request_approval
---

## Propósito

Skill orquestador que ejecuta una **auditoría bancaria integral** aplicando los
frameworks adecuados según el perfil del banco (A/B/C definidos en el paquete
ASOBAN), consolida hallazgos cross-framework y produce un PDF bilingüe único.

Es la skill de mayor alcance. Se activa cuando el usuario pide "auditoría
completa" / "audit full" / "engagement bancario" o menciona clientes bancarios
paraguayos (BCP, SIB, ASOBAN).

**NO reemplaza** los skills específicos (`pci-dss-audit`, `swift-network-security`,
`core-banking-assessment`, `atm-security`). Este los coordina.

## Prerequisitos (bloqueantes)

Antes de correr cualquier comando:

1. ✅ **Autorización escrita** del banco (email firmado, SOW, o ticket de
   cambio con approval del CISO). Sin esto: **DETENER**.
2. ✅ **NDA firmado** — template disponible en
   `docs/sales/asoban/06_nda_plantilla.md`.
3. ✅ **Cuestionario de alcance completado**
   (`docs/sales/asoban/02_cuestionario_alcance.md`) — indica el perfil A/B/C,
   hosts, frameworks aplicables.
4. ✅ **Credenciales read-only** en `~/.kryon/secrets.env` o provistas por
   CLI, nunca hardcodeadas.
5. ✅ **Ventana de mantenimiento confirmada** si se tocan hosts de producción.

Si falta alguno, detener y pedírselo al usuario **antes** de avanzar.

## Selección de perfil (obligatoria antes de ejecutar)

Si el usuario no lo especifica, preguntá:

| Perfil | Criterio | Frameworks | Controles | Duración |
|---|---|---|---|---|
| Perfil A | Banco pequeño, sin ATMs | BCP PY + CIS OS + PCI-DSS | ~223 | 3-4 semanas |
| Perfil B | Banco mediano, con ATMs | A + Docker + Core Banking + ATMs | ~338 | 5-6 semanas |
| Perfil C | Banco grande, SWIFT | B + SWIFT CSP + Windows Server | ~422 | 8-10 semanas |

Perfil por defecto: **Perfil B** (cubre la mayoría de bancos LATAM de tamaño medio).
Escalar a **Perfil C** si el banco es miembro de SWIFT.

## Flujo estricto (3 fases)

### Fase 1 — Diagnóstico (solo lectura, SIEMPRE primero)

1. Inventario de hosts según cuestionario (Linux / Windows / DB / ATMs).
2. Para cada host Linux usar el framework CIS correspondiente:
   - Ubuntu → `cis-ubuntu-22.04-l1`
   - Debian → `cis-debian-12-l1`
   - RHEL / Rocky / Alma → `cis-rhel-9-l1`
3. Para hosts Windows: usar `transport="winrm"` en el CheckContext y ejecutar
   `cis-windows-server-2022-l1`.
4. Para hosts Docker: `cis-docker-1.6`.
5. Para core bancario (T24/Finacle/Flexcube): `core-banking-hardening`.
6. Para ATMs: `atm-security-bcp-2024` (requiere WinRM).
7. Para marcos regulatorios (aplican al conjunto, no a un host específico):
   `pci-dss-4.0`, `swift-csp-2024`, `bcp-py-res-12-2021`.

Cada ejecución se guarda como JSON separado en
`workspaces/<engagement-id>/compliance/<framework-id>-<host>.json`.

### Fase 2 — Propuesta (NUNCA modificar, SIEMPRE esperar OK)

Después del diagnóstico:

1. Agregar los JSON por framework usando
   `kryon.reporting.multi_framework_pdf.compute_repro_hash(framework_results)`
   para producir el hash maestro de la auditoría.
2. Producir tabla ejecutiva cross-framework (veredictos por framework, CRITICAL
   por framework, riesgo agregado).
3. **Si el usuario pidió remediation** (adicional al diagnóstico):
   - Listar cada FAIL con comando de remediation propuesto.
   - Agrupar por host / framework.
   - Indicar si es destructivo (clasificador de `command_safety`).
   - **Preguntar**: "¿Aplico estas correcciones?"
   - **ESPERAR** respuesta explícita antes de proceder.

### Fase 3 — Reporte consolidado

1. `render_multi_framework_html(framework_results, host="<engagement-label>",
   client_name="<banco>", audit_date=<fecha>)`.
2. Si hay WeasyPrint: convertir a PDF. Si no: dejar HTML.
3. Guardar en `reports/<engagement-id>/auditoria-consolidada.pdf`.
4. Generar también el plan de remediation en XLSX/CSV priorizado.
5. Actualizar la entrada del cliente en el lead tracker (`services/lead_tracker.py`)
   con el engagement_id, fecha, cantidad de findings.

## Reglas críticas (no negociables)

- **Segregación determinística/LLM**: los veredictos PASS/FAIL vienen siempre
  del motor CIS. El LLM solo genera **narrativa**. Si un regulador pregunta
  por un hallazgo, la defensa es la `evidence_command` + `evidence_stdout` +
  `reproducibility_hash`.
- **Ningún comando destructivo sin aprobación explícita** del usuario.
  El clasificador `command_safety.py` bloquea por defecto.
- **Siempre backup antes de modificar**. Usar `cp file file.bak.$(date +%s)`
  en Linux, `Copy-Item` en Windows.
- **Si un control falla**, detener esa cadena y reportar; no asumir el
  siguiente comando funcionará.
- **Datos de cliente**: nunca capturar PAN, PIN, credenciales. Si un comando
  los expondría, **skipear** y marcar N/A con `rationale` que lo explique.
- **Zona horaria y timestamps**: usar UTC en logs, hora local de Paraguay
  (America/Asuncion) en la narrativa para el CISO.

## Integración con otros skills

Este playbook **delega** en skills especializados cuando necesita profundidad:

- Para findings PCI-DSS → referir a `pci-dss-audit` para interpretación detallada.
- Para T24/Finacle → `core-banking-assessment` para análisis de vulnerabilidades
  específicas del core.
- Para SWIFT → `swift-network-security` para la arquitectura A1-A4/B.
- Para ATMs → `atm-security` para physical + NDC/DDC hardening.
- Para hallazgos LLM-sensibles → `safe-modification` antes de cualquier cambio.

## Outputs esperados

Al final de un engagement completo, el workspace debe contener:

```
workspaces/<engagement-id>/
├── scope.json                    # cuestionario + hosts confirmados
├── compliance/
│   ├── cis-ubuntu-22.04-l1-srv01.json
│   ├── cis-debian-12-l1-srv02.json
│   ├── cis-windows-server-2022-l1-dc01.json
│   ├── cis-docker-1.6-srv-docker.json
│   ├── core-banking-hardening-t24.json
│   ├── atm-security-bcp-2024-atm-005.json
│   ├── pci-dss-4.0.json
│   ├── swift-csp-2024.json
│   └── bcp-py-res-12-2021.json
├── reports/
│   ├── auditoria-consolidada.pdf         # PDF bilingüe ES/EN
│   ├── plan-remediation.xlsx             # acciones priorizadas
│   └── presentacion-comite-riesgo.pptx   # 20 slides ejecutivos
├── evidence/
│   └── raw-stdout-<framework>-<host>.txt # reproducible
└── audit-metadata.json                   # hashes, fechas, scope
```

## Ejemplo de interacción (español)

```
Usuario: "necesito hacer una auditoría completa para Banco Plata SA, perfil B"

Kryon (este skill):
  1. "Confirmo: perfil B (banco mediano con ATMs), ~338 controles, 5-6 semanas.
      Antes de empezar necesito:
      - Confirmación: ¿tenés autorización escrita? (sí/no)
      - NDA firmado: ¿referencia del documento?
      - Cuestionario de alcance (doc 02): ¿lo completaste?
      - Hosts en alcance: ¿cuántos Linux, Windows, DB, ATMs?"

Usuario: "Sí a todo. Tengo 8 Linux Ubuntu, 4 Windows, 2 Oracle, 30 ATMs"

Kryon:
  2. "OK. Arranco con Fase 1 — diagnóstico (solo lectura). Esto va a correr
      por varias horas. Te voy reportando avances por host. Empiezo por los
      8 hosts Linux con CIS Ubuntu 22.04 L1."

  [ejecuta run_compliance_audit por host, framework a framework]

  3. "Fase 1 completa. Resumen:
      - 338 controles ejecutados
      - 47 FAIL (8 CRITICAL)
      - 281 PASS, 10 N/A
      - Riesgo agregado: ALTO
      Detalle por framework en tabla adjunta. ¿Querés que genere el PDF
      consolidado o primero revisamos los 8 CRITICAL?"
```

## Notas regulatorias (Paraguay)

- **BCP Resolución 12/2021**: art. 21 (segregación), art. 22 (MFA), art. 23
  (privilegios), art. 24 (DR), art. 25 (logging). Siempre citar articulo.
- **BCP ATM 2024**: arts. 5-12 sobre PCI PTS + anti-skim + TR-31.
- **SIB (Superintendencia de Bancos)**: auditoría anual; este reporte es
  material defendible.
- **SEPRELAD**: no cubierto por este skill (prevención de lavado — requiere
  análisis de transacciones, no de infraestructura).
- **Ley 6534/2020**: datos personales. No capturar, no persistir.
