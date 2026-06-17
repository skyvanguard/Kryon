---
name: modbus-audit
description: "Auditoría Modbus/TCP (puerto 502) — IEC 62443 SR 1.1 + NERC CIP-005 con detector deterministico"
triggers:
  tech: ["modbus", "scada", "plc", "ot", "ics", "industrial"]
  ports: [502]
  keywords:
    - "modbus"
    - "scada"
    - "plc"
    - "ot security"
    - "ics security"
    - "industrial control"
    - "control industrial"
    - "auditoría ot"
    - "auditoria ot"
    - "iec 62443"
    - "nerc cip"
priority: 15
required_tools:
  - run_command
  - run_compliance_audit
pre_hooks:
  - python: ./pre_hooks/modbus_scan_hook.py:run
    args:
      host: "{ctx.host}"
      port: 502
    inject_as: modbus_scan_result
    required: false
    timeout_s: 15
---

## STOP CONDITION

**Una respuesta SIN `tool_call` solo es válida cuando:**

1. El operador NO dio target. Mensaje de 1 línea pidiendo IP/host del PLC, fin.
2. El detector pre-hook `modbus_scan_result` ya fue inyectado al contexto Y
   reportó `reachable=False`. Caso PASS — el target no expone Modbus, narrá
   eso al usuario y terminá.
3. El operador dijo `stop`, `informe`, o `resumen`.

**En cualquier otro caso, la próxima acción es un tool_call.** Modbus
auditing tiene 3 fases tras el detector pre-hook; no termines en fase 1
con un PLAN textual.

## Fase 1 — Lectura del detector deterministico

El pre_hook ya corrió. En el contexto encontrás:

```
modbus_scan_result:
  reachable: true
  unauth_read_coils: true
  unauth_read_holding: true
  device_identification:
    vendor: "Schneider Electric"
    product_code: "Modicon M340"
    revision: "v3.10"
```

Si `reachable=False` → reporta PASS e intenta otro vector (¿el cliente
tiene otros PLCs en el segmento? `nmap -p 502 <CIDR>` para descubrirlos).

Si `reachable=True` y `has_unauth_exposure=True` (cualquiera de los reads
funcionó) → **CRÍTICO**. Avanzá a Fase 2.

## Fase 2 — Compliance audit completo

```
run_compliance_audit(host=<plc_ip>, framework="modbus")
```

Esto dispara todos los checks `MOD-*` registrados (Sprint 1: 2 checks;
Sprint 2-5 traerán DNP3/S7/IEC104/MQTT). El verdict es la verdad
auditable — el cliente bancario lo puede llevar a su comité de riesgo
sin filtros del LLM.

## Fase 3 — Búsqueda de CVEs específicas del firmware

Con `device_identification.vendor` + `product_code` + `revision`:

```
search_vulnerabilities(
    technology="<vendor> <product_code>",
    min_score=7.0,
)
```

CVEs comunes en Modbus PLCs:
- CVE-2018-7522 — Schneider M340 buffer overflow
- CVE-2019-6829 — Allen-Bradley CompactLogix unauth modify
- CVE-2021-22779 — Schneider Modicon improper auth (no fix; segregar)
- CVE-2022-1373 — Siemens SIMATIC S7-1500 web RCE (también Modbus)

## Restricciones autoimpuestas (banking-safe)

- **`attempt_write=True` requiere autorización ESCRITA explícita** del
  cliente. Una escritura accidental a un coil que controla un compresor,
  válvula, o relé puede dañar equipo físico. NUNCA lo activamos por
  default; el `modbus_scan_hook` lo deja en False.
- **No corras nmap script `modbus-discover`** durante el horario de
  producción del PLC. Los PLCs viejos pueden colgarse con un scan
  agresivo. Coordiná con el operador del proceso.
- **Scope estricto**: solo el host especificado. Modbus pivotea a través
  de gateways serie (Modbus RTU detrás de un Modbus/TCP gateway) — eso
  es DOS PASOS más adentro de la red, NO lo audites sin contrato
  separado.

## IEC 62443 mapping

Cada check Modbus mapea a Foundational Requirements (FR) y Security
Requirements (SR):

| Check    | FR | SR      | Title                                  |
|----------|----|---------|----------------------------------------|
| MOD-1.1  | FR1 | SR 1.1 | Identification & Authentication        |
| MOD-1.2  | FR1 | SR 1.5 | Authenticator Management               |

Sprint 2-5 cubrirán FR2 (use control), FR3 (system integrity), FR4
(data confidentiality), FR5 (restricted data flow), FR6 (timely
response to events), FR7 (resource availability).

## Banking context

PLCs Modbus son cada vez más comunes en bancos paraguayos para:
- HVAC del datacenter (precision cooling)
- Generadores de respaldo (sincronización de fase con la red)
- Control de acceso físico (torniquetes, bóvedas con timers)
- Sistemas de detección de incendios (FM-200 release)

Una falla de auth Modbus en estos sistemas es CRÍTICA por el potential
de impacto físico, no solo por confidencialidad. El reporte al CISO
debe enfatizar el vector físico cuando el PLC controla equipo de
seguridad.
