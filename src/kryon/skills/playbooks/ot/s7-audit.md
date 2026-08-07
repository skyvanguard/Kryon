---
name: s7-audit
description: "Auditoría Siemens S7Comm (puerto 102) — IEC 62443 + Siemens ProductCERT con detector deterministico"
triggers:
  tech: ["siemens", "s7", "s7comm", "tia-portal", "step7", "wincc", "plc"]
  ports: [102]
  keywords:
    - "siemens"
    - "s7"
    - "s7-300"
    - "s7-400"
    - "s7-1200"
    - "s7-1500"
    - "tia portal"
    - "step7"
    - "step 7"
    - "wincc"
    - "simatic"
priority: 15
required_tools:
  - run_command
  - run_compliance_audit
pre_hooks:
  - python: ./pre_hooks/s7_enum_hook.py:run
    args:
      host: "{ctx.host}"
      port: 102
    inject_as: s7_enum_result
    required: false
    timeout_s: 20
---

## STOP CONDITION

**Una respuesta SIN `tool_call` solo es válida cuando:**

1. El operador NO dio target — pedile la IP del PLC, fin.
2. `s7_enum_result.reachable=False` y `cotp_connected=False` → reporta
   PASS y termina.
3. Operador dijo `stop`, `informe`, `resumen`.

## Fase 1 — Lectura del detector

```
s7_enum_result:
  reachable: true
  cotp_connected: true
  s7_session_established: true
  module_identification:
    order_code: "6ES7 315-2EH14-0AB0"
    firmware: "V 3.2.6"
  plc_firmware_version: "V 3.2.6"
```

`s7_session_established=true` sin auth = **CRÍTICO**.
`order_code` + `firmware` permiten lookup CVE específico al modelo.

## Fase 2 — Compliance audit completo

```
run_compliance_audit(host=<plc_ip>, framework="s7")
```

Sprint 3 cubre:
- S7-1.1 (CRITICAL) — anonymous S7 session establishment
- S7-2.1 (HIGH)     — firmware currency vs known CVE bands

## Fase 3 — CVE search por order code + firmware

```
cve_intel(query="<order_code>")
```

CVEs frecuentes por familia:
- **S7-1500**: CVE-2018-13815 (DoS), CVE-2019-10923 (auth bypass),
  CVE-2020-15782 (memory protection bypass)
- **S7-1200**: CVE-2020-15782 (mem-protect bypass), CVE-2021-37200
- **S7-300/400**: CVE-2016-9159 (memory disclosure), CVE-2017-2682
  (RCE via S7Comm), CVE-2018-16556 (DoS)

Siemens Security Advisories: https://cert-portal.siemens.com/

## Restricciones autoimpuestas (banking + plant-safe)

- **NUNCA llames a STOP/RUN/MRES vía S7Comm**. Function codes
  `0x29` (PI Service - operating mode) pueden detener el PLC físicamente
  → caída de proceso. Audit baseline solo lee SZL.
- **NUNCA escribas en datablocks** vía función Write Var (0x05). Eso
  modifica el comportamiento del proceso controlado.
- **No corras `nmap --script s7-info` durante operación**. S7-300/400
  viejos pueden bloquear comunicación cuando reciben handshakes
  malformados (CVE-2016-9159 era exactamente eso).
- **Scope estricto**: solo el PLC dado. Si tiene tarjetas comunicación
  CP (CP-343, CP-443), NO las audites por separado sin autorización —
  el escaneo sequential a múltiples interfaces puede confundir el
  proceso de gateway interno.

## IEC 62443 mapping

| Check    | FR  | SR     | Description                            |
|----------|-----|--------|----------------------------------------|
| S7-1.1   | FR1 | SR 1.1 | Identification & Authentication        |
| S7-2.1   | FR3 | SR 3.4 | Software & Information Integrity       |

## LATAM banking + industrial context

Siemens domina el mercado de PLC en LATAM. En bancos paraguayos
aparecen S7-1200/1500 en:
- **HVAC del datacenter**: control de chillers, AHUs, free cooling
- **Generadores diesel de respaldo**: ATS controllers, sincronización
- **Sistemas de incendios**: panel de detección + actuación FM-200
- **Control de acceso físico**: torniquetes, puertas de bóveda con
  timers programados

Una falla de auth S7Comm en un PLC del datacenter = potencial
disrupción del cooling = shutdown forzoso de servidores. El reporte
al CISO debe enfatizar el blast radius físico, no solo el data
exposure.
