---
name: dnp3-audit
description: "Auditoría DNP3 (puerto 20000) para utilities/power grid — IEEE 1815 + NERC CIP-005/007 con detector deterministico"
triggers:
  tech: ["dnp3", "scada", "rtu", "ied", "substation", "power-grid"]
  ports: [20000]
  keywords:
    - "dnp3"
    - "ieee 1815"
    - "rtu"
    - "ied"
    - "substation"
    - "subestación"
    - "subestacion"
    - "power grid"
    - "red eléctrica"
    - "red electrica"
    - "ande"
    - "itaipu"
    - "endesa"
    - "edesur"
    - "nerc cip"
priority: 15
required_tools:
  - run_command
  - run_compliance_audit
pre_hooks:
  - python: ./pre_hooks/dnp3_probe_hook.py:run
    args:
      host: "{ctx.host}"
      port: 20000
    inject_as: dnp3_probe_result
    required: false
    timeout_s: 15
---

## STOP CONDITION

**Una respuesta SIN `tool_call` solo es válida cuando:**

1. El operador NO dio target — pedile la IP del RTU/IED, fin.
2. El detector inyectó `reachable=False` Y `responds_to_dnp3=False` →
   reporta PASS, terminá.
3. El operador dijo `stop`, `informe`, `resumen`.

## Fase 1 — Lectura del detector

El pre_hook `dnp3_probe_result` ya está en contexto:

```
dnp3_probe_result:
  reachable: true
  responds_to_dnp3: true
  outstation_address: 4
  secure_auth_v5_active: false
  iin_bits:
    device_restart: false
    device_trouble: false
    config_corrupt: false
```

`secure_auth_v5_active=false` + `responds_to_dnp3=true` = **CRÍTICO**.

## Fase 2 — Compliance audit completo

```
run_compliance_audit(host=<rtu_ip>, framework="dnp3")
```

Sprint 2 cubre:
- DNP3-1.1 (CRITICAL) — unauth read access
- DNP3-2.1 (MEDIUM)   — outstation health flags

## Fase 3 — CVEs específicas del firmware

```
cve_intel(query="DNP3 RTU")
```

CVEs comunes:
- CVE-2013-2823 — Schneider RTU DoS via crafted DNP3 frame
- CVE-2014-0660 — GE D60 / SR60 RTU memory corruption
- CVE-2018-7820 — Schweitzer SEL RTU bypass
- CVE-2021-22713 — ABB RTU560 unauthorized command execution

## Restricciones autoimpuestas (banking + utility-safe)

- **NUNCA function code 0x05 (Direct Operate) ni 0x06 (Select Before
  Operate)**. Estos mandan al RTU a actuar sobre breakers, switches,
  isolators físicos. Una operación equivocada en una subestación = corte
  regional. El audit baseline es READ-ONLY.
- **No corras nmap NSE script `dnp3-info`** durante horario de operación.
  Algunos RTUs viejos colapsan con scan agresivo.
- **Scope estricto**: solo el RTU especificado. DNP3 hostea Master ↔
  Outstation; no audites el Master sin contrato separado del SCADA
  vendor.

## IEC 62443 + NERC CIP mapping

| Check     | IEC 62443 SR | NERC CIP    |
|-----------|--------------|-------------|
| DNP3-1.1  | SR 1.1       | CIP-005 R1, CIP-007 R5 |
| DNP3-2.1  | SR 6.1       | CIP-008 R1  |

## LATAM utility context

DNP3 en bancos paraguayos no es directo (los bancos no operan red
eléctrica), pero SÍ aparece cuando:
- El datacenter tiene un **transfer switch automático** entre red
  pública y generador — algunos modelos hablan DNP3 al UPS/genset.
- **Subestaciones de planta** en oficinas centrales con contratos
  directos con ANDE — el medidor inteligente puede exponer DNP3.

Para utilities reales (ANDE, ITAIPU, ENDE, ENDESA, Edesur), DNP3 es el
core protocol. Aquí el audit es de máxima criticidad — un IED
comprometido = blackout.
