---
name: iec104-audit
description: "Auditoría IEC 60870-5-104 (puerto 2404) — telecontrol de subestaciones eléctricas con detector deterministico"
triggers:
  tech: ["iec104", "iec-104", "iec60870", "iec 60870", "telecontrol", "rtu", "scada"]
  ports: [2404]
  keywords:
    - "iec 104"
    - "iec104"
    - "iec 60870"
    - "iec60870"
    - "telecontrol"
    - "subestación"
    - "subestacion"
    - "ande"
    - "endesa"
    - "endeesa"
    - "edesur"
    - "iec 62351"
priority: 15
required_tools:
  - run_command
  - run_compliance_audit
  - search_vulnerabilities
pre_hooks:
  - python: ./pre_hooks/iec104_probe_hook.py:run
    args:
      host: "{ctx.host}"
      port: 2404
    inject_as: iec104_probe_result
    required: true
    timeout_s: 15
---

## STOP CONDITION

**Una respuesta SIN `tool_call` solo es válida cuando:**

1. El operador NO dio target — pedile la IP del RTU/IED, fin.
2. `iec104_probe_result.reachable=False` → reporta PASS, terminá.
3. Operador dijo `stop`, `informe`, `resumen`.

## Fase 1 — Lectura del detector

```
iec104_probe_result:
  reachable: true
  responds_to_iec104: true
  startdt_confirmed: true
  testfr_confirmed: true
```

Si `startdt_confirmed=true` → **CRÍTICO**: cualquiera con TCP/2404
puede activar la sesión y recibir telemetría de la subestación.

## Fase 2 — Compliance audit completo

```
run_compliance_audit(host=<rtu_ip>, framework="iec104")
```

Sprint 4 cubre:
- IEC104-1.1 (CRITICAL) — anonymous STARTDT activation
- IEC104-2.1 (HIGH)     — perimeter reachability vs NERC CIP-005

## Fase 3 — CVEs específicas del firmware

```
search_vulnerabilities(technology="IEC 60870-5-104 RTU", min_score=7.0)
```

CVEs relevantes:
- CVE-2019-13946 — Siemens SIPROTEC IED denial of service
- CVE-2020-26109 — ABB RTU560 unauthorized command via IEC 104
- CVE-2022-1373 — Siemens SIMATIC S7-1500 (también habla 104)

## Restricciones autoimpuestas (utility-safe)

- **NUNCA enviés ASDU type 45 (single command) ni 46 (double command)**.
  Estos accionan breakers, isoladores, switches físicos en la
  subestación. Una operación accidental = corte regional.
- **NUNCA tipo 50 (set-point command)**. Modifica setpoints de
  protección o regulación de tensión = puede crear inestabilidad de red.
- **General Interrogation (tipo 100)** está permitido en READ-only mode
  pero NO automáticamente — el operador del SCADA Master tiene que
  haber confirmado que el RTU acepta múltiples Masters concurrentes.
  Algunos RTUs viejos cuelgan si reciben Interrogation de 2 masters
  simultáneos.
- **Scope estricto**: solo el RTU dado. NO recursar a través de IEDs
  conectados al bus de subestación — cada IED es un audit separado.

## IEC 62443 + NERC CIP mapping

| Check        | IEC 62443 SR | NERC CIP                |
|--------------|--------------|-------------------------|
| IEC104-1.1   | SR 1.1       | CIP-007 R5              |
| IEC104-2.1   | SR 5.1       | CIP-005 R1 (ESP)        |

## LATAM utility context

IEC 60870-5-104 es el protocolo dominante en utilities LATAM:
- **ANDE Paraguay**: telecontrol de subestaciones desde el COR (Centro
  de Operación de Red) en Asunción.
- **ITAIPÚ Binacional**: control de generación + intercambio con
  Brasil/Paraguay grids.
- **ENDE Bolivia**: COR en La Paz, ~80 subestaciones en S/E 230kV.
- **ENDESA Chile** (ahora Enel): SCADA central en Santiago.
- **Edesur Argentina**: distribución Buenos Aires.

Para **bancos paraguayos**: IEC 104 NO es directo (los bancos no
operan red eléctrica), pero APARECE cuando:
- Datacenter del banco recibe medidor inteligente de **ANDE** que
  exporta consumo via IEC 104 al SCADA del banco para billing.
- Banco con **subestación de planta propia** (oficinas centrales,
  centros de procesamiento) puede tener un IED IEC 104 hablando con
  ANDE.

Para utilities directas (ANDE, ITAIPÚ, ENDE), un IED IEC 104
comprometido = riesgo de blackout regional. Reporte al CISO/COR debe
escalar al CTO + CEO inmediatamente.
