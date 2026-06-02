---
name: mqtt-industrial-audit
description: "Auditoría MQTT broker industrial (puerto 1883/8883) — Mosquitto/HiveMQ/EMQX con detector deterministico"
triggers:
  tech: ["mqtt", "mosquitto", "hivemq", "emqx", "iiot", "iot"]
  ports: [1883, 8883]
  keywords:
    - "mqtt"
    - "mosquitto"
    - "hivemq"
    - "emqx"
    - "rabbitmq mqtt"
    - "iiot"
    - "scada broker"
    - "broker industrial"
priority: 15
required_tools:
  - run_command
  - run_compliance_audit
pre_hooks:
  - python: ./pre_hooks/mqtt_audit_hook.py:run
    args:
      host: "{ctx.host}"
      port: 1883
    inject_as: mqtt_audit_result
    required: true
    timeout_s: 10
---

## STOP CONDITION

**Una respuesta SIN `tool_call` solo es válida cuando:**

1. El operador NO dio target — pedile la IP del broker, fin.
2. `mqtt_audit_result.reachable=False` → reporta PASS, terminá.
3. Operador dijo `stop`, `informe`, `resumen`.

## Fase 1 — Lectura del detector

```
mqtt_audit_result:
  reachable: true
  anonymous_connect_accepted: true
  sys_topic_readable: true
  broker_banner: "mosquitto version 2.0.18"
  connack_return_code: 0
```

`anonymous_connect_accepted=true` = **CRÍTICO**.
`sys_topic_readable=true` = **HIGH** (broker info leak).

## Fase 2 — Compliance audit completo

```
run_compliance_audit(host=<broker_ip>, framework="mqtt")
```

Sprint 5 cubre:
- MQTT-1.1 (CRITICAL) — anonymous CONNECT
- MQTT-2.1 (HIGH)     — $SYS/# disclosure

## Fase 3 — Manual follow-ups (NO automatizar)

Estas son cosas que el operador debería ejecutar **manualmente** con
autorización del cliente — automatizarlas en el playbook arriesga
flooding del broker en producción:

1. **Wildcard subscription `#`** — enumera TODOS los topics:
   `mosquitto_sub -h <broker> -t '#' -W 5 -v`
   Si hay topics como `devices/+/cmd` o `actuators/relay/+/set`,
   son canales de control directo a equipo físico.

2. **Test PUBLISH en topic encontrado** — solo con autorización
   ESCRITA del cliente: `mosquitto_pub -h <broker> -t 'test/probe'
   -m 'kryon-audit'`. Si llega = puedes inyectar mensajes.

3. **TLS check en puerto 8883**:
   `openssl s_client -connect <broker>:8883 -tls1_2`
   ¿Cert válido? ¿CA confiable? ¿Client cert requerido?

## Fase 4 — CVEs específicas del broker

```
search_vulnerabilities(technology="mosquitto 2.0.18", min_score=7.0)
```

CVEs frecuentes:
- **Mosquitto**: CVE-2023-28366 (memory disclosure), CVE-2023-3592 (DoS)
- **HiveMQ**: CVE-2023-37468 (auth bypass before 4.10.0)
- **EMQX**: CVE-2023-26497 (cluster RPC unauth)
- **RabbitMQ MQTT**: CVE-2023-46118 (DoS via large payload)

## Restricciones autoimpuestas (broker-safe)

- **NO PUBLISH en producción sin autorización ESCRITA**. Un mensaje
  inyectado en `actuators/relay/SETPOINT` puede arrancar / parar
  equipo físico real.
- **NO uses `#` wildcard subscription en producción** sin warning al
  operador. En brokers con miles de mensajes/segundo, eso flooded el
  audit container y puede causar OOM.
- **Scope estricto**: solo el broker dado. Si el broker es bridge a
  otros (cluster), NO audites los upstream sin contrato separado.

## IEC 62443 + OWASP IoT mapping

| Check     | IEC 62443 SR | OWASP IoT Top 10              |
|-----------|--------------|-------------------------------|
| MQTT-1.1  | SR 1.1       | I1 (Weak passwords)           |
| MQTT-2.1  | SR 5.1       | I3 (Insecure interfaces)      |

## LATAM banking + IIoT context

MQTT brokers en bancos paraguayos aparecen en:
- **Sensores de datacenter**: temperatura, humedad, current draw por
  rack, leakage detection. Brokers Mosquitto en VMs internas.
- **Generadores diesel**: telemetría de presión de aceite, RPM, voltaje
  de salida. Algunos models exportan vía MQTT al SCADA del banco.
- **Sistemas de cámaras IP**: las cámaras modernas pushean events
  (motion detected, tampering) a un broker central.
- **POS centralizado**: algunos integradores exportan eventos vía MQTT
  al SOC del banco.

Una broker MQTT comprometido en cualquiera de esos contextos =
visibilidad total del operación interna del banco. Reporte al CISO
debe enfatizar la lateralización: desde el broker, el atacante puede
mapear toda la infra connected (IoT + OT + PoS).
