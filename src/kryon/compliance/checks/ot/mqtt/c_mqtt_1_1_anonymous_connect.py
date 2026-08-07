"""F84.5 — MQTT check 1.1: Anonymous CONNECT accepted.

Mosquitto / HiveMQ / EMQX / RabbitMQ-MQTT all default to allowing
anonymous connections unless the operator explicitly disables it.
For an industrial broker on the corporate network, that's a direct
violation of IEC 62443 SR 1.1 — every connecting party should be
identified.

Verdict:
  FAIL — broker accepted CONNECT without username/password
  PASS — broker rejected (rc=4 bad creds, rc=5 not authorized,
         or any non-zero rc) OR port unreachable
  N/A  — port open but didn't return a valid CONNACK (other service)
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check
from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit


class _Mqtt_11Check:
    control_id = "MQTT-1.1"
    control_title = "MQTT broker anonymous CONNECT (IEC 62443 SR 1.1)"
    section = "MQTT-1"
    severity = "CRITICAL"
    remediation_static = (
        "Disable anonymous in mosquitto.conf: set `allow_anonymous false` "
        "and configure a `password_file` with hashed credentials per "
        "client. For HiveMQ, set authentication.type=username-password "
        "and load an extension. For RabbitMQ MQTT plugin, configure "
        "rabbitmq.conf with `mqtt.default_user` removed and TLS client "
        "certs required. After re-enabling auth, audit subscribers — "
        "device gateways may need new credentials provisioned."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        result = mqtt_industrial_audit(ctx.host, port=1883)
        elapsed_ms = int((time.time() - t0) * 1000)

        if not result.reachable:
            verdict = "PASS"
            stdout = f"port 1883 unreachable on {ctx.host}: {result.error}"
        elif result.connack_return_code is None:
            verdict = "N/A"
            stdout = (
                f"Port 1883 open on {ctx.host} but no valid CONNACK in the "
                f"response. Could be a different service or non-MQTT "
                f"variant (custom binary protocol)."
            )
        elif result.anonymous_connect_accepted:
            verdict = "FAIL"
            stdout = f"MQTT broker at {ctx.host}:1883 accepted anonymous CONNECT (return_code=0)."
            if result.broker_banner:
                stdout += f" Broker banner: {result.broker_banner!r}."
        else:
            verdict = "PASS"
            stdout = (
                f"MQTT broker at {ctx.host}:1883 rejected anonymous "
                f"CONNECT with return_code={result.connack_return_code}."
            )

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="mqtt_industrial_audit(host, port=1883)",
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed={
                "reachable": result.reachable,
                "connack_return_code": result.connack_return_code,
                "anonymous_connect_accepted": result.anonymous_connect_accepted,
                "broker_banner": result.broker_banner,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=elapsed_ms,
            host=ctx.host,
            run_id="",
        )


CHECK = _Mqtt_11Check()
register_check(CHECK)
