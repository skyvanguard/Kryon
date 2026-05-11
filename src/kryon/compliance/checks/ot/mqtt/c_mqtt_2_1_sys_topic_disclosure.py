"""F84.5 — MQTT check 2.1: $SYS topic readable without auth.

The `$SYS/#` namespace exposes broker telemetry: version, build,
uptime, connected clients, messages-per-second, subscriber counts,
publish rates by topic. For a defender this is operational gold; for
an attacker it's a pre-attack inventory.

Check fires when both:
  (a) anonymous CONNECT was accepted (MQTT-1.1 prerequisite)
  (b) SUBSCRIBE to `$SYS/#` returned data within timeout

Verdict:
  FAIL — $SYS PUBLISHes received
  PASS — broker rejected the SUBSCRIBE OR returned nothing
  N/A  — anonymous CONNECT itself was rejected (MQTT-1.1 covered it)
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check
from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit


class _Mqtt_21Check:
    control_id = "MQTT-2.1"
    control_title = "MQTT broker $SYS topic disclosure"
    section = "MQTT-2"
    severity = "HIGH"
    remediation_static = (
        "ACL the $SYS/# namespace to admin clients only. Mosquitto: add "
        "an ACL file with `pattern read $SYS/#` reserved to a specific "
        "username, deny `$SYS/#` for everyone else. HiveMQ: configure a "
        "topic-permissions extension. Even with auth on, $SYS leaks "
        "internal state — treat it as sensitive."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        result = mqtt_industrial_audit(ctx.host, port=1883)
        elapsed_ms = int((time.time() - t0) * 1000)

        if not result.anonymous_connect_accepted:
            verdict = "N/A"
            stdout = (
                f"Cannot evaluate $SYS disclosure on {ctx.host}: anonymous "
                f"CONNECT was not accepted (MQTT-1.1 covers that finding)."
            )
        elif result.sys_topic_readable:
            verdict = "FAIL"
            stdout = f"MQTT broker at {ctx.host}:1883 disclosed $SYS topic data to anonymous SUBSCRIBE."
            if result.broker_banner:
                stdout += f" Sample: {result.broker_banner!r}."
        else:
            verdict = "PASS"
            stdout = (
                f"MQTT broker at {ctx.host}:1883 accepted anonymous "
                f"CONNECT but did not return $SYS data within the "
                f"timeout — likely ACL'd."
            )

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="mqtt_industrial_audit(host).sys_topic_readable",
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed={
                "anonymous_connect_accepted": result.anonymous_connect_accepted,
                "sys_topic_readable": result.sys_topic_readable,
                "broker_banner": result.broker_banner,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=elapsed_ms,
            host=ctx.host,
            run_id="",
        )


CHECK = _Mqtt_21Check()
register_check(CHECK)
