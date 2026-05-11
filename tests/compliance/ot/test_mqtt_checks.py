"""F84.5 — integration tests for MQTT industrial broker compliance checks."""

from __future__ import annotations

import pytest

from kryon.compliance.checks.base import CheckContext
from kryon.tools.ot.mqtt_industrial_audit import MqttProbeResult


def _stub_audit(monkeypatch: pytest.MonkeyPatch, result: MqttProbeResult) -> None:
    import kryon.compliance.checks.ot.mqtt.c_mqtt_1_1_anonymous_connect as c11
    import kryon.compliance.checks.ot.mqtt.c_mqtt_2_1_sys_topic_disclosure as c21
    import kryon.tools.ot.mqtt_industrial_audit as src

    fake = lambda *a, **k: result  # noqa: E731
    monkeypatch.setattr(src, "mqtt_industrial_audit", fake)
    monkeypatch.setattr(c11, "mqtt_industrial_audit", fake)
    monkeypatch.setattr(c21, "mqtt_industrial_audit", fake)


# ---------- MQTT-1.1 anonymous CONNECT ----------


class TestMqtt_11AnonConnect:
    def test_pass_when_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.mqtt.c_mqtt_1_1_anonymous_connect import CHECK

        _stub_audit(monkeypatch, MqttProbeResult(
            host="10.0.0.5", port=1883, reachable=False,
            anonymous_connect_accepted=False, sys_topic_readable=False,
            error="tcp_connect_failed",
        ))
        assert CHECK.run(CheckContext(host="10.0.0.5")).verdict == "PASS"

    def test_fail_when_anonymous_accepted(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.compliance.checks.ot.mqtt.c_mqtt_1_1_anonymous_connect import CHECK

        _stub_audit(monkeypatch, MqttProbeResult(
            host="10.0.0.5", port=1883, reachable=True,
            anonymous_connect_accepted=True, sys_topic_readable=True,
            broker_banner="mosquitto version 2.0.18",
            connack_return_code=0,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        assert "mosquitto" in result.evidence_stdout

    def test_pass_when_rejected_with_rc5(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """rc=5 = not authorized — broker enforces auth, that's the
        desired posture, not a finding."""
        from kryon.compliance.checks.ot.mqtt.c_mqtt_1_1_anonymous_connect import CHECK

        _stub_audit(monkeypatch, MqttProbeResult(
            host="10.0.0.5", port=1883, reachable=True,
            anonymous_connect_accepted=False, sys_topic_readable=False,
            connack_return_code=5,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"
        assert "return_code=5" in result.evidence_stdout

    def test_na_when_no_connack(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Port open but no CONNACK — different protocol on the port."""
        from kryon.compliance.checks.ot.mqtt.c_mqtt_1_1_anonymous_connect import CHECK

        _stub_audit(monkeypatch, MqttProbeResult(
            host="10.0.0.5", port=1883, reachable=True,
            anonymous_connect_accepted=False, sys_topic_readable=False,
            connack_return_code=None,
        ))
        assert CHECK.run(CheckContext(host="10.0.0.5")).verdict == "N/A"

    def test_severity_is_critical(self) -> None:
        from kryon.compliance.checks.ot.mqtt.c_mqtt_1_1_anonymous_connect import CHECK

        assert CHECK.severity == "CRITICAL"


# ---------- MQTT-2.1 $SYS topic disclosure ----------


class TestMqtt_21SysDisclosure:
    def test_na_when_anon_connect_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If MQTT-1.1 already covers the auth gap, $SYS check is N/A —
        we never even subscribed."""
        from kryon.compliance.checks.ot.mqtt.c_mqtt_2_1_sys_topic_disclosure import CHECK

        _stub_audit(monkeypatch, MqttProbeResult(
            host="10.0.0.5", port=1883, reachable=True,
            anonymous_connect_accepted=False, sys_topic_readable=False,
            connack_return_code=5,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "N/A"
        assert "MQTT-1.1" in result.evidence_stdout

    def test_fail_when_sys_topic_returned_data(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.compliance.checks.ot.mqtt.c_mqtt_2_1_sys_topic_disclosure import CHECK

        _stub_audit(monkeypatch, MqttProbeResult(
            host="10.0.0.5", port=1883, reachable=True,
            anonymous_connect_accepted=True, sys_topic_readable=True,
            broker_banner="mosquitto version 2.0.18",
            connack_return_code=0,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        assert "mosquitto" in result.evidence_stdout

    def test_pass_when_anon_accepted_but_sys_acld(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Operator left anonymous CONNECT on but ACL'd $SYS — the
        defense-in-depth pattern works for this check."""
        from kryon.compliance.checks.ot.mqtt.c_mqtt_2_1_sys_topic_disclosure import CHECK

        _stub_audit(monkeypatch, MqttProbeResult(
            host="10.0.0.5", port=1883, reachable=True,
            anonymous_connect_accepted=True, sys_topic_readable=False,
            connack_return_code=0,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"


# ---------- Runner registration ----------


def test_runner_registers_mqtt_checks() -> None:
    from kryon.compliance.runner import _import_all_checks, registered_checks

    _import_all_checks()
    ids = {c.control_id for c in registered_checks()}
    assert "MQTT-1.1" in ids
    assert "MQTT-2.1" in ids


def test_f84_complete_5_protocols_10_checks() -> None:
    """F84 closure pin: all 5 OT protocols (Modbus, DNP3, S7, IEC104,
    MQTT) are registered with 2 checks each = 10 total. If a future
    refactor accidentally drops one, this test catches it."""
    from kryon.compliance.runner import _import_all_checks, registered_checks

    _import_all_checks()
    ids = {c.control_id for c in registered_checks()}

    expected_per_protocol = {
        "MOD-": ["MOD-1.1", "MOD-1.2"],
        "DNP3-": ["DNP3-1.1", "DNP3-2.1"],
        "S7-": ["S7-1.1", "S7-2.1"],
        "IEC104-": ["IEC104-1.1", "IEC104-2.1"],
        "MQTT-": ["MQTT-1.1", "MQTT-2.1"],
    }
    for prefix, expected in expected_per_protocol.items():
        for check_id in expected:
            assert check_id in ids, (
                f"F84 protocol {prefix!r} missing check {check_id!r}"
            )

    ot_check_count = sum(
        1 for cid in ids
        if any(cid.startswith(p) for p in expected_per_protocol)
    )
    assert ot_check_count == 10, (
        f"F84 should have exactly 10 OT checks, found {ot_check_count}"
    )
