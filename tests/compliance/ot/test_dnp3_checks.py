"""F84.2 — integration tests for the DNP3 compliance checks."""

from __future__ import annotations

import pytest

from kryon.compliance.checks.base import CheckContext
from kryon.tools.ot.dnp3_probe import DNP3ProbeResult


def _stub_probe(monkeypatch: pytest.MonkeyPatch, result: DNP3ProbeResult) -> None:
    """Same shadow-aware stub pattern as F84.1 modbus tests."""
    import kryon.tools.ot.dnp3_probe as src
    import kryon.compliance.checks.ot.dnp3.c_dnp3_1_1_unauth_read as c11
    import kryon.compliance.checks.ot.dnp3.c_dnp3_2_1_device_health as c21

    fake = lambda *a, **k: result  # noqa: E731
    monkeypatch.setattr(src, "dnp3_probe", fake)
    monkeypatch.setattr(c11, "dnp3_probe", fake)
    monkeypatch.setattr(c21, "dnp3_probe", fake)


# ---------- DNP3-1.1 ----------


class TestDnp311UnauthRead:
    def test_pass_when_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.dnp3.c_dnp3_1_1_unauth_read import CHECK

        _stub_probe(monkeypatch, DNP3ProbeResult(
            host="10.0.0.5", port=20000, reachable=False,
            responds_to_dnp3=False,
            error="tcp_connect_failed",
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"

    def test_na_when_port_open_but_not_dnp3(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.dnp3.c_dnp3_1_1_unauth_read import CHECK

        _stub_probe(monkeypatch, DNP3ProbeResult(
            host="10.0.0.5", port=20000, reachable=True,
            responds_to_dnp3=False,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "N/A"
        assert "DNP3 framing" in result.evidence_stdout

    def test_fail_when_unauth_read_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.dnp3.c_dnp3_1_1_unauth_read import CHECK

        _stub_probe(monkeypatch, DNP3ProbeResult(
            host="10.0.0.5", port=20000, reachable=True,
            responds_to_dnp3=True,
            outstation_address=4,
            secure_auth_v5_active=False,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        assert "address 4" in result.evidence_stdout
        assert "without SAv5" in result.evidence_stdout

    def test_fail_includes_restart_warning_when_iin_set(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """device_restart bit is critical context — recently rebooted
        outstations may have lost SAv5 session state. Mention in verdict."""
        from kryon.compliance.checks.ot.dnp3.c_dnp3_1_1_unauth_read import CHECK

        _stub_probe(monkeypatch, DNP3ProbeResult(
            host="10.0.0.5", port=20000, reachable=True,
            responds_to_dnp3=True,
            outstation_address=4,
            secure_auth_v5_active=False,
            iin_bits={"device_restart": True},
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert "DEVICE_RESTART" in result.evidence_stdout

    def test_pass_when_sav5_challenges(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.dnp3.c_dnp3_1_1_unauth_read import CHECK

        _stub_probe(monkeypatch, DNP3ProbeResult(
            host="10.0.0.5", port=20000, reachable=True,
            responds_to_dnp3=True,
            outstation_address=4,
            secure_auth_v5_active=True,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"
        assert "SAv5" in result.evidence_stdout

    def test_severity_is_critical(self) -> None:
        from kryon.compliance.checks.ot.dnp3.c_dnp3_1_1_unauth_read import CHECK

        assert CHECK.severity == "CRITICAL"


# ---------- DNP3-2.1 ----------


class TestDnp321DeviceHealth:
    def test_na_when_outstation_unreachable(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.compliance.checks.ot.dnp3.c_dnp3_2_1_device_health import CHECK

        _stub_probe(monkeypatch, DNP3ProbeResult(
            host="10.0.0.5", port=20000, reachable=False,
            responds_to_dnp3=False,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "N/A"

    def test_pass_when_no_trouble_flags(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.compliance.checks.ot.dnp3.c_dnp3_2_1_device_health import CHECK

        _stub_probe(monkeypatch, DNP3ProbeResult(
            host="10.0.0.5", port=20000, reachable=True,
            responds_to_dnp3=True,
            iin_bits={
                "device_restart": False, "device_trouble": False,
                "config_corrupt": False, "buffer_overflow": False,
            },
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"

    def test_fail_when_device_trouble_flag_set(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.compliance.checks.ot.dnp3.c_dnp3_2_1_device_health import CHECK

        _stub_probe(monkeypatch, DNP3ProbeResult(
            host="10.0.0.5", port=20000, reachable=True,
            responds_to_dnp3=True,
            iin_bits={
                "device_restart": False, "device_trouble": True,
                "config_corrupt": False, "buffer_overflow": False,
            },
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        assert "device_trouble" in result.evidence_stdout

    def test_fail_when_multiple_trouble_flags(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.compliance.checks.ot.dnp3.c_dnp3_2_1_device_health import CHECK

        _stub_probe(monkeypatch, DNP3ProbeResult(
            host="10.0.0.5", port=20000, reachable=True,
            responds_to_dnp3=True,
            iin_bits={
                "device_restart": True, "device_trouble": False,
                "config_corrupt": True, "buffer_overflow": False,
            },
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        # Both flags should appear in the evidence so the SOC sees both.
        assert "device_restart" in result.evidence_stdout
        assert "config_corrupt" in result.evidence_stdout
        assert result.evidence_parsed["trouble_flags_set"] == [
            "device_restart", "config_corrupt",
        ]


# ---------- Runner integration ----------


def test_runner_registers_dnp3_checks() -> None:
    from kryon.compliance.runner import _import_all_checks, registered_checks

    _import_all_checks()
    ids = {c.control_id for c in registered_checks()}
    assert "DNP3-1.1" in ids
    assert "DNP3-2.1" in ids


def test_dnp3_checks_use_dnp3_section_prefix() -> None:
    """Section prefix DNP3- is used by reporting/multi_framework_pdf to
    group checks; pin the contract."""
    from kryon.compliance.checks.ot.dnp3.c_dnp3_1_1_unauth_read import CHECK as C11
    from kryon.compliance.checks.ot.dnp3.c_dnp3_2_1_device_health import CHECK as C21

    for check in (C11, C21):
        assert check.section.startswith("DNP3-")
        assert check.control_id.startswith("DNP3-")
