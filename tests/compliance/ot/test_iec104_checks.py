"""F84.4 — integration tests for IEC 60870-5-104 compliance checks."""

from __future__ import annotations

import pytest

from kryon.compliance.checks.base import CheckContext
from kryon.tools.ot.iec104_probe import IEC104ProbeResult


def _stub_probe(monkeypatch: pytest.MonkeyPatch, result: IEC104ProbeResult) -> None:
    """Shadow-aware patch — both checks bind `iec104_probe` at import."""
    import kryon.compliance.checks.ot.iec104.c_iec104_1_1_anonymous_session as c11
    import kryon.compliance.checks.ot.iec104.c_iec104_2_1_perimeter_exposure as c21
    import kryon.tools.ot.iec104_probe as src

    fake = lambda *a, **k: result  # noqa: E731
    monkeypatch.setattr(src, "iec104_probe", fake)
    monkeypatch.setattr(c11, "iec104_probe", fake)
    monkeypatch.setattr(c21, "iec104_probe", fake)


# ---------- IEC104-1.1 anonymous STARTDT ----------


class TestIec104_11AnonStart:
    def test_pass_when_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.iec104.c_iec104_1_1_anonymous_session import CHECK

        _stub_probe(monkeypatch, IEC104ProbeResult(
            host="10.0.0.5", port=2404, reachable=False,
            responds_to_iec104=False, startdt_confirmed=False,
            testfr_confirmed=False, error="tcp_connect_failed",
        ))
        assert CHECK.run(CheckContext(host="10.0.0.5")).verdict == "PASS"

    def test_fail_when_startdt_confirmed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.iec104.c_iec104_1_1_anonymous_session import CHECK

        _stub_probe(monkeypatch, IEC104ProbeResult(
            host="10.0.0.5", port=2404, reachable=True,
            responds_to_iec104=True, startdt_confirmed=True,
            testfr_confirmed=True,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        assert "STARTDT" in result.evidence_stdout
        assert "TESTFR" in result.evidence_stdout  # liveness mentioned

    def test_pass_when_startdt_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.iec104.c_iec104_1_1_anonymous_session import CHECK

        _stub_probe(monkeypatch, IEC104ProbeResult(
            host="10.0.0.5", port=2404, reachable=True,
            responds_to_iec104=True, startdt_confirmed=False,
            testfr_confirmed=False,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"
        assert "rejected" in result.evidence_stdout

    def test_na_when_no_iec104_framing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.iec104.c_iec104_1_1_anonymous_session import CHECK

        _stub_probe(monkeypatch, IEC104ProbeResult(
            host="10.0.0.5", port=2404, reachable=True,
            responds_to_iec104=False, startdt_confirmed=False,
            testfr_confirmed=False,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "N/A"

    def test_severity_is_critical(self) -> None:
        from kryon.compliance.checks.ot.iec104.c_iec104_1_1_anonymous_session import CHECK

        assert CHECK.severity == "CRITICAL"


# ---------- IEC104-2.1 perimeter exposure ----------


class TestIec104_21Perimeter:
    def test_pass_when_port_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.iec104.c_iec104_2_1_perimeter_exposure import CHECK

        _stub_probe(monkeypatch, IEC104ProbeResult(
            host="10.0.0.5", port=2404, reachable=False,
            responds_to_iec104=False, startdt_confirmed=False,
            testfr_confirmed=False, error="tcp_connect_failed",
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"
        assert "perimeter firewall" in result.evidence_stdout

    def test_fail_when_port_reachable_regardless_of_auth(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Even if STARTDT is rejected, port being open from the audit
        source means the perimeter is permeable. NERC CIP-005 R1 cares
        about layer-3 boundary, not just layer-7 auth."""
        from kryon.compliance.checks.ot.iec104.c_iec104_2_1_perimeter_exposure import CHECK

        _stub_probe(monkeypatch, IEC104ProbeResult(
            host="10.0.0.5", port=2404, reachable=True,
            responds_to_iec104=True, startdt_confirmed=False,
            testfr_confirmed=False,
        ))
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        assert "OPEN" in result.evidence_stdout
        assert "NERC CIP-005" in result.evidence_stdout


# ---------- Runner registration ----------


def test_runner_registers_iec104_checks() -> None:
    from kryon.compliance.runner import _import_all_checks, registered_checks

    _import_all_checks()
    ids = {c.control_id for c in registered_checks()}
    assert "IEC104-1.1" in ids
    assert "IEC104-2.1" in ids
