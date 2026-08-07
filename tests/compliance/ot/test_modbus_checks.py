"""F84.1 — integration tests for the Modbus compliance checks.

Stubs `kryon.tools.ot.modbus_scan.modbus_scan` so we exercise the
verdict logic without a real Modbus host. The actual scanner is tested
in `tests/tools/ot/test_modbus_scan.py`.
"""

from __future__ import annotations

import pytest

from kryon.compliance.checks.base import CheckContext
from kryon.tools.ot.modbus_scan import ModbusScanResult

# ---------- Helpers ----------


def _stub_scan_result(monkeypatch: pytest.MonkeyPatch, result: ModbusScanResult) -> None:
    """Patch BOTH the source module and the check module's import alias.
    Each check did `from kryon.tools.ot.modbus_scan import modbus_scan`,
    so a single setattr on the source isn't enough — the symbol is
    already bound in the check module's namespace."""
    import kryon.compliance.checks.ot.modbus.c_mod_1_1_unauth_read as c11
    import kryon.compliance.checks.ot.modbus.c_mod_1_2_device_identification as c12
    import kryon.tools.ot.modbus_scan as src

    fake = lambda *a, **k: result  # noqa: E731
    monkeypatch.setattr(src, "modbus_scan", fake)
    monkeypatch.setattr(c11, "modbus_scan", fake)
    monkeypatch.setattr(c12, "modbus_scan", fake)


# ---------- MOD-1.1 — anonymous read access ----------


class TestMod11UnauthRead:
    def test_pass_when_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.modbus.c_mod_1_1_unauth_read import CHECK

        _stub_scan_result(
            monkeypatch,
            ModbusScanResult(
                host="10.0.0.5",
                port=502,
                reachable=False,
                unauth_read_coils=False,
                unauth_read_holding=False,
                error="tcp_connect_failed",
            ),
        )
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"
        assert "unreachable" in result.evidence_stdout

    def test_fail_when_coils_read_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.modbus.c_mod_1_1_unauth_read import CHECK

        _stub_scan_result(
            monkeypatch,
            ModbusScanResult(
                host="10.0.0.5",
                port=502,
                reachable=True,
                unauth_read_coils=True,
                unauth_read_holding=False,
                response_unit_ids=(1,),
            ),
        )
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        assert "Read Coils" in result.evidence_stdout
        assert result.evidence_parsed["unauth_read_coils"] is True

    def test_fail_when_both_reads_succeed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.modbus.c_mod_1_1_unauth_read import CHECK

        _stub_scan_result(
            monkeypatch,
            ModbusScanResult(
                host="10.0.0.5",
                port=502,
                reachable=True,
                unauth_read_coils=True,
                unauth_read_holding=True,
                device_identification={"vendor": "Schneider", "product_code": "M340"},
            ),
        )
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        assert "Read Coils" in result.evidence_stdout
        assert "Read Holding Registers" in result.evidence_stdout
        # Device identity should be cited in the FAIL evidence so the
        # auditor can hand the bank a unique fingerprint per finding.
        assert "Schneider" in result.evidence_stdout

    def test_pass_when_reads_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.modbus.c_mod_1_1_unauth_read import CHECK

        _stub_scan_result(
            monkeypatch,
            ModbusScanResult(
                host="10.0.0.5",
                port=502,
                reachable=True,
                unauth_read_coils=False,
                unauth_read_holding=False,
            ),
        )
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"

    def test_severity_is_critical(self) -> None:
        from kryon.compliance.checks.ot.modbus.c_mod_1_1_unauth_read import CHECK

        assert CHECK.severity == "CRITICAL"


# ---------- MOD-1.2 — device identification disclosure ----------


class TestMod12DeviceID:
    def test_pass_when_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.modbus.c_mod_1_2_device_identification import CHECK

        _stub_scan_result(
            monkeypatch,
            ModbusScanResult(
                host="10.0.0.5",
                port=502,
                reachable=False,
                unauth_read_coils=False,
                unauth_read_holding=False,
            ),
        )
        assert CHECK.run(CheckContext(host="10.0.0.5")).verdict == "PASS"

    def test_pass_when_no_identity_returned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Older PLC without MEI 0x0E support — empty identification dict
        is fine; the device kept its mouth shut, that's the desired posture."""
        from kryon.compliance.checks.ot.modbus.c_mod_1_2_device_identification import CHECK

        _stub_scan_result(
            monkeypatch,
            ModbusScanResult(
                host="10.0.0.5",
                port=502,
                reachable=True,
                unauth_read_coils=False,
                unauth_read_holding=False,
                device_identification={},
            ),
        )
        assert CHECK.run(CheckContext(host="10.0.0.5")).verdict == "PASS"

    def test_fail_when_identity_disclosed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.modbus.c_mod_1_2_device_identification import CHECK

        _stub_scan_result(
            monkeypatch,
            ModbusScanResult(
                host="10.0.0.5",
                port=502,
                reachable=True,
                unauth_read_coils=False,
                unauth_read_holding=False,
                device_identification={
                    "vendor": "Schneider Electric",
                    "product_code": "Modicon M340",
                    "revision": "v3.10",
                },
            ),
        )
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        assert "Schneider" in result.evidence_stdout
        assert "M340" in result.evidence_stdout

    def test_severity_is_medium(self) -> None:
        """Device-id disclosure is informational; severity is MEDIUM not
        CRITICAL because the scanner needs network reachability already."""
        from kryon.compliance.checks.ot.modbus.c_mod_1_2_device_identification import CHECK

        assert CHECK.severity == "MEDIUM"


# ---------- Runner integration ----------


def test_runner_registers_modbus_checks() -> None:
    """Pin: both Sprint-1 Modbus checks live in the global registry after
    `_import_all_checks()`. Drift detection — F84 Sprint 2 will ADD
    DNP3 / S7 / IEC104 / MQTT, never remove these."""
    from kryon.compliance.runner import _import_all_checks, registered_checks

    _import_all_checks()
    ids = {c.control_id for c in registered_checks()}
    assert "MOD-1.1" in ids
    assert "MOD-1.2" in ids


def test_modbus_check_metadata_complete() -> None:
    """Each Modbus check exposes the same shape every other compliance
    check does: control_id, title, section, severity, remediation."""
    from kryon.compliance.checks.ot.modbus.c_mod_1_1_unauth_read import CHECK as MOD11
    from kryon.compliance.checks.ot.modbus.c_mod_1_2_device_identification import CHECK as MOD12

    for check in (MOD11, MOD12):
        assert check.control_id.startswith("MOD-")
        assert len(check.control_title) > 10
        assert check.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert len(check.remediation_static) > 30
