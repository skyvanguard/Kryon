"""F84.3 — integration tests for S7Comm compliance checks."""

from __future__ import annotations

import pytest

from kryon.compliance.checks.base import CheckContext
from kryon.tools.ot.s7_enum import S7EnumResult


def _stub_enum(monkeypatch: pytest.MonkeyPatch, result: S7EnumResult) -> None:
    """Shadow-aware monkey-patch shared by both S7 checks."""
    import kryon.compliance.checks.ot.s7.c_s7_1_1_anonymous_session as c11
    import kryon.compliance.checks.ot.s7.c_s7_2_1_firmware_currency as c21
    import kryon.tools.ot.s7_enum as src

    fake = lambda *a, **k: result  # noqa: E731
    monkeypatch.setattr(src, "s7_enum", fake)
    monkeypatch.setattr(c11, "s7_enum", fake)
    monkeypatch.setattr(c21, "s7_enum", fake)


# ---------- S7-1.1 anonymous session ----------


class TestS7_11AnonSession:
    def test_pass_when_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from kryon.compliance.checks.ot.s7.c_s7_1_1_anonymous_session import CHECK

        _stub_enum(
            monkeypatch,
            S7EnumResult(
                host="10.0.0.5",
                port=102,
                reachable=False,
                cotp_connected=False,
                s7_session_established=False,
                error="tcp_connect_failed",
            ),
        )
        assert CHECK.run(CheckContext(host="10.0.0.5")).verdict == "PASS"

    def test_fail_when_session_established(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.compliance.checks.ot.s7.c_s7_1_1_anonymous_session import CHECK

        _stub_enum(
            monkeypatch,
            S7EnumResult(
                host="10.0.0.5",
                port=102,
                reachable=True,
                cotp_connected=True,
                s7_session_established=True,
                module_identification={
                    "order_code": "6ES7 315-2EH14-0AB0",
                    "firmware": "V 3.2.6",
                },
                plc_firmware_version="V 3.2.6",
            ),
        )
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        # Order code must be in evidence so the auditor can ID the device.
        assert "6ES7 315-2EH14-0AB0" in result.evidence_stdout

    def test_pass_when_s7_setup_rejected(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """COTP went through but PLC's access protection refused S7 setup —
        the device IS protected, that's PASS."""
        from kryon.compliance.checks.ot.s7.c_s7_1_1_anonymous_session import CHECK

        _stub_enum(
            monkeypatch,
            S7EnumResult(
                host="10.0.0.5",
                port=102,
                reachable=True,
                cotp_connected=True,
                s7_session_established=False,
                error="s7_setup_rejected",
            ),
        )
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"
        assert "access protection" in result.evidence_stdout

    def test_na_when_cotp_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Port open but COTP rejected — could be wrong rack/slot or
        an entirely different ISO-on-TCP service."""
        from kryon.compliance.checks.ot.s7.c_s7_1_1_anonymous_session import CHECK

        _stub_enum(
            monkeypatch,
            S7EnumResult(
                host="10.0.0.5",
                port=102,
                reachable=True,
                cotp_connected=False,
                s7_session_established=False,
            ),
        )
        assert CHECK.run(CheckContext(host="10.0.0.5")).verdict == "N/A"

    def test_severity_is_critical(self) -> None:
        from kryon.compliance.checks.ot.s7.c_s7_1_1_anonymous_session import CHECK

        assert CHECK.severity == "CRITICAL"


# ---------- S7-2.1 firmware currency ----------


class TestS7_21FirmwareCurrency:
    def test_na_when_session_not_established(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.compliance.checks.ot.s7.c_s7_2_1_firmware_currency import CHECK

        _stub_enum(
            monkeypatch,
            S7EnumResult(
                host="10.0.0.5",
                port=102,
                reachable=False,
                cotp_connected=False,
                s7_session_established=False,
            ),
        )
        assert CHECK.run(CheckContext(host="10.0.0.5")).verdict == "N/A"

    def test_fail_when_firmware_below_floor(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """S7-1500 floor is V 2.5.0; firmware 2.1.4 is FAIL."""
        from kryon.compliance.checks.ot.s7.c_s7_2_1_firmware_currency import CHECK

        _stub_enum(
            monkeypatch,
            S7EnumResult(
                host="10.0.0.5",
                port=102,
                reachable=True,
                cotp_connected=True,
                s7_session_established=True,
                module_identification={
                    "order_code": "6ES7 511-1AK02-0AB0",  # S7-1500
                    "firmware": "V 2.1.4",
                },
                plc_firmware_version="V 2.1.4",
            ),
        )
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "FAIL"
        assert "BELOW the safe floor" in result.evidence_stdout

    def test_pass_when_firmware_at_or_above_floor(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.compliance.checks.ot.s7.c_s7_2_1_firmware_currency import CHECK

        _stub_enum(
            monkeypatch,
            S7EnumResult(
                host="10.0.0.5",
                port=102,
                reachable=True,
                cotp_connected=True,
                s7_session_established=True,
                module_identification={
                    "order_code": "6ES7 511-1AK02-0AB0",
                    "firmware": "V 2.6.0",
                },
                plc_firmware_version="V 2.6.0",
            ),
        )
        result = CHECK.run(CheckContext(host="10.0.0.5"))
        assert result.verdict == "PASS"

    def test_na_when_order_code_not_in_tracked_band(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A non-S7 Siemens device (e.g. ET 200SP head, 6ES7 1xx)
        doesn't fit our hard-coded vulnerability bands — N/A, not FAIL."""
        from kryon.compliance.checks.ot.s7.c_s7_2_1_firmware_currency import CHECK

        _stub_enum(
            monkeypatch,
            S7EnumResult(
                host="10.0.0.5",
                port=102,
                reachable=True,
                cotp_connected=True,
                s7_session_established=True,
                module_identification={
                    "order_code": "6ES7 155-6AU01-0CN0",  # ET 200SP
                    "firmware": "V 1.0.0",
                },
                plc_firmware_version="V 1.0.0",
            ),
        )
        assert CHECK.run(CheckContext(host="10.0.0.5")).verdict == "N/A"

    def test_na_when_firmware_unparseable(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.compliance.checks.ot.s7.c_s7_2_1_firmware_currency import CHECK

        _stub_enum(
            monkeypatch,
            S7EnumResult(
                host="10.0.0.5",
                port=102,
                reachable=True,
                cotp_connected=True,
                s7_session_established=True,
                module_identification={
                    "order_code": "6ES7 315-2EH14-0AB0",
                    "firmware": "weird-string-no-version",
                },
                plc_firmware_version="weird-string-no-version",
            ),
        )
        assert CHECK.run(CheckContext(host="10.0.0.5")).verdict == "N/A"


# ---------- Runner integration ----------


def test_runner_registers_s7_checks() -> None:
    from kryon.compliance.runner import _import_all_checks, registered_checks

    _import_all_checks()
    ids = {c.control_id for c in registered_checks()}
    assert "S7-1.1" in ids
    assert "S7-2.1" in ids
