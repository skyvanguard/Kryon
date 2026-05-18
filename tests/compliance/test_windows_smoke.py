"""F199 — Windows Server + endpoint compliance smoke tests.

Verifies:
  1. All 15 WIN-* check modules import cleanly and self-register.
  2. The framework prefix filter in `run_compliance_audit` selects only
     WIN-* control IDs.
  3. Sample parsers produce the right verdict on hand-crafted PowerShell
     output fixtures.
  4. The Protocol contract (control_title / severity / remediation_static)
     is satisfied by every check.
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.compliance.checks.base import CheckContext
from kryon.compliance.runner import _import_all_checks, registered_checks


@pytest.fixture(scope="module", autouse=True)
def _ensure_checks_loaded() -> None:
    _import_all_checks()


def _ids_with_prefix(prefix: str) -> list[str]:
    return [c.control_id for c in registered_checks() if c.control_id.startswith(prefix)]


def _ctx() -> CheckContext:
    return CheckContext(host="localhost", transport="winrm")


def _fake(stdout: str, stderr: str = "", rc: int = 0):
    def fn(_ctx, _cmd, **_kw):
        return stdout, stderr, rc

    return fn


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_all_15_windows_checks_registered() -> None:
    win_ids = _ids_with_prefix("WIN-")
    expected = {
        "WIN-1.1",
        "WIN-1.2",
        "WIN-1.3",
        "WIN-2.1",
        "WIN-2.2",
        "WIN-2.3",
        "WIN-2.4",
        "WIN-2.5",
        "WIN-3.1",
        "WIN-3.2",
        "WIN-3.3",
        "WIN-3.4",
        "WIN-3.5",
        "WIN-4.1",
        "WIN-4.2",
    }
    assert set(win_ids) == expected, f"missing or extra: {set(win_ids) ^ expected}"


def test_win_checks_satisfy_protocol() -> None:
    for c in registered_checks():
        if not c.control_id.startswith("WIN-"):
            continue
        assert c.control_title, f"{c.control_id} missing title"
        assert c.section, f"{c.control_id} missing section"
        assert c.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}, f"{c.control_id} severity={c.severity}"
        assert c.remediation_static, f"{c.control_id} missing remediation"


# ---------------------------------------------------------------------------
# Sample parser fixtures
# ---------------------------------------------------------------------------


class TestSmb1Check:
    def test_smb1_true_fails(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_1_1_smbv1 as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("True\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"
        assert res.evidence_parsed["smb1_enabled"] is True

    def test_smb1_false_passes(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_1_1_smbv1 as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("False\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


class TestLsaProtectionCheck:
    def test_runasppl_1_passes(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_1_2_lsa_protection as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("1\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_runasppl_absent_fails(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_1_2_lsa_protection as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("", "ItemNotFound: cannot find path", 1))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"


class TestDcPrintSpoolerCheck:
    def test_non_dc_is_na(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_1_3_dc_print_spooler as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("ProductType=WinNT SpoolerStatus=Running\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "N/A"

    def test_dc_with_spooler_running_fails(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_1_3_dc_print_spooler as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("ProductType=LanmanNT SpoolerStatus=Running\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_dc_with_spooler_stopped_passes(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_1_3_dc_print_spooler as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("ProductType=LanmanNT SpoolerStatus=Stopped\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


class TestFirewallDomainCheck:
    def test_enabled_passes(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_2_2_firewall_domain as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("True\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_disabled_fails(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_2_2_firewall_domain as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("False\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"


class TestRdpNlaCheck:
    def test_nla_on_passes(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_3_4_rdp_nla as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("1\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_nla_off_fails(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_3_4_rdp_nla as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("0\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_absent_fails(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_3_4_rdp_nla as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("", "ItemNotFound", 1))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"


class TestUacCheck:
    def test_consent_2_passes(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_3_5_uac as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("2\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_consent_0_fails(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_3_5_uac as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("0\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"


class TestWsusInternetCheck:
    def test_unset_passes(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_2_5_wsus_internet as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_private_wsus_passes(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_2_5_wsus_internet as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("http://wsus.empresa.local:8530\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_public_wsus_fails(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_2_5_wsus_internet as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("http://evil.example.com:8530\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"


class TestRemoteRegistryCheck:
    def test_running_fails(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_4_1_remote_registry as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("Status=Running StartType=Manual\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_stopped_and_disabled_passes(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_4_1_remote_registry as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("Status=Stopped StartType=Disabled\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


class TestEdrDetectionCheck:
    def test_no_edr_fails(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_4_2_edr_detection as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_crowdstrike_running_passes(self, monkeypatch):
        from kryon.compliance.checks.windows import c_win_4_2_edr_detection as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("CSFalconService=Running\n"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


# ---------------------------------------------------------------------------
# Framework prefix filter
# ---------------------------------------------------------------------------


def test_framework_prefix_includes_windows_aliases() -> None:
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    assert _FRAMEWORK_PREFIX["windows"] == ("WIN-",)
    assert _FRAMEWORK_PREFIX["win"] == ("WIN-",)
    assert _FRAMEWORK_PREFIX["windows-server"] == ("WIN-",)
