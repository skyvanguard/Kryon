"""F198 — Asterisk (VoIP) compliance smoke tests.

Verifies:
  1. All 8 VOIP-* check modules import cleanly and self-register.
  2. The framework prefix filter in `run_compliance_audit` selects only
     VOIP-* control IDs.
  3. Sample parsers produce the right verdict on synthetic config
     output (proves the checks aren't empty stubs).
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
    return CheckContext(host="localhost", transport="local")


def _fake(stdout: str, stderr: str = "", rc: int = 0):
    def fn(_ctx, _cmd, **_kw):
        return stdout, stderr, rc

    return fn


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_all_8_asterisk_checks_registered() -> None:
    voip_ids = _ids_with_prefix("VOIP-")
    expected = {
        "VOIP-1.1",
        "VOIP-1.2",
        "VOIP-2.1",
        "VOIP-2.2",
        "VOIP-2.3",
        "VOIP-3.1",
        "VOIP-3.2",
        "VOIP-3.3",
    }
    assert set(voip_ids) == expected, f"missing or extra: {set(voip_ids) ^ expected}"


# ---------------------------------------------------------------------------
# VOIP-2.1 allowguest
# ---------------------------------------------------------------------------


class TestAllowGuestCheck:
    def test_allowguest_yes_fails(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_2_1_allowguest as mod

        cfg = "[general]\nbindport=5060\nallowguest=yes\n\n[users]\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"
        assert res.evidence_parsed["allowguest"] == "yes"

    def test_allowguest_no_passes(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_2_1_allowguest as mod

        cfg = "[general]\nallowguest=no\n\n[users]\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_no_general_section_is_na(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_2_1_allowguest as mod

        cfg = "[transport-udp]\ntype=transport\nprotocol=udp\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "N/A"


# ---------------------------------------------------------------------------
# VOIP-2.2 alwaysauthreject
# ---------------------------------------------------------------------------


class TestAlwaysAuthRejectCheck:
    def test_no_value_fails(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_2_2_alwaysauthreject as mod

        cfg = "[general]\nalwaysauthreject=no\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_yes_passes(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_2_2_alwaysauthreject as mod

        cfg = "[general]\nalwaysauthreject=yes\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_unset_defaults_to_pass_on_modern_asterisk(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_2_2_alwaysauthreject as mod

        cfg = "[general]\nbindport=5060\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


# ---------------------------------------------------------------------------
# VOIP-1.2 AMI default secret
# ---------------------------------------------------------------------------


class TestAmiDefaultSecretCheck:
    def test_default_secret_fails(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_1_2_ami_default_secret as mod

        cfg = "[general]\nenabled=yes\nport=5038\n\n[admin]\nsecret=amp111\npermit=0.0.0.0/0\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"
        weak = res.evidence_parsed["weak_users"]
        assert any(u["user"] == "admin" for u in weak)

    def test_strong_secret_passes(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_1_2_ami_default_secret as mod

        cfg = "[general]\nenabled=yes\n\n[admin]\nsecret=Xz9!qP3LmRf2bT8w\npermit=127.0.0.1/32\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_short_secret_fails_even_if_not_default(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_1_2_ami_default_secret as mod

        cfg = "[admin]\nsecret=abc1\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"


# ---------------------------------------------------------------------------
# VOIP-3.3 Asterisk version
# ---------------------------------------------------------------------------


class TestAsteriskVersionCheck:
    def test_version_16_fails(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_3_3_asterisk_version as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("Asterisk 16.30.0"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"
        assert res.evidence_parsed["major"] == 16

    def test_version_20_passes(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_3_3_asterisk_version as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("Asterisk 20.5.1"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_version_18_near_eol_fails(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_3_3_asterisk_version as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("Asterisk 18.20.0"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_unparseable_version_is_error(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_3_3_asterisk_version as mod

        monkeypatch.setattr(mod, "run_cmd", _fake("asterisk: command not found", "not found", 127))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "ERROR"


# ---------------------------------------------------------------------------
# VOIP-3.1 SRTP disabled
# ---------------------------------------------------------------------------


class TestSrtpDisabledCheck:
    def test_no_srtp_anywhere_fails(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_3_1_srtp_disabled as mod

        cfg = (
            "--sip.conf--\n[general]\nbindport=5060\n\n[1001]\ntype=friend\n"
            "--pjsip.conf--\n[transport-udp]\ntype=transport\n"
        )
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_srtp_via_media_encryption_passes(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_3_1_srtp_disabled as mod

        cfg = "--sip.conf--\n\n--pjsip.conf--\n[1001]\ntype=endpoint\nmedia_encryption=sdes\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


# ---------------------------------------------------------------------------
# VOIP-3.2 SIP-TLS disabled
# ---------------------------------------------------------------------------


class TestSipTlsDisabledCheck:
    def test_no_tls_fails(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_3_2_sip_tls_disabled as mod

        cfg = "--sip.conf--\n[general]\nbindport=5060\n--pjsip.conf--\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_tls_via_pjsip_transport_passes(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_3_2_sip_tls_disabled as mod

        cfg = "--sip.conf--\n--pjsip.conf--\n[transport-tls]\ntype=transport\nprotocol=tls\nbind=0.0.0.0:5061\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


# ---------------------------------------------------------------------------
# VOIP-2.3 AMI WAN exposure
# ---------------------------------------------------------------------------


class TestAmiWanExposureCheck:
    def test_default_bindaddr_with_public_iface_fails(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_2_3_ami_wan_exposure as mod

        out = (
            "[general]\nenabled=yes\nport=5038\nbindaddr=0.0.0.0\n"
            "--interfaces--\n"
            "1: lo    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0  inet 200.1.1.50/24 brd 200.1.1.255 scope global eth0\n"
        )
        monkeypatch.setattr(mod, "run_cmd", _fake(out))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"
        assert "200.1.1.50" in res.evidence_parsed["host_public_ips"]

    def test_localhost_bindaddr_passes(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_2_3_ami_wan_exposure as mod

        out = (
            "[general]\nenabled=yes\nbindaddr=127.0.0.1\n"
            "--interfaces--\n"
            "1: lo    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0  inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
        )
        monkeypatch.setattr(mod, "run_cmd", _fake(out))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_private_only_iface_passes(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_2_3_ami_wan_exposure as mod

        out = "[general]\nbindaddr=0.0.0.0\n--interfaces--\n1: eth0  inet 192.168.1.10/24 scope global eth0\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(out))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


# ---------------------------------------------------------------------------
# VOIP-1.1 anonymous register
# ---------------------------------------------------------------------------


class TestAnonRegisterCheck:
    def test_default_with_dial_fails(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_1_1_anon_register as mod

        cfg = (
            "[globals]\nFOO=bar\n\n"
            "[default]\n"
            "exten => _X.,1,Dial(SIP/${EXTEN})\n"
            "exten => _X.,n,Hangup()\n\n"
            "[from-internal]\nexten => 100,1,Dial(SIP/100)\n"
        )
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"
        assert "Dial" in res.evidence_parsed["dangerous_apps"]

    def test_default_with_hangup_only_passes(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_1_1_anon_register as mod

        cfg = "[default]\nexten => _X.,1,Hangup()\n\n[from-internal]\nexten => 100,1,Dial(SIP/100)\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_no_default_context_passes(self, monkeypatch):
        from kryon.compliance.checks.asterisk import c_voip_1_1_anon_register as mod

        cfg = "[from-internal]\nexten => 100,1,Dial(SIP/100)\n"
        monkeypatch.setattr(mod, "run_cmd", _fake(cfg))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


# ---------------------------------------------------------------------------
# Framework prefix filter
# ---------------------------------------------------------------------------


def test_framework_prefix_includes_asterisk_aliases() -> None:
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    assert _FRAMEWORK_PREFIX["asterisk"] == ("VOIP-",)
    assert _FRAMEWORK_PREFIX["voip"] == ("VOIP-",)
    assert _FRAMEWORK_PREFIX["freepbx"] == ("VOIP-",)
