"""Tests for the deterministic AD breach chain (initial-access phase).

The offensive logic lives in the importable library
``kryon.tools.lateral_movement.ad_breach``; the pre_hook
(``playbooks/cwe-detection/ad_breach_hook.py``) is a thin adapter. We unit-test
the pure parsers/candidate-list + the ``run_breach`` orchestration (sub-functions
monkeypatched — no network/subprocess), then verify the skill YAML wires through
to the hook via the SAME path-resolution the runner uses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import kryon.skills
from kryon.skills.pre_hook_runner import _resolve_python_callable
from kryon.skills.pre_hook_spec import parse_pre_hooks
from kryon.tools.lateral_movement import ad_breach

_PLAYBOOKS = Path(kryon.skills.__file__).parent / "playbooks"


# --------------------------------------------------------------------------- #
# Pure helpers                                                                 #
# --------------------------------------------------------------------------- #


def test_strip_ansi_removes_colour_codes() -> None:
    coloured = "\x1b[32m[+] VALID USERNAME: bob@thm.loc\x1b[0m"
    assert ad_breach._strip_ansi(coloured) == "[+] VALID USERNAME: bob@thm.loc"


def test_base_domain_name_capitalises_left_label() -> None:
    assert ad_breach.base_domain_name("thm.loc") == "Thm"
    assert ad_breach.base_domain_name("CORP.example.com") == "Corp"
    assert ad_breach.base_domain_name("") == ""


def test_common_password_candidates_puts_domain_flavoured_first() -> None:
    cands = ad_breach.common_password_candidates("thm.loc", limit=20)
    assert cands[0] == "Thm2025!"
    assert "Thm@123" in cands
    # curated commons still present
    assert "Password1" in cands
    assert "Welcome1" in cands


def test_common_password_candidates_respects_limit() -> None:
    assert len(ad_breach.common_password_candidates("thm.loc", limit=5)) == 5
    assert len(ad_breach.common_password_candidates("", limit=3)) == 3


def test_common_password_candidates_dedups_and_min_length() -> None:
    cands = ad_breach.common_password_candidates("", limit=0)  # 0 = no cap
    assert len(cands) == len(set(cands)), "no duplicates"
    assert all(len(p) >= ad_breach._MIN_PW_LEN for p in cands)


def test_common_password_candidates_no_domain_has_no_flavoured() -> None:
    cands = ad_breach.common_password_candidates("", limit=20)
    assert cands[0] == "Password1"  # first curated, no domain prefix


def test_parse_valid_usernames_ansi_safe_and_dedup() -> None:
    out = (
        "\x1b[32m[+] VALID USERNAME:\tADMINISTRATOR@thm.loc\x1b[0m\n"
        "\x1b[32m[+] VALID USERNAME:\tadministrator@thm.loc\x1b[0m\n"
        "\x1b[32m[+] VALID USERNAME:\tbob.smith@thm.loc\x1b[0m\n"
    )
    users = ad_breach.parse_valid_usernames(out)
    assert users == ["administrator", "bob.smith"]  # case-folded + deduped


def test_parse_valid_usernames_empty() -> None:
    assert ad_breach.parse_valid_usernames("") == []
    assert ad_breach.parse_valid_usernames("nothing here") == []


def test_parse_spray_logins_handles_formats() -> None:
    out = "\x1b[32m[+] VALID LOGIN:\t bob@thm.loc\x1b[0m\n[+] VALID LOGIN:  THM\\alice\n[+] VALID LOGIN: carol\n"
    creds = ad_breach.parse_spray_logins(out, "Welcome1")
    assert ("bob", "Welcome1") in creds
    assert ("alice", "Welcome1") in creds
    assert ("carol", "Welcome1") in creds


def test_parse_spray_logins_dedups() -> None:
    out = "[+] VALID LOGIN: bob\n[+] VALID LOGIN: bob@thm.loc\n"
    assert ad_breach.parse_spray_logins(out, "x") == [("bob", "x")]


def test_dedup_creds_case_insensitive_user() -> None:
    creds = [("Bob", "p1"), ("bob", "p1"), ("bob", "p2"), ("", "p3"), ("x", "")]
    assert ad_breach.dedup_creds(creds) == [("bob", "p1"), ("bob", "p2")]


def test_host_of_variants() -> None:
    assert ad_breach.host_of("https://dc.thm.loc:8443/path") == "dc.thm.loc"
    assert ad_breach.host_of("192.168.12.100:445") == "192.168.12.100"
    assert ad_breach.host_of("dc.thm.loc") == "dc.thm.loc"
    assert ad_breach.host_of("") == ""


def test_userenum_wordlist_defaults_to_honeypot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KRYON_AD_USERLIST", raising=False)
    assert ad_breach.userenum_wordlist() == ad_breach._USERENUM_WL


def test_userenum_wordlist_prefers_existing_osint_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    wl = tmp_path / "osint_users.txt"
    wl.write_text("jane.smith\nbob.taylor\n")
    monkeypatch.setenv("KRYON_AD_USERLIST", str(wl))
    assert ad_breach.userenum_wordlist() == str(wl)


def test_userenum_wordlist_ignores_missing_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRYON_AD_USERLIST", "/nope/does/not/exist.txt")
    assert ad_breach.userenum_wordlist() == ad_breach._USERENUM_WL


# --------------------------------------------------------------------------- #
# Lockout safety (fix for the live account-lockout the blind spray caused)     #
# --------------------------------------------------------------------------- #


def test_lockout_threshold_parses_pass_pol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ad_breach, "_sh", lambda cmd, t: "  Account Lockout Threshold : 5\n")
    assert ad_breach.lockout_threshold("dc") == 5


def test_lockout_threshold_zero_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ad_breach, "_sh", lambda cmd, t: "Account Lockout Threshold: 0\n")
    assert ad_breach.lockout_threshold("dc") is None


def test_lockout_threshold_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ad_breach, "_sh", lambda cmd, t: "")
    assert ad_breach.lockout_threshold("dc") is None


def test_safe_spray_limit_stays_below_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KRYON_AD_SPRAY_LIMIT", raising=False)  # ceiling 5
    monkeypatch.setattr(ad_breach, "lockout_threshold", lambda host: 5)
    n, note = ad_breach.safe_spray_limit("dc")
    assert n == 3  # threshold 5 -> 5-2, margin for pre-existing failures
    assert "threshold 5" in note


def test_safe_spray_limit_unknown_hard_caps_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KRYON_AD_SPRAY_LIMIT", raising=False)
    monkeypatch.setattr(ad_breach, "lockout_threshold", lambda host: None)
    n, note = ad_breach.safe_spray_limit("dc")
    assert n == 2
    assert "cap 2" in note


def test_safe_spray_limit_respects_operator_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ad_breach, "lockout_threshold", lambda host: 20)
    monkeypatch.setenv("KRYON_AD_SPRAY_LIMIT", "3")
    n, _ = ad_breach.safe_spray_limit("dc")
    assert n == 3  # min(operator 3, threshold 20 - 2)


# --------------------------------------------------------------------------- #
# run_breach orchestration (sub-functions monkeypatched — no I/O)             #
# --------------------------------------------------------------------------- #


@pytest.fixture
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default stubs: reachable DC, some users, no creds. Individual tests
    override the pieces they care about."""
    monkeypatch.setattr(ad_breach, "resolve_domain", lambda host: "thm.loc")
    monkeypatch.setattr(ad_breach, "enum_users", lambda host, domain: ["administrator", "bob", "alice"])
    monkeypatch.setattr(ad_breach, "asrep_roast", lambda host, domain, users: [])
    monkeypatch.setattr(ad_breach, "common_password_spray", lambda dc, domain, users, pw: [])
    # Roomy lockout threshold so safe_spray_limit doesn't clamp below the test's
    # KRYON_AD_SPRAY_LIMIT (real nxc --pass-pol is never called in unit tests).
    monkeypatch.setattr(ad_breach, "lockout_threshold", lambda host: 20)


def test_run_breach_no_target() -> None:
    assert "no target host" in ad_breach.run_breach({}).lower()
    assert "no target host" in ad_breach.run_breach("").lower()


def test_run_breach_not_a_dc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ad_breach, "resolve_domain", lambda host: "")
    out = ad_breach.run_breach({"target": "192.168.12.100"})
    assert "not a reachable Domain Controller" in out


def test_run_breach_asrep_foothold(_no_network, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ad_breach, "asrep_roast", lambda h, d, u: [("svc-admin", "management2005")])
    out = ad_breach.run_breach({"target": "192.168.12.100"})
    assert "AS-REP foothold: svc-admin:management2005" in out
    assert "CONFIRMED foothold (1 credential" in out


def test_run_breach_spray_foothold(_no_network, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ad_breach, "common_password_spray", lambda dc, d, u, pw: [("bob", "Welcome1")])
    out = ad_breach.run_breach({"target": "192.168.12.100"})
    assert "SPRAY foothold: bob:Welcome1" in out
    assert "CONFIRMED foothold" in out
    # spray line names how many passwords/users were tried + the lockout note
    assert "spraying" in out.lower()
    assert "lockout" in out.lower()


def test_run_breach_no_cred_gives_next_steps(_no_network) -> None:
    out = ad_breach.run_breach({"target": "192.168.12.100"})
    assert "no credential recovered" in out
    # actionable pivots for the model
    assert "Gitea" in out or "coercion" in out.lower() or "Responder" in out


def test_run_breach_spray_disabled_by_env(_no_network, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRYON_AD_SPRAY", "0")
    called = {"spray": False}

    def _spy(dc, d, u, pw):  # pragma: no cover - must NOT be called
        called["spray"] = True
        return []

    monkeypatch.setattr(ad_breach, "common_password_spray", _spy)
    out = ad_breach.run_breach({"target": "192.168.12.100"})
    assert "password spray DISABLED" in out
    assert called["spray"] is False


def test_run_breach_uses_host_key_fallback(_no_network) -> None:
    """ctx with host but no target still resolves (build_turn_ctx sets both,
    but older call sites may pass only one)."""
    out = ad_breach.run_breach({"host": "192.168.12.100"})
    assert "[AD-BREACH deterministic initial access]" in out


def test_run_breach_spray_limit_env(_no_network, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRYON_AD_SPRAY_LIMIT", "3")
    captured = {"n": -1}

    def _spy(dc, d, users, passwords):
        captured["n"] = len(passwords)
        return []

    monkeypatch.setattr(ad_breach, "common_password_spray", _spy)
    ad_breach.run_breach({"target": "192.168.12.100"})
    assert captured["n"] == 3


# --------------------------------------------------------------------------- #
# Skill → hook wiring (same path-resolution the runner uses)                  #
# --------------------------------------------------------------------------- #


def test_skill_prehook_resolves_and_runs() -> None:
    """The skill's `python:` hook must resolve to a callable that runs the
    library — catches path/import regressions across the whole wiring."""
    hooks = parse_pre_hooks(
        [
            {
                "python": "./cwe-detection/ad_breach_hook.py:run",
                "inject_as": "active_directory_breach_foothold",
                "required": False,
                "timeout_s": 900,
            }
        ],
        source_dir=str(_PLAYBOOKS),
    )
    assert len(hooks) == 1
    func = _resolve_python_callable(hooks[0])
    # Empty ctx → graceful skip (no network), proves the import chain works.
    assert "no target host" in func({}).lower()
