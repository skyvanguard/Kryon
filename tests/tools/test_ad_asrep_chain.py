"""T4-A7: enumerate_ad must persist discovered users to the file asreproast reads,
and asreproast must fail clearly (not run against a nonexistent file) when it's
missing. Closes the enumerate_ad → asreproast chain."""

from __future__ import annotations

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"
os.environ["KRYON_RED_TEAM"] = "true"  # module import is gated on this

from kryon.tools.lateral_movement import ad_attacks

_enumerate_ad = ad_attacks.enumerate_ad._raw_fn
_asreproast = ad_attacks.asreproast._raw_fn


def test_asreproast_errors_clearly_when_no_userlist(monkeypatch, tmp_path):
    missing = tmp_path / "nope.txt"
    monkeypatch.setattr(ad_attacks, "_AD_USERS_FILE", str(missing))
    # _run_cmd must NOT be reached — assert it raises if called
    monkeypatch.setattr(ad_attacks, "_run_cmd", lambda *a, **k: pytest_fail())
    out = json.loads(_asreproast("10.0.0.1", "corp.local"))
    assert out["hash_count"] == 0
    assert "no userlist" in out["error"]
    assert "enumerate_ad" in out["next_step"]


def pytest_fail():
    raise AssertionError("_run_cmd should not run when the userlist is missing")


def test_enumerate_ad_writes_userlist(monkeypatch, tmp_path):
    target = tmp_path / "ad_users.txt"
    monkeypatch.setattr(ad_attacks, "_AD_USERS_FILE", str(target))

    def fake_run(cmd, timeout=120):
        if "ldapsearch" in cmd:
            return "sAMAccountName: alice\nsAMAccountName: bob\nsAMAccountName: dc01$\n"
        return ""

    monkeypatch.setattr(ad_attacks, "_run_cmd", fake_run)
    out = json.loads(_enumerate_ad("10.0.0.1", "corp.local"))

    assert "alice" in out["users"] and "bob" in out["users"]
    assert "dc01$" not in out["users"]  # machine account dropped
    assert out["users_file"] == str(target)
    assert target.read_text(encoding="utf-8").splitlines() == ["alice", "bob"]


def test_chain_enumerate_then_asreproast(monkeypatch, tmp_path):
    target = tmp_path / "ad_users.txt"
    monkeypatch.setattr(ad_attacks, "_AD_USERS_FILE", str(target))

    def fake_run(cmd, timeout=120):
        if "ldapsearch" in cmd:
            return "sAMAccountName: svc-admin\n"
        if "GetNPUsers" in cmd:
            return "$krb5asrep$23$svc-admin@CORP.LOCAL:abcd$deadbeef"
        return ""

    monkeypatch.setattr(ad_attacks, "_run_cmd", fake_run)
    json.loads(_enumerate_ad("10.0.0.1", "corp.local"))  # writes file
    roast = json.loads(_asreproast("10.0.0.1", "corp.local"))
    assert roast["hash_count"] == 1
    assert "svc-admin" in roast["vulnerable_accounts"]
