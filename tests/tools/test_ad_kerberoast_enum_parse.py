"""T4-M11: kerberoast must keep the SPN/account (it discarded them), and enumerate_ad
must parse enum4linux-NG output (username:/groupname:), not only legacy enum4linux."""

from __future__ import annotations

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"
os.environ["KRYON_RED_TEAM"] = "true"

from kryon.tools.lateral_movement import ad_attacks

_kerberoast = ad_attacks.kerberoast._raw_fn
_enumerate_ad = ad_attacks.enumerate_ad._raw_fn


def test_kerberoast_keeps_spn_and_account(monkeypatch):
    hashline = "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$abcdef0123"
    table = "MSSQLSvc/sql01.corp.local:1433   svc_sql   Domain Users   2020-01-01"
    monkeypatch.setattr(ad_attacks, "_run_cmd", lambda *a, **k: f"{table}\n\n{hashline}\n")
    out = json.loads(_kerberoast("10.0.0.1", "corp.local", "u", "p"))

    assert out["ticket_count"] == 1
    t = out["tickets"][0]
    assert t["account"] == "svc_sql"
    assert t["spn"] == "MSSQLSvc/sql01.corp.local:1433"
    assert "MSSQLSvc/sql01.corp.local:1433" in out["spns"]


def test_enumerate_ad_parses_enum4linux_ng(monkeypatch, tmp_path):
    monkeypatch.setattr(ad_attacks, "_AD_USERS_FILE", str(tmp_path / "u.txt"))

    def fake_run(cmd, timeout=120):
        if cmd.startswith("enum4linux-ng"):
            return "username: Administrator\nusername: svc-web\ngroupname: Domain Admins\n"
        return ""  # ldapsearch / rpcclient empty

    monkeypatch.setattr(ad_attacks, "_run_cmd", fake_run)
    out = json.loads(_enumerate_ad("10.0.0.1", "corp.local"))
    assert "Administrator" in out["users"]
    assert "svc-web" in out["users"]
    assert "Domain Admins" in out["groups"]


def test_enumerate_ad_still_parses_legacy_enum4linux(monkeypatch, tmp_path):
    monkeypatch.setattr(ad_attacks, "_AD_USERS_FILE", str(tmp_path / "u.txt"))

    def fake_run(cmd, timeout=120):
        if cmd.startswith("enum4linux-ng"):
            return "user:[legacyuser] rid:[0x451]\ngroup:[Legacy Group] rid:[0x201]\n"
        return ""

    monkeypatch.setattr(ad_attacks, "_run_cmd", fake_run)
    out = json.loads(_enumerate_ad("10.0.0.1", "corp.local"))
    assert "legacyuser" in out["users"]
    assert "Legacy Group" in out["groups"]
