"""enumerate_ad anonymous LDAP user enumeration (the THM Operation Endgame fix).

Modern AD restricts anonymous RPC/SAMR (enum4linux + rpcclient enumdomusers → access denied), but
LDAP anonymous READ is frequently still allowed. enumerate_ad now runs `ldapsearch -x` and parses
sAMAccountName, so the AS-REP/spray rules get a user list where before they got nothing. Validated live
on Operation Endgame: 0 users -> 331."""

from __future__ import annotations

import json
import os

os.environ.setdefault("KRYON_RED_TEAM", "true")

from kryon.tools.lateral_movement import ad_attacks

_raw = getattr(ad_attacks.enumerate_ad, "_raw_fn", None) or getattr(ad_attacks.enumerate_ad, "__wrapped__", None)

_LDAPSEARCH_OUT = (
    "# extended LDIF\n"
    "dn: CN=DWAYNE_NGUYEN,CN=Users,DC=thm,DC=local\n"
    "sAMAccountName: DWAYNE_NGUYEN\n\n"
    "dn: CN=BRANDON_PITTMAN,CN=Users,DC=thm,DC=local\n"
    "sAMAccountName: BRANDON_PITTMAN\n\n"
    "dn: CN=DC01,OU=Domain Controllers,DC=thm,DC=local\n"
    "sAMAccountName: DC01$\n\n"  # machine account — must be dropped
)


def test_anon_ldapsearch_users_parsed(monkeypatch):
    seen = {}

    def fake_run(cmd, timeout=60):
        if cmd.startswith("ldapsearch"):
            seen["ldapsearch"] = cmd
            return _LDAPSEARCH_OUT
        return ""

    monkeypatch.setattr(ad_attacks, "_run_cmd", fake_run)
    out = json.loads(_raw("10.64.145.44", "thm.local"))
    # anon simple bind, base DN derived from the domain, asks for sAMAccountName
    assert "-x" in seen["ldapsearch"] and "DC=thm,DC=local" in seen["ldapsearch"]
    assert "sAMAccountName" in seen["ldapsearch"]
    # human users parsed, machine account ($) dropped
    assert "DWAYNE_NGUYEN" in out["users"] and "BRANDON_PITTMAN" in out["users"]
    assert "DC01$" not in out["users"]


def test_authenticated_bind_when_creds_given(monkeypatch):
    seen = {}

    def fake_run(cmd, timeout=60):
        if cmd.startswith("ldapsearch"):
            seen["ldapsearch"] = cmd
        return ""

    monkeypatch.setattr(ad_attacks, "_run_cmd", fake_run)
    _raw("10.64.145.44", "thm.local", username="jdoe", password="pw")
    assert "jdoe@thm.local" in seen["ldapsearch"] and "-x" not in seen["ldapsearch"].split()[1:3]
