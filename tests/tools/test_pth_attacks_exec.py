"""pass-the-hash family tools must actually run the full command and interpret its
string output.

Regression (T4-C1): the tools called run_command(bin, args) — but run_command's 2nd
positional is `ctf`, not args, so only the bare binary ran; then they did
cmd_result.get("success") on the returned STRING → AttributeError swallowed by the
except → EVERY call returned a fake failure."""

from __future__ import annotations

import json
import os

os.environ.setdefault("KRYON_RED_TEAM", "true")  # module is red-team gated

from kryon.tools.lateral_movement import pth_attacks  # noqa: E402


def test_exec_runs_the_full_command(monkeypatch):
    captured = {}

    def fake_run_command(cmd, *a, **kw):
        captured["cmd"] = cmd
        captured["extra"] = (a, kw)
        return "some real output line\nsecond line"

    monkeypatch.setattr(pth_attacks, "run_command", fake_run_command)
    ok, out = pth_attacks._exec(["pth-winexe", "-U", "CORP/admin%hash", "//10.0.0.5"])
    # The WHOLE command runs, not just the bare binary; no args land in the ctf slot.
    assert captured["cmd"] == "pth-winexe -U CORP/admin%hash //10.0.0.5"
    assert captured["extra"] == ((), {})
    assert ok is True
    assert out == "some real output line\nsecond line"


def test_exec_detects_error_output(monkeypatch):
    monkeypatch.setattr(pth_attacks, "run_command", lambda cmd: "ERROR: connection refused")
    ok, _ = pth_attacks._exec(["pth-winexe", "x"])
    assert ok is False


def test_pass_the_hash_no_attributeerror_and_reports_success(monkeypatch):
    # The exact bug: str.get() used to raise; now a real shell output → success.
    monkeypatch.setattr(pth_attacks, "run_command", lambda cmd: "Microsoft Windows\nC:\\Users\\admin>")
    res = pth_attacks.pass_the_hash._raw_fn(
        target="10.0.0.5", domain="CORP", username="admin", ntlm_hash="31d6cfe0d16ae931b73c59d7e0c089c0"
    )
    d = json.loads(res)
    assert d["success"] is True
    assert d["authenticated"] is True
    assert "str" not in (d.get("error") or "")  # not the old AttributeError text


def test_extract_ntlm_hash_parses_output(monkeypatch):
    dump = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    monkeypatch.setattr(pth_attacks, "run_command", lambda cmd: dump)
    res = pth_attacks.extract_ntlm_hash._raw_fn(sam_file="/tmp/SAM", system_file="/tmp/SYSTEM")
    d = json.loads(res)
    assert d["success"] is True
    assert any("31d6cfe0" in h for h in d["hashes"])
