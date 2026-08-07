"""T4-M4: the EternalBlue/BlueKeep/ExploitDB branches called functions that never
existed (metasploit_wrapper.run_metasploit_module, exploit_db.search_exploitdb).
Verify the real APIs are wired and _msf_exploit normalizes the outcome."""

from __future__ import annotations

import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.tools.autonomous import orchestrator as orch


def test_real_functions_exist():
    from kryon.tools.exploitation import exploit_db
    from kryon.tools.exploitation.metasploit_wrapper import use_exploit_module

    assert callable(use_exploit_module)
    assert callable(exploit_db.search_by_software)
    # the dead names must NOT be relied on anymore
    assert not hasattr(exploit_db, "search_exploitdb")


def test_msf_exploit_detects_session(monkeypatch):
    import kryon.tools.exploitation.metasploit_wrapper as mw

    monkeypatch.setattr(
        mw,
        "use_exploit_module",
        lambda *a, **k: {"success": True, "output": "[*] Meterpreter session 1 opened (10.0.0.1)"},
    )
    out = orch._msf_exploit("exploit/x", "10.0.0.5", payload="windows/x64/meterpreter/reverse_tcp")
    assert out["session_opened"] is True


def test_msf_exploit_detects_vulnerable(monkeypatch):
    import kryon.tools.exploitation.metasploit_wrapper as mw

    monkeypatch.setattr(
        mw,
        "use_exploit_module",
        lambda *a, **k: {"success": True, "output": "[+] 10.0.0.5:3389 - The target is vulnerable."},
    )
    out = orch._msf_exploit("auxiliary/scanner/x", "10.0.0.5")
    assert out["vulnerable"] is True
    assert out["session_opened"] is False


def test_msf_exploit_negative(monkeypatch):
    import kryon.tools.exploitation.metasploit_wrapper as mw

    monkeypatch.setattr(mw, "use_exploit_module", lambda *a, **k: {"success": False, "error": "connection refused"})
    out = orch._msf_exploit("exploit/x", "10.0.0.5")
    assert out["session_opened"] is False
    assert out["vulnerable"] is False
    assert "connection refused" in out["output"]
