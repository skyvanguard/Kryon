"""T4-A6: _autonomous_privilege_escalation ENUMERATES; it must never report root
just because a candidate vector was found. Only an already-root shell is success."""

from __future__ import annotations

import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.tools.autonomous import orchestrator as orch


def test_enumeration_with_vectors_is_not_escalation(monkeypatch):
    # Linux enum finds a SUID binary → candidate, but NOT root.
    monkeypatch.setattr(
        "kryon.tools.privilege_escalation.linux_privesc.enumerate_linux_privesc",
        lambda: {"suid_binaries": ["/usr/bin/find"], "sudo_permissions": []},
    )
    out = orch._autonomous_privilege_escalation("10.0.0.1", {"privilege_level": "www-data"}, "linux")
    assert out["success"] is False
    assert out["escalated"] is False
    assert out["method"] == "suid"
    assert out["candidate_vectors"] and out["candidate_vectors"][0]["method"] == "suid"


def test_already_root_shell_is_success(monkeypatch):
    monkeypatch.setattr(
        "kryon.tools.privilege_escalation.linux_privesc.enumerate_linux_privesc",
        lambda: {"suid_binaries": []},
    )
    out = orch._autonomous_privilege_escalation("10.0.0.1", {"privilege_level": "root"}, "linux")
    assert out["success"] is True
    assert out["escalated"] is True


def test_no_vectors_is_not_success(monkeypatch):
    monkeypatch.setattr(
        "kryon.tools.privilege_escalation.linux_privesc.enumerate_linux_privesc",
        lambda: {"suid_binaries": [], "sudo_permissions": []},
    )
    out = orch._autonomous_privilege_escalation("10.0.0.1", {"privilege_level": "user"}, "linux")
    assert out["success"] is False
    assert out["method"] == "none"
    assert out["candidate_vectors"] == []
