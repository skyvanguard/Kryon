"""Tests for _autonomous_privilege_escalation fixes.

Three defects: dead ref (linux_privesc.auto_privilege_escalation never existed),
IndexError on a present-but-empty vector list, and target_os='auto' routing to
winpeas instead of Linux. The real enumerators are monkeypatched — nothing runs
locally.
"""

from __future__ import annotations

from kryon.tools.autonomous.orchestrator import _autonomous_privilege_escalation


def _patch_linux(monkeypatch, fake):
    monkeypatch.setattr("kryon.tools.privilege_escalation.linux_privesc.enumerate_linux_privesc", fake)


def _patch_windows(monkeypatch, fake):
    monkeypatch.setattr("kryon.tools.privilege_escalation.windows_privesc.run_winpeas", fake)


def test_linux_sudo_vector_is_candidate_not_root(monkeypatch):
    # T4-A6: enumerating a sudo NOPASSWD rule is a CANDIDATE, not proof of root.
    _patch_linux(monkeypatch, lambda: {"sudo_permissions": ["(ALL) NOPASSWD: /bin/bash"], "suid_binaries": []})
    out = _autonomous_privilege_escalation("10.0.0.5", {}, "linux")
    assert out["success"] is False  # honest: enumeration != escalation
    assert out["escalated"] is False
    assert out["method"] == "sudo"
    assert out["candidate_vectors"][0]["method"] == "sudo"


def test_linux_falls_through_to_suid(monkeypatch):
    _patch_linux(monkeypatch, lambda: {"sudo_permissions": [], "suid_binaries": ["/usr/bin/find"]})
    out = _autonomous_privilege_escalation("10.0.0.5", {}, "linux")
    assert out["method"] == "suid"


def test_linux_all_empty_no_indexerror(monkeypatch):
    # Regression: the old `[{}][0]` crashed with IndexError when the vector list
    # was present but empty. Now it returns a clean 'none'.
    _patch_linux(
        monkeypatch,
        lambda: {
            "sudo_permissions": [],
            "suid_binaries": [],
            "capabilities": [],
            "writable_files": [],
            "cron_jobs": [],
        },
    )
    out = _autonomous_privilege_escalation("10.0.0.5", {}, "linux")
    assert out["success"] is False
    assert out["method"] == "none"


def test_auto_routes_to_linux_not_windows(monkeypatch):
    # Regression: target_os='auto' used to hit winpeas. It must use Linux.
    called = {"linux": False, "windows": False}

    def linux():
        called["linux"] = True
        return {"suid_binaries": ["/usr/bin/vim"]}

    def windows():
        called["windows"] = True
        return {"critical_findings": []}

    _patch_linux(monkeypatch, linux)
    _patch_windows(monkeypatch, windows)
    _autonomous_privilege_escalation("10.0.0.5", {}, "auto")

    assert called["linux"] is True
    assert called["windows"] is False


def test_windows_branch(monkeypatch):
    # T4-A6: winpeas critical findings are candidates too, not confirmed escalation.
    _patch_windows(monkeypatch, lambda: {"critical_findings": ["AlwaysInstallElevated"]})
    out = _autonomous_privilege_escalation("10.0.0.5", {}, "windows")
    assert out["success"] is False
    assert out["method"] == "winpeas"
    assert out["candidate_vectors"] == ["AlwaysInstallElevated"]


def test_already_root_access_reports_success(monkeypatch):
    # The one honest True: the obtained shell already reports root.
    _patch_linux(monkeypatch, lambda: {"suid_binaries": []})
    out = _autonomous_privilege_escalation("10.0.0.5", {"privilege_level": "root"}, "linux")
    assert out["success"] is True
    assert out["escalated"] is True
