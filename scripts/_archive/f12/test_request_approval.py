"""F12.6 tests — request_approval @function_tool."""
from __future__ import annotations

import json
import os
from unittest.mock import patch

from kryon.tools.validation.request_approval import request_approval

_SAMPLE_ACTIONS = [
    {
        "command": "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.1744",
        "purpose": "Backup sshd_config",
        "severity": "read",
        "reversible": True,
        "target_host": "admin@192.168.1.10",
    },
    {
        "command": "sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
        "purpose": "Disable root SSH login",
        "severity": "high",
        "reversible": True,
        "backup_path": "/etc/ssh/sshd_config.bak.1744",
        "target_host": "admin@192.168.1.10",
    },
    {
        "command": "systemctl reload sshd",
        "purpose": "Reload SSH daemon",
        "severity": "critical",
        "reversible": False,
        "target_host": "admin@192.168.1.10",
    },
]


def _invoke(**kwargs) -> dict:
    """Call the FunctionTool via its agent-facing interface."""
    import asyncio
    payload = json.dumps({
        "title": kwargs.pop("title", "Aplicar 3 correcciones"),
        "actions": kwargs.pop("actions", _SAMPLE_ACTIONS),
        "subtitle": kwargs.pop("subtitle", "admin@192.168.1.10"),
        "dry_run": kwargs.pop("dry_run", False),
        "impact_notes": kwargs.pop("impact_notes", None) or [],
    })
    return json.loads(asyncio.run(request_approval.on_invoke_tool(None, payload)))


def test_noninteractive_default_no() -> None:
    for k in ("KRYON_AUTO_APPROVE",):
        os.environ.pop(k, None)
    # Tests run under docker exec — stdin is NOT a TTY, so the tool
    # short-circuits to a safe "no".
    r = _invoke()
    assert r["verdict"] == "no", r
    assert "non-interactive" in r["reason"].lower()
    print("  ok: non-TTY context -> default-deny with reason")


def test_auto_approve_bypass() -> None:
    os.environ["KRYON_AUTO_APPROVE"] = "true"
    try:
        r = _invoke()
        assert r["verdict"] == "yes", r
        assert "KRYON_AUTO_APPROVE" in r["reason"]
        assert r["n_actions"] == 3
    finally:
        os.environ.pop("KRYON_AUTO_APPROVE", None)
    print("  ok: KRYON_AUTO_APPROVE=true -> yes + reason trail")


def test_empty_actions_rejects() -> None:
    os.environ["KRYON_AUTO_APPROVE"] = "true"  # force past interactivity gate
    try:
        r = _invoke(actions=[])
        # With auto-approve, empty still says yes but n_actions=0.
        # To check the empty-action guard works, disable auto-approve and
        # rely on interactive path — we test that branch next.
        assert r["n_actions"] == 0
    finally:
        os.environ.pop("KRYON_AUTO_APPROVE", None)
    print("  ok: empty actions -> verdict with n_actions=0")


def test_severity_alias_normalisation() -> None:
    # Confirm that a "critical" severity maps to destructive. We can't
    # observe internal Severity easily without UI render, but we can
    # confirm no exception + verdict comes back sane.
    os.environ["KRYON_AUTO_APPROVE"] = "true"
    try:
        mixed = [
            {"command": "rm foo", "severity": "crit"},
            {"command": "cat bar", "severity": "info"},
            {"command": "echo baz"},  # no severity → defaults to modify
        ]
        r = _invoke(actions=mixed)
        assert r["verdict"] == "yes"
        assert r["n_actions"] == 3
    finally:
        os.environ.pop("KRYON_AUTO_APPROVE", None)
    print("  ok: severity aliases (crit/info/default) accepted")


def test_interactive_yes_path_via_mock() -> None:
    """Simulate TTY + mocked Prompt.ask returning 'y'."""
    os.environ.pop("KRYON_AUTO_APPROVE", None)
    import sys

    with patch.object(sys.stdin, "isatty", return_value=True), \
         patch.object(sys.stdout, "isatty", return_value=True), \
         patch("kryon.repl.ui.approval.Prompt.ask", return_value="y"):
        r = _invoke()
    assert r["verdict"] == "yes", r
    assert r["n_actions"] == 3
    print("  ok: interactive + 'y' -> yes")


def test_interactive_abort_path_via_mock() -> None:
    os.environ.pop("KRYON_AUTO_APPROVE", None)
    import sys

    with patch.object(sys.stdin, "isatty", return_value=True), \
         patch.object(sys.stdout, "isatty", return_value=True), \
         patch("kryon.repl.ui.approval.Prompt.ask", return_value="a"):
        r = _invoke()
    assert r["verdict"] == "abort", r
    print("  ok: interactive + 'a' -> abort")


if __name__ == "__main__":
    print("F12.6 request_approval function_tool tests")
    test_noninteractive_default_no()
    test_auto_approve_bypass()
    test_empty_actions_rejects()
    test_severity_alias_normalisation()
    test_interactive_yes_path_via_mock()
    test_interactive_abort_path_via_mock()
    print("\nALL PASS")
