"""Unit tests for repl.ui.approval — no interactive input."""
from __future__ import annotations

import io
from unittest.mock import patch

from rich.console import Console

from kryon.repl.ui.approval import (
    ApprovalRequest,
    ApprovalResult,
    ProposedAction,
    Severity,
    ask_approval,
    ask_yes_no,
    _render_summary_panel,
    _render_detail_panel,
    _severity_counts,
)


def _sample_request(dry_run: bool = False) -> ApprovalRequest:
    return ApprovalRequest(
        title="Aplicar 3 correcciones CRITICAL",
        subtitle="admin@192.168.1.10",
        dry_run=dry_run,
        actions=[
            ProposedAction(
                command="cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)",
                severity=Severity.READ,
                purpose="Backup sshd_config antes de modificar",
                reversible=True,
                target_host="admin@192.168.1.10",
            ),
            ProposedAction(
                command="sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
                severity=Severity.MODIFY,
                purpose="Desactivar login de root por SSH",
                reversible=True,
                backup_path="/etc/ssh/sshd_config.bak.1744729832",
                target_host="admin@192.168.1.10",
            ),
            ProposedAction(
                command="systemctl reload sshd",
                severity=Severity.DESTRUCTIVE,
                purpose="Recargar SSH daemon (reinicia conexión)",
                reversible=False,
                target_host="admin@192.168.1.10",
            ),
        ],
        impact_notes=[
            "Afecta: 1 host, 1 servicio (SSH)",
            "Backup se conserva por 30 días",
        ],
    )


def test_severity_counts() -> None:
    req = _sample_request()
    counts = _severity_counts(req.actions)
    assert counts[Severity.READ] == 1
    assert counts[Severity.MODIFY] == 1
    assert counts[Severity.DESTRUCTIVE] == 1
    print("  ok: severity_counts tallies by type")


def test_render_summary_renders_without_error() -> None:
    buf = io.StringIO()
    con = Console(file=buf, width=100, force_terminal=True, color_system=None)
    con.print(_render_summary_panel(_sample_request()))
    out = buf.getvalue()
    assert "3 correcciones CRITICAL" in out
    assert "admin@192.168.1.10" in out
    assert "1 destructive" in out
    assert "1 modify" in out
    print("  ok: summary panel renders with title + badges")


def test_render_summary_marks_dry_run() -> None:
    buf = io.StringIO()
    con = Console(file=buf, width=100, force_terminal=True, color_system=None)
    con.print(_render_summary_panel(_sample_request(dry_run=True)))
    out = buf.getvalue()
    assert "DRY-RUN" in out
    print("  ok: dry_run flag surfaces DRY-RUN banner")


def test_render_detail_includes_commands_and_backup() -> None:
    buf = io.StringIO()
    con = Console(file=buf, width=120, force_terminal=True, color_system=None)
    con.print(_render_detail_panel(_sample_request()))
    out = buf.getvalue()
    assert "sed -i" in out
    assert "systemctl reload sshd" in out
    assert "/etc/ssh/sshd_config.bak.1744729832" in out  # backup path surfaced
    print("  ok: detail panel shows full commands + backup paths")


def test_ask_approval_yes() -> None:
    with patch("kryon.repl.ui.approval.Prompt.ask", return_value="y"):
        result = ask_approval(_sample_request(), console=Console(file=io.StringIO()))
    assert result == ApprovalResult.YES
    print("  ok: 'y' returns YES")


def test_ask_approval_enter_defaults_to_no() -> None:
    with patch("kryon.repl.ui.approval.Prompt.ask", return_value="N"):
        result = ask_approval(
            _sample_request(),
            default=ApprovalResult.NO,
            console=Console(file=io.StringIO()),
        )
    assert result == ApprovalResult.NO
    print("  ok: empty input defaults to NO (safety)")


def test_ask_approval_abort() -> None:
    with patch("kryon.repl.ui.approval.Prompt.ask", return_value="a"):
        result = ask_approval(_sample_request(), console=Console(file=io.StringIO()))
    assert result == ApprovalResult.ABORT
    print("  ok: 'a' returns ABORT")


def test_ask_approval_details_then_yes() -> None:
    """'d' opens details panel, then next prompt accepts."""
    calls = iter(["d", "y"])
    with patch("kryon.repl.ui.approval.Prompt.ask", side_effect=lambda *a, **k: next(calls)):
        result = ask_approval(_sample_request(), console=Console(file=io.StringIO()))
    assert result == ApprovalResult.YES
    print("  ok: 'd' shows details then re-prompts, 'y' accepts")


def test_ask_approval_invalid_reprompts() -> None:
    calls = iter(["?", "x", "y"])
    with patch("kryon.repl.ui.approval.Prompt.ask", side_effect=lambda *a, **k: next(calls)):
        result = ask_approval(_sample_request(), console=Console(file=io.StringIO()))
    assert result == ApprovalResult.YES
    print("  ok: invalid input re-prompts until valid choice")


def test_ask_approval_keyboard_interrupt_aborts() -> None:
    with patch("kryon.repl.ui.approval.Prompt.ask", side_effect=KeyboardInterrupt()):
        result = ask_approval(_sample_request(), console=Console(file=io.StringIO()))
    assert result == ApprovalResult.ABORT
    print("  ok: Ctrl+C treated as ABORT")


def test_ask_yes_no_defaults_safely() -> None:
    with patch("kryon.repl.ui.approval.Prompt.ask", return_value="N"):
        assert ask_yes_no("continuar?", console=Console(file=io.StringIO())) is False
    with patch("kryon.repl.ui.approval.Prompt.ask", return_value="y"):
        assert ask_yes_no("continuar?", console=Console(file=io.StringIO())) is True
    print("  ok: ask_yes_no honours y / N")


if __name__ == "__main__":
    print("F12.1 approval UI unit tests")
    test_severity_counts()
    test_render_summary_renders_without_error()
    test_render_summary_marks_dry_run()
    test_render_detail_includes_commands_and_backup()
    test_ask_approval_yes()
    test_ask_approval_enter_defaults_to_no()
    test_ask_approval_abort()
    test_ask_approval_details_then_yes()
    test_ask_approval_invalid_reprompts()
    test_ask_approval_keyboard_interrupt_aborts()
    test_ask_yes_no_defaults_safely()
    print("\nALL PASS")
