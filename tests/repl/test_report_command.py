"""Contract for the /report REPL command (Workstream C — deliverable)."""

from __future__ import annotations

from kryon.repl.commands import report as report_mod


def test_command_is_registered() -> None:
    from kryon.repl.commands.base import get_command

    cmd = get_command("report")
    assert cmd is not None
    # Alias resolves too.
    assert get_command("reporte") is cmd


def test_parse_flags_defaults_and_overrides() -> None:
    assert report_mod._parse_flags(None) == {
        "type": "technical",
        "format": "pdf",
        "client": "",
        "scope": "",
    }
    opts = report_mod._parse_flags(["--type", "executive", "--format", "html", "--client", "Example"])
    assert opts["type"] == "executive"
    assert opts["format"] == "html"
    assert opts["client"] == "Example"


def test_no_findings_is_handled(monkeypatch) -> None:
    # With no persisted findings, the command must return True (handled) without
    # trying to generate a report.
    monkeypatch.setattr(report_mod, "_load_findings", lambda: [])
    assert report_mod.handle_report([]) is True


def test_load_findings_dedups_by_signature(monkeypatch) -> None:
    from types import SimpleNamespace

    from kryon.intelligence.models import Finding, Severity

    def _rec(title, asset, sev):
        f = Finding(title=title, description="d", severity=sev, affected_asset=asset)
        return SimpleNamespace(finding_json=f.model_dump_json())

    dup_a = _rec("SPF missing", "example.com", Severity.MEDIUM)
    dup_b = _rec("SPF missing", "example.com", Severity.MEDIUM)  # same content, saved twice
    other = _rec("XSS", "example.com", Severity.HIGH)

    class _Store:
        def list_all_findings(self, **kw):
            return [dup_a, dup_b, other]

    monkeypatch.setattr(report_mod, "_get_store", lambda: _Store())
    loaded = report_mod._load_findings()
    titles = sorted(f.title for f in loaded)
    assert titles == ["SPF missing", "XSS"]  # the duplicate SPF collapsed to one


def test_handle_uses_report_handler(monkeypatch) -> None:
    called = {}
    monkeypatch.setattr(report_mod, "handle_report", lambda args=None: called.setdefault("ran", True) or True)
    assert report_mod.report_cmd.handle(["--type", "technical"]) is True
    assert called.get("ran") is True
