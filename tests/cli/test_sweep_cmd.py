"""Tests for the one-command multi-host sweep (F1.2)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import kryon.discovery as discovery
from kryon.cli import queue_cmd, sweep_cmd


def _args(**kw):
    base = dict(
        subnet="10.0.0.0/30",
        framework="",
        client="banco_x",
        out="",
        orchestrated=False,
        auto_approve=False,
        ssh_key="",
        engage_bin="",
        format="csv",
        limit=0,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _fake_engage_writer(out_root: Path):
    """Return a fake _run_one that writes a findings.json like real engage."""

    def _run_one(argv, item_id, timeout=None):
        # argv carries ["--out", "<out_root>/<item_id>"] and ["--engagement-id", item_id]
        out_dir = Path(argv[argv.index("--out") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"kryon-{item_id}.findings.json").write_text(
            json.dumps(
                {
                    "context": {"target_scope": item_id, "engagement_id": item_id},
                    "findings": [
                        {
                            "rule_id": "R1",
                            "severity": "high",
                            "message": "issue",
                            "cwe": "CWE-1",
                            "host": item_id,
                            "remediation": "fix",
                            "evidence": "ev",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return item_id, 0, ""

    return _run_one


def test_sweep_discovers_audits_and_consolidates(tmp_path, monkeypatch, capsys):
    out_root = tmp_path / "out"
    monkeypatch.setattr("kryon.reporting.findings_export._REPORTS_DIR", tmp_path / "reports")
    # Two live hosts discovered.
    monkeypatch.setattr(discovery, "discover_subnet", lambda subnet: ["asset-a", "asset-b"])
    monkeypatch.setattr(
        discovery,
        "merge_assets",
        lambda a, b: SimpleNamespace(to_targets=lambda: ["10.0.0.1", "10.0.0.2"]),
    )
    monkeypatch.setattr(queue_cmd, "_run_one", _fake_engage_writer(out_root))

    rc = sweep_cmd.run_sweep_command(_args(out=str(out_root)))
    assert rc == 0
    # Consolidated deliverable exists and aggregates both hosts.
    summary = json.loads((out_root / "segment-summary.json").read_text(encoding="utf-8"))
    assert summary["host_count"] == 2
    assert summary["total_findings"] == 2
    out = capsys.readouterr().out
    assert "consolidated:" in out


def test_sweep_no_hosts_returns_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery, "discover_subnet", lambda subnet: [])
    monkeypatch.setattr(discovery, "merge_assets", lambda a, b: SimpleNamespace(to_targets=lambda: []))
    rc = sweep_cmd.run_sweep_command(_args(out=str(tmp_path / "out")))
    assert rc == 0


def test_sweep_respects_limit(tmp_path, monkeypatch):
    out_root = tmp_path / "out"
    monkeypatch.setattr("kryon.reporting.findings_export._REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(discovery, "discover_subnet", lambda subnet: ["a", "b", "c"])
    monkeypatch.setattr(
        discovery,
        "merge_assets",
        lambda a, b: SimpleNamespace(to_targets=lambda: ["h1", "h2", "h3"]),
    )
    calls = []

    def _counting(argv, item_id, timeout=None):
        calls.append(item_id)
        return _fake_engage_writer(out_root)(argv, item_id)

    monkeypatch.setattr(queue_cmd, "_run_one", _counting)
    sweep_cmd.run_sweep_command(_args(out=str(out_root), limit=2))
    assert len(calls) == 2
