"""F196 — `kryon queue process` drains the queue by invoking engage per item.

Banca-safe defaults: concurrency 1, no auto-retry. Items that fail
stay in `failed` status for operator triage.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.queue_cmd import (
    _build_engage_argv,
    _process_queue,
    _resolve_engage_bin,
    _run_one,
)
from kryon.queue import EngagementQueue


def test_run_one_timeout_kills_child_and_reports_124(monkeypatch):
    """A wedged `kryon engage` child must be killed at the wall timeout, not hang
    the worker (and thus the parallel pool's __exit__). _run_one returns exit 124
    and forwards the budget to subprocess.run."""
    import kryon.cli.queue_cmd as qc

    def _fake_run(argv, **kwargs):
        assert kwargs.get("timeout") == 5  # budget forwarded to the child
        raise subprocess.TimeoutExpired(cmd=argv, timeout=5)

    monkeypatch.setattr(qc.subprocess, "run", _fake_run)
    iid, rc, err = _run_one(["kryon", "engage"], "item-1", timeout=5)
    assert iid == "item-1"
    assert rc == 124
    assert "timed out" in err


def test_run_one_forwards_timeout_on_success(monkeypatch):
    """The per-item timeout reaches subprocess.run on the happy path too."""
    import kryon.cli.queue_cmd as qc

    captured: dict = {}

    class _Proc:
        returncode = 0
        stderr = ""

    def _fake_run(argv, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        return _Proc()

    monkeypatch.setattr(qc.subprocess, "run", _fake_run)
    iid, rc, _ = _run_one(["x"], "i", timeout=3600)
    assert captured["timeout"] == 3600
    assert rc == 0


@pytest.fixture
def isolated_queue(tmp_path, monkeypatch):
    """Point KRYON_QUEUE_PATH at a tmp file so the test doesn't touch
    the real .kryon/queue.json."""
    qpath = tmp_path / "queue.json"
    monkeypatch.setenv("KRYON_QUEUE_PATH", str(qpath))
    return qpath


def _make_args(**overrides) -> argparse.Namespace:
    """Minimal args namespace for _process_queue."""
    defaults = {
        "queue_action": "process",
        "concurrency": 1,
        "limit": 0,
        "framework": "",
        "orchestrated": False,
        "auto_approve": False,
        "dry_run_only": False,
        "out": "",
        "client": "",
        "ssh_key": "",
        "engage_bin": "",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# _resolve_engage_bin
# ---------------------------------------------------------------------------


class TestResolveEngageBin:
    def test_explicit_wins(self, monkeypatch):
        monkeypatch.setenv("KRYON_ENGAGE_BIN", "from-env")
        assert _resolve_engage_bin("uv run kryon") == ["uv", "run", "kryon"]

    def test_env_used_when_no_explicit(self, monkeypatch):
        monkeypatch.setenv("KRYON_ENGAGE_BIN", "python -m kryon")
        assert _resolve_engage_bin("") == ["python", "-m", "kryon"]

    def test_default_falls_back_to_kryon(self, monkeypatch):
        monkeypatch.delenv("KRYON_ENGAGE_BIN", raising=False)
        assert _resolve_engage_bin("") == ["kryon"]


# ---------------------------------------------------------------------------
# _build_engage_argv
# ---------------------------------------------------------------------------


class TestBuildEngageArgv:
    def test_minimal_argv(self):
        argv = _build_engage_argv(
            engage_bin=["kryon"],
            target="10.0.0.5",
            objective="",
            framework="",
            orchestrated=False,
            auto_approve=False,
            dry_run_only=False,
            out_dir="",
            client="",
            ssh_key="",
            item_id="abc123",
        )
        assert argv[0] == "kryon"
        assert argv[1] == "engage"
        assert argv[2] == "10.0.0.5"
        assert "--engagement-id" in argv
        assert "abc123" in argv

    def test_framework_passed_through(self):
        argv = _build_engage_argv(
            engage_bin=["kryon"],
            target="10.0.0.5",
            objective="",
            framework="pci_dss,bcp_py",
            orchestrated=False,
            auto_approve=False,
            dry_run_only=False,
            out_dir="",
            client="",
            ssh_key="",
            item_id="abc123",
        )
        idx = argv.index("--framework")
        assert argv[idx + 1] == "pci_dss,bcp_py"

    def test_orchestrated_auto_approve_flags(self):
        argv = _build_engage_argv(
            engage_bin=["kryon"],
            target="10.0.0.5",
            objective="",
            framework="",
            orchestrated=True,
            auto_approve=True,
            dry_run_only=False,
            out_dir="",
            client="",
            ssh_key="",
            item_id="abc123",
        )
        assert "--orchestrated" in argv
        assert "--auto-approve" in argv

    def test_out_dir_namespaced_by_item_id(self):
        argv = _build_engage_argv(
            engage_bin=["kryon"],
            target="10.0.0.5",
            objective="",
            framework="",
            orchestrated=False,
            auto_approve=False,
            dry_run_only=False,
            out_dir="/tmp/reports",
            client="",
            ssh_key="",
            item_id="abc123",
        )
        idx = argv.index("--out")
        assert argv[idx + 1] == os.path.join("/tmp/reports", "abc123")


# ---------------------------------------------------------------------------
# _process_queue — serial (concurrency=1)
# ---------------------------------------------------------------------------


class TestProcessQueueSerial:
    def test_empty_queue_returns_zero(self, isolated_queue, capsys):
        # No items queued.
        rc = _process_queue(_make_args())
        captured = capsys.readouterr()
        assert rc == 0
        assert "no pending items" in captured.out

    def test_drains_all_pending_serial(self, isolated_queue, monkeypatch, capsys):
        q = EngagementQueue.load()
        q.add("10.0.0.5")
        q.add("10.0.0.6")
        q.add("10.0.0.7")
        q.save()

        captured_argvs: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            captured_argvs.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr("kryon.cli.queue_cmd.subprocess.run", fake_run)

        rc = _process_queue(_make_args())
        assert rc == 0
        assert len(captured_argvs) == 3
        # All three targets were invoked.
        targets_seen = {argv[2] for argv in captured_argvs}
        assert targets_seen == {"10.0.0.5", "10.0.0.6", "10.0.0.7"}

        # Queue state reflects success.
        q2 = EngagementQueue.load()
        assert all(i.status == "completed" for i in q2.items)

    def test_failed_engage_marks_item_failed_and_continues(self, isolated_queue, monkeypatch):
        q = EngagementQueue.load()
        q.add("10.0.0.5")  # will fail
        q.add("10.0.0.6")  # will succeed
        q.save()

        def fake_run(argv, **_kwargs):
            target = argv[2]
            rc = 1 if target == "10.0.0.5" else 0
            return subprocess.CompletedProcess(argv, rc, stdout="", stderr="boom" if rc else "")

        monkeypatch.setattr("kryon.cli.queue_cmd.subprocess.run", fake_run)

        rc = _process_queue(_make_args())
        # Aggregate exit is non-zero when any item failed.
        assert rc == 1

        q2 = EngagementQueue.load()
        by_target = {i.target: i for i in q2.items}
        assert by_target["10.0.0.5"].status == "failed"
        assert by_target["10.0.0.6"].status == "completed"
        assert "boom" in by_target["10.0.0.5"].error

    def test_limit_respected(self, isolated_queue, monkeypatch):
        q = EngagementQueue.load()
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"):
            q.add(ip)
        q.save()

        invocations: list[str] = []

        def fake_run(argv, **_kwargs):
            invocations.append(argv[2])
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr("kryon.cli.queue_cmd.subprocess.run", fake_run)

        rc = _process_queue(_make_args(limit=2))
        assert rc == 0
        assert len(invocations) == 2

        # The other two are still pending.
        q2 = EngagementQueue.load()
        pending_after = [i for i in q2.items if i.status == "pending"]
        assert len(pending_after) == 2

    def test_priority_order_serial(self, isolated_queue, monkeypatch):
        q = EngagementQueue.load()
        q.add("10.0.0.1", priority=50)
        q.add("10.0.0.2", priority=10)  # highest priority
        q.add("10.0.0.3", priority=30)
        q.save()

        order: list[str] = []

        def fake_run(argv, **_kwargs):
            order.append(argv[2])
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr("kryon.cli.queue_cmd.subprocess.run", fake_run)

        _process_queue(_make_args())
        # Lowest priority number = first run.
        assert order == ["10.0.0.2", "10.0.0.3", "10.0.0.1"]


# ---------------------------------------------------------------------------
# _process_queue — parallel (concurrency>1)
# ---------------------------------------------------------------------------


class TestProcessQueueParallel:
    def test_parallel_drains_all(self, isolated_queue, monkeypatch):
        q = EngagementQueue.load()
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"):
            q.add(ip)
        q.save()

        invocations: list[str] = []

        def fake_run(argv, **_kwargs):
            invocations.append(argv[2])
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr("kryon.cli.queue_cmd.subprocess.run", fake_run)

        rc = _process_queue(_make_args(concurrency=2))
        assert rc == 0
        assert sorted(invocations) == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]

        q2 = EngagementQueue.load()
        assert all(i.status == "completed" for i in q2.items)
