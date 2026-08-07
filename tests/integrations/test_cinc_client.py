"""Cinc Auditor client — cinc_cmd builder + run_profile (injected runner)."""

from __future__ import annotations

import subprocess
import types

import pytest

from kryon.integrations.cinc import client as C
from kryon.integrations.cinc.client import CincError, cinc_cmd, run_profile

_JSON = '{"profiles":[{"name":"p","controls":[]}]}'


def _proc(returncode: int, stdout: str = "", stderr: str = ""):
    def runner(*_a, **_k):
        return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    return runner


def test_cinc_cmd_builds_json_exec():
    argv = cinc_cmd("https://github.com/dev-sec/ssh-baseline", "ssh://root@10.0.0.5", ["--port", "2222"])
    assert argv[:2] == ["cinc-auditor", "exec"]
    assert "https://github.com/dev-sec/ssh-baseline" in argv
    assert "-t" in argv and "ssh://root@10.0.0.5" in argv
    assert argv[argv.index("--reporter") + 1] == "json"
    assert "--port" in argv and "2222" in argv


def test_run_profile_returns_json_on_success():
    out = run_profile("p", "local://", runner=_proc(0, _JSON))
    assert out == _JSON


def test_run_profile_returns_json_on_failures_exit_100():
    # exit 100 = controls failed — normal, JSON still on stdout.
    out = run_profile("p", "local://", runner=_proc(100, _JSON))
    assert out == _JSON


def test_run_profile_no_json_raises():
    with pytest.raises(CincError, match="no JSON"):
        run_profile("p", "local://", runner=_proc(1, "", "boom"))


def test_run_profile_binary_missing_raises(monkeypatch):
    def runner(*_a, **_k):
        raise FileNotFoundError("cinc-auditor")

    with pytest.raises(CincError, match="not found"):
        run_profile("p", "local://", runner=runner)


def test_run_profile_timeout_raises():
    def runner(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="cinc-auditor", timeout=1)

    with pytest.raises(CincError, match="timed out"):
        run_profile("p", "local://", runner=runner)
