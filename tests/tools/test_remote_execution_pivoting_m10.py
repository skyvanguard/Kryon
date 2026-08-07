"""T4-M10: remote_execution + pivoting were defined but never @function_tool and
never registered — and every call hit the str-as-dict bug (run_command's 2nd
positional is `interactive`, not args; then `.get()` on the returned STRING raised
AttributeError, swallowed by the except → fake failure on every invocation).

They must now (a) run the full command and interpret its string output, (b) be
@function_tool objects, and (c) register under KRYON_RED_TEAM."""

from __future__ import annotations

import json
import os

os.environ.setdefault("KRYON_RED_TEAM", "true")  # package is red-team gated
os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

from kryon.tools.lateral_movement import pivoting, remote_execution  # noqa: E402, I001


# --- str-as-dict regression: the whole command runs, no AttributeError -----


def test_remote_exec_helper_runs_full_command(monkeypatch):
    captured = {}

    def fake_run_command(cmd, *a, **kw):
        captured["cmd"] = cmd
        captured["extra"] = (a, kw)
        return "nt authority\\system"

    monkeypatch.setattr(remote_execution, "run_command", fake_run_command)
    ok, out = remote_execution._exec(["psexec.py", "CORP/admin@10.0.0.5", "-hashes", "H", "whoami"])
    assert captured["cmd"] == "psexec.py CORP/admin@10.0.0.5 -hashes H whoami"
    assert captured["extra"] == ((), {})  # nothing lands in the interactive/ctf slot
    assert ok is True
    assert "system" in out


def test_psexec_reports_success_no_attributeerror(monkeypatch):
    monkeypatch.setattr(remote_execution, "run_command", lambda cmd: "nt authority\\system")
    res = remote_execution.psexec_execute._raw_fn(
        target="10.0.0.5", username="admin", ntlm_hash="aad3b435:31d6cfe0", command="whoami"
    )
    d = json.loads(res)
    assert d["success"] is True
    assert "system" in d["output"]
    assert "str" not in (d.get("error") or "")  # not the old AttributeError text


def test_psexec_requires_credentials():
    res = remote_execution.psexec_execute._raw_fn(target="10.0.0.5", username="admin")
    d = json.loads(res)
    assert d["success"] is False
    assert "hash" in d["error"].lower()


def test_remote_exec_detects_error_output(monkeypatch):
    monkeypatch.setattr(remote_execution, "run_command", lambda cmd: "ERROR: connection refused")
    res = remote_execution.ssh_execute._raw_fn(target="10.0.0.5", username="root", command="id")
    d = json.loads(res)
    assert d["success"] is False


# --- pivoting: background tunnels succeed on empty output ------------------


def test_socks_proxy_succeeds_on_empty_bg_output(monkeypatch):
    # ssh -N -D detaches and prints nothing → that's success for a tunnel.
    monkeypatch.setattr(pivoting, "run_command", lambda cmd: "")
    res = pivoting.setup_socks_proxy._raw_fn(pivot_host="10.10.10.5", pivot_user="user", local_port=1080)
    d = json.loads(res)
    assert d["success"] is True
    assert d["proxy_address"] == "socks5://127.0.0.1:1080"


def test_ssh_tunnel_fails_on_error_marker(monkeypatch):
    monkeypatch.setattr(
        pivoting, "run_command", lambda cmd: "ssh: connect to host 10.10.10.5 port 22: Connection refused"
    )
    res = pivoting.setup_ssh_tunnel._raw_fn(
        pivot_host="10.10.10.5", pivot_user="user", local_port=8080, remote_host="192.168.1.50", remote_port=80
    )
    d = json.loads(res)
    assert d["success"] is False
    assert "refused" in d["error"].lower()


def test_check_pivot_connectivity_reports_reachable(monkeypatch):
    monkeypatch.setattr(pivoting, "run_command", lambda cmd: "Connection to 192.168.1.50 445 port [tcp/*] succeeded!")
    res = pivoting.check_pivot_connectivity._raw_fn(
        pivot_host="10.10.10.5", target_host="192.168.1.50", target_port=445
    )
    d = json.loads(res)
    assert d["reachable"] is True


# --- function_tool shape + registry ---------------------------------------


def test_all_are_function_tools():
    for mod, names in (
        (
            remote_execution,
            (
                "psexec_execute",
                "wmiexec_execute",
                "smbexec_execute",
                "dcomexec_execute",
                "ssh_execute",
                "winrm_execute",
            ),
        ),
        (
            pivoting,
            (
                "setup_ssh_tunnel",
                "setup_port_forward",
                "setup_socks_proxy",
                "setup_reverse_port_forward",
                "check_pivot_connectivity",
            ),
        ),
    ):
        for name in names:
            obj = getattr(mod, name)
            assert hasattr(obj, "name"), f"{name} is not a function_tool"
            assert hasattr(obj, "params_json_schema"), f"{name} missing schema"
            assert hasattr(obj, "_raw_fn"), f"{name} missing raw callable"


def test_registered_under_red_team(monkeypatch):
    monkeypatch.setenv("KRYON_RED_TEAM", "true")
    import importlib

    import kryon.skills.tool_budget as tb

    importlib.reload(tb)
    registry = tb.build_tool_registry()
    assert "psexec_execute" in registry
    assert "setup_socks_proxy" in registry


def test_absent_without_red_team(monkeypatch):
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    import importlib

    import kryon.skills.tool_budget as tb

    importlib.reload(tb)
    registry = tb.build_tool_registry()
    assert "psexec_execute" not in registry
    assert "setup_socks_proxy" not in registry
