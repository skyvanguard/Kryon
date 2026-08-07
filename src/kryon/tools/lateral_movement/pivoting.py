"""
KRYON Network Pivoting Module
===============================

Network pivoting and tunneling tools for lateral movement.
Implements SSH tunnels, port forwarding, and SOCKS proxies.

Primary Users:
- Pentest Agent (Alpha-Red)
- Network Analyst (Alpha-Silver)

Authorization: red-team gated (KRYON_RED_TEAM). Only use within an authorized
penetration-testing scope with written authorization.
"""

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command

# Markers that mean the tool failed (its output is an error, not a result).
_FAIL_MARKERS = (
    "error",
    "failed",
    "denied",
    "not found",
    "no such",
    "traceback",
    "refused",
    "not installed",
    "command not found",
    "usage:",
)


def _exec(cmd_parts: list[str]) -> tuple[bool, str]:
    """Run cmd_parts to completion and return (success, output).

    T4-M10: same str-as-dict fix as remote_execution/pth_attacks — join the whole
    command (``run_command``'s 2nd positional is ``interactive``, not args) and read
    the returned string instead of calling ``.get()`` on it.
    """
    out = run_command(" ".join(cmd_parts))
    low = (out or "").lower()
    ok = bool(out.strip()) and not any(m in low for m in _FAIL_MARKERS)
    return ok, out


def _run_bg(cmd_parts: list[str]) -> tuple[bool, str]:
    """Launch a long-running tunnel/proxy in the background and report whether it
    started. Unlike ``_exec``, EMPTY output means success here (the SSH ``-N`` process
    detaches and prints nothing); only an explicit error marker means it failed to
    bind/connect.
    """
    out = run_command(" ".join(cmd_parts) + " &")
    low = (out or "").lower()
    failed = any(m in low for m in _FAIL_MARKERS)
    return (not failed), out


@function_tool(strict_mode=False)
def setup_ssh_tunnel(
    pivot_host: str,
    pivot_user: str,
    local_port: int,
    remote_host: str,
    remote_port: int,
    pivot_password: str | None = None,
    pivot_key: str | None = None,
) -> str:
    """
    Set up an SSH local port-forward through a pivot/jump host:
    ``localhost:local_port -> remote_host:remote_port`` via ``pivot_user@pivot_host``.

    Args:
        pivot_host: Pivot/jump host
        pivot_user: Username on the pivot host
        local_port: Local port to listen on
        remote_host: Final destination host (reachable from the pivot)
        remote_port: Port on the destination host
        pivot_password: Password for the pivot host (informational; key auth preferred)
        pivot_key: SSH key file for the pivot host

    Returns:
        str: JSON with success, tunnel_command, output, and error.
    """
    result: dict[str, Any] = {"success": False, "tunnel_command": "", "output": "", "error": None}

    cmd_parts = ["ssh", "-N", "-L", f"{local_port}:{remote_host}:{remote_port}"]
    if pivot_key:
        cmd_parts.extend(["-i", pivot_key])
    cmd_parts.append(f"{pivot_user}@{pivot_host}")
    result["tunnel_command"] = " ".join(cmd_parts)

    ok, out = _run_bg(cmd_parts)
    if ok:
        result["success"] = True
        result["output"] = f"SSH tunnel established: localhost:{local_port} -> {remote_host}:{remote_port}"
    else:
        result["error"] = out.strip() or "Tunnel setup failed"
    return json.dumps(result)


@function_tool(strict_mode=False)
def setup_port_forward(
    pivot_host: str,
    pivot_user: str,
    forward_specs: list[dict[str, Any]],
    pivot_key: str | None = None,
) -> str:
    """
    Set up multiple local port-forwards through a pivot host in one SSH session.

    Args:
        pivot_host: Pivot host
        pivot_user: Username
        forward_specs: Forwards, e.g. [{"local": 8080, "remote": "192.168.1.50:80"}]
        pivot_key: SSH key file

    Returns:
        str: JSON with success, forwards, command, and error.
    """
    result: dict[str, Any] = {"success": False, "forwards": [], "command": "", "error": None}

    cmd_parts = ["ssh", "-N"]
    for spec in forward_specs:
        local_port = spec["local"]
        remote = spec["remote"]
        cmd_parts.extend(["-L", f"{local_port}:{remote}"])
        result["forwards"].append(f"localhost:{local_port} -> {remote}")

    if pivot_key:
        cmd_parts.extend(["-i", pivot_key])
    cmd_parts.append(f"{pivot_user}@{pivot_host}")
    result["command"] = " ".join(cmd_parts)

    ok, out = _run_bg(cmd_parts)
    if ok:
        result["success"] = True
    else:
        result["error"] = out.strip() or "Port forward failed"
    return json.dumps(result)


@function_tool(strict_mode=False)
def setup_socks_proxy(
    pivot_host: str,
    pivot_user: str,
    local_port: int = 1080,
    pivot_key: str | None = None,
) -> str:
    """
    Set up a dynamic SOCKS proxy (``ssh -D``) through a pivot host, so the whole
    downstream network is reachable via ``socks5://127.0.0.1:local_port``.

    Returns:
        str: JSON with success, proxy_address, command, output, and error.
    """
    result: dict[str, Any] = {"success": False, "proxy_address": "", "command": "", "output": "", "error": None}

    cmd_parts = ["ssh", "-N", "-D", str(local_port)]
    if pivot_key:
        cmd_parts.extend(["-i", pivot_key])
    cmd_parts.append(f"{pivot_user}@{pivot_host}")
    result["command"] = " ".join(cmd_parts)
    result["proxy_address"] = f"socks5://127.0.0.1:{local_port}"

    ok, out = _run_bg(cmd_parts)
    if ok:
        result["success"] = True
        result["output"] = f"SOCKS proxy listening on 127.0.0.1:{local_port}"
    else:
        result["error"] = out.strip() or "SOCKS proxy failed"
    return json.dumps(result)


@function_tool(strict_mode=False)
def setup_reverse_port_forward(
    pivot_host: str,
    pivot_user: str,
    remote_port: int,
    local_host: str,
    local_port: int,
    pivot_key: str | None = None,
) -> str:
    """
    Set up a reverse port-forward (``ssh -R``): the pivot host opens ``remote_port``
    and forwards it back to ``local_host:local_port`` on the attacker. Useful to pull
    a callback through a host that can reach you but that you cannot reach directly.

    Returns:
        str: JSON with success, command, output, and error.
    """
    result: dict[str, Any] = {"success": False, "command": "", "output": "", "error": None}

    cmd_parts = ["ssh", "-N", "-R", f"{remote_port}:{local_host}:{local_port}"]
    if pivot_key:
        cmd_parts.extend(["-i", pivot_key])
    cmd_parts.append(f"{pivot_user}@{pivot_host}")
    result["command"] = " ".join(cmd_parts)

    ok, out = _run_bg(cmd_parts)
    if ok:
        result["success"] = True
        result["output"] = f"Reverse forward: {pivot_host}:{remote_port} -> {local_host}:{local_port}"
    else:
        result["error"] = out.strip() or "Reverse forward failed"
    return json.dumps(result)


@function_tool(strict_mode=False)
def check_pivot_connectivity(
    pivot_host: str,
    target_host: str,
    target_port: int,
    through_socks: bool = False,
    socks_proxy: str | None = None,
) -> str:
    """
    Check whether a final target is reachable through the pivot — either by running
    ``nc -zv`` on the pivot over SSH, or through an established SOCKS proxy with
    proxychains.

    Returns:
        str: JSON with success, reachable, output, and error.
    """
    result: dict[str, Any] = {"success": False, "reachable": False, "output": "", "error": None}

    if through_socks and socks_proxy:
        cmd_parts = ["proxychains", "-q", "nc", "-zv", target_host, str(target_port)]
    else:
        cmd_parts = ["ssh", pivot_host, f"nc -zv {target_host} {target_port}"]

    ok, out = _exec(cmd_parts)
    result["output"] = out
    if ok:
        result["success"] = True
        if "succeeded" in out or "open" in out:
            result["reachable"] = True
    else:
        # nc prints "succeeded" to stderr and may look like a failure marker; still
        # surface reachability if the success token is present.
        if "succeeded" in out.lower() or " open" in out.lower():
            result["success"] = True
            result["reachable"] = True
        else:
            result["error"] = out.strip() or "Connectivity check failed"
    return json.dumps(result)
