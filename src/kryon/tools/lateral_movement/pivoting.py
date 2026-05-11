"""
KRYON Network Pivoting Module
===============================

Network pivoting and tunneling tools for lateral movement.
Implements SSH tunnels, port forwarding, and SOCKS proxies.

Primary Users:
- Pentest Agent (Alpha-Red)
- Network Analyst (Alpha-Silver)
"""

from typing import Any

from kryon.tools.common import run_command


def setup_ssh_tunnel(
    pivot_host: str,
    pivot_user: str,
    local_port: int,
    remote_host: str,
    remote_port: int,
    pivot_password: str | None = None,
    pivot_key: str | None = None,
) -> dict[str, Any]:
    """
    Setup SSH tunnel for port forwarding.

    Args:
        pivot_host: Pivot/jump host
        pivot_user: Username on pivot host
        local_port: Local port to listen on
        remote_host: Final destination host
        remote_port: Port on destination host
        pivot_password: Password for pivot host
        pivot_key: SSH key file for pivot host

    Returns:
        Dictionary with tunnel setup result

    Example:
        >>> tunnel = setup_ssh_tunnel(
        ...     pivot_host="10.10.10.100",
        ...     pivot_user="user",
        ...     local_port=8080,
        ...     remote_host="192.168.1.50",
        ...     remote_port=80
        ... )
    """
    result = {"success": False, "tunnel_command": "", "pid": None, "error": None}

    try:
        # Build SSH tunnel command
        cmd_parts = ["ssh", "-N", "-L"]
        cmd_parts.append(f"{local_port}:{remote_host}:{remote_port}")

        if pivot_key:
            cmd_parts.extend(["-i", pivot_key])

        cmd_parts.append(f"{pivot_user}@{pivot_host}")

        tunnel_cmd = " ".join(cmd_parts)
        result["tunnel_command"] = tunnel_cmd

        # Execute tunnel in background
        cmd_result = run_command(cmd_parts[0], " ".join(cmd_parts[1:]) + " &")

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = f"SSH tunnel established: localhost:{local_port} -> {remote_host}:{remote_port}"
        else:
            result["error"] = cmd_result.get("error", "Tunnel setup failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def setup_port_forward(
    pivot_host: str,
    pivot_user: str,
    forward_specs: list[dict[str, Any]],
    pivot_key: str | None = None,
) -> dict[str, Any]:
    """
    Setup multiple port forwards through pivot host.

    Args:
        pivot_host: Pivot host
        pivot_user: Username
        forward_specs: List of forward specifications [{"local": 8080, "remote": "192.168.1.50:80"}]
        pivot_key: SSH key file

    Returns:
        Dictionary with port forward result

    Example:
        >>> forwards = setup_port_forward(
        ...     pivot_host="10.10.10.100",
        ...     pivot_user="user",
        ...     forward_specs=[
        ...         {"local": 8080, "remote": "192.168.1.50:80"},
        ...         {"local": 3389, "remote": "192.168.1.51:3389"}
        ...     ]
        ... )
    """
    result = {"success": False, "forwards": [], "command": "", "error": None}

    try:
        cmd_parts = ["ssh", "-N"]

        # Add multiple -L options
        for spec in forward_specs:
            local_port = spec["local"]
            remote = spec["remote"]
            cmd_parts.extend(["-L", f"{local_port}:{remote}"])
            result["forwards"].append(f"localhost:{local_port} -> {remote}")

        if pivot_key:
            cmd_parts.extend(["-i", pivot_key])

        cmd_parts.append(f"{pivot_user}@{pivot_host}")

        result["command"] = " ".join(cmd_parts)

        cmd_result = run_command(cmd_parts[0], " ".join(cmd_parts[1:]) + " &")

        if cmd_result.get("success"):
            result["success"] = True
        else:
            result["error"] = cmd_result.get("error", "Port forward failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def setup_socks_proxy(
    pivot_host: str,
    pivot_user: str,
    local_port: int = 1080,
    pivot_key: str | None = None,
) -> dict[str, Any]:
    """
    Setup SOCKS proxy through pivot host.

    Args:
        pivot_host: Pivot host
        pivot_user: Username
        local_port: Local SOCKS proxy port
        pivot_key: SSH key file

    Returns:
        Dictionary with SOCKS proxy result

    Example:
        >>> proxy = setup_socks_proxy(
        ...     pivot_host="10.10.10.100",
        ...     pivot_user="user",
        ...     local_port=1080
        ... )
    """
    result = {"success": False, "proxy_address": "", "command": "", "error": None}

    try:
        cmd_parts = ["ssh", "-N", "-D", str(local_port)]

        if pivot_key:
            cmd_parts.extend(["-i", pivot_key])

        cmd_parts.append(f"{pivot_user}@{pivot_host}")

        result["command"] = " ".join(cmd_parts)
        result["proxy_address"] = f"socks5://127.0.0.1:{local_port}"

        cmd_result = run_command(cmd_parts[0], " ".join(cmd_parts[1:]) + " &")

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = f"SOCKS proxy listening on 127.0.0.1:{local_port}"
        else:
            result["error"] = cmd_result.get("error", "SOCKS proxy failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def setup_reverse_port_forward(
    pivot_host: str,
    pivot_user: str,
    remote_port: int,
    local_host: str,
    local_port: int,
    pivot_key: str | None = None,
) -> dict[str, Any]:
    """
    Setup reverse port forward (pivot host forwards to attacker).

    Args:
        pivot_host: Pivot host
        pivot_user: Username
        remote_port: Port to open on pivot host
        local_host: Attacker host
        local_port: Port on attacker host
        pivot_key: SSH key file

    Returns:
        Dictionary with reverse forward result

    Example:
        >>> reverse = setup_reverse_port_forward(
        ...     pivot_host="10.10.10.100",
        ...     pivot_user="user",
        ...     remote_port=4444,
        ...     local_host="10.10.14.5",
        ...     local_port=4444
        ... )
    """
    result = {"success": False, "command": "", "error": None}

    try:
        cmd_parts = ["ssh", "-N", "-R"]
        cmd_parts.append(f"{remote_port}:{local_host}:{local_port}")

        if pivot_key:
            cmd_parts.extend(["-i", pivot_key])

        cmd_parts.append(f"{pivot_user}@{pivot_host}")

        result["command"] = " ".join(cmd_parts)

        cmd_result = run_command(cmd_parts[0], " ".join(cmd_parts[1:]) + " &")

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = f"Reverse forward: {pivot_host}:{remote_port} -> {local_host}:{local_port}"
        else:
            result["error"] = cmd_result.get("error", "Reverse forward failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def check_pivot_connectivity(
    pivot_host: str,
    target_host: str,
    target_port: int,
    through_socks: bool = False,
    socks_proxy: str | None = None,
) -> dict[str, Any]:
    """
    Check connectivity to target through pivot.

    Args:
        pivot_host: Pivot host
        target_host: Final target host
        target_port: Port on target
        through_socks: Use SOCKS proxy for test
        socks_proxy: SOCKS proxy address (e.g., "127.0.0.1:1080")

    Returns:
        Dictionary with connectivity test result

    Example:
        >>> connectivity = check_pivot_connectivity(
        ...     pivot_host="10.10.10.100",
        ...     target_host="192.168.1.50",
        ...     target_port=445
        ... )
    """
    result = {"success": False, "reachable": False, "error": None}

    try:
        if through_socks and socks_proxy:
            # Use proxychains or similar
            cmd_parts = ["proxychains", "-q", "nc", "-zv", target_host, str(target_port)]
        else:
            # Direct SSH command execution through pivot
            cmd_parts = ["ssh", pivot_host, f"nc -zv {target_host} {target_port}"]

        cmd_result = run_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            if "succeeded" in output or "open" in output:
                result["reachable"] = True
            result["success"] = True
        else:
            result["error"] = cmd_result.get("error", "Connectivity check failed")

    except Exception as e:
        result["error"] = str(e)

    return result
