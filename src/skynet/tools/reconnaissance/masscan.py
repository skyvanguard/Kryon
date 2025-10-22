"""
Masscan - Mass IP port scanner
===============================

Masscan is the fastest port scanner, capable of scanning the entire
Internet in under 6 minutes. Ideal for large-scale reconnaissance.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def masscan_scan(
    target: str,
    ports: str = "0-65535",
    rate: int = 10000,
    output_format: str = "list",
    exclude_ports: str = "",
    interface: str = "",
    router_mac: str = "",
    top_ports: int = 0,
    ctf=None
) -> str:
    """
    Ultra-fast mass port scanner for large-scale reconnaissance.

    Masscan can scan thousands of IPs in seconds. Use with caution
    on production networks - high scan rates can cause network issues.

    Args:
        target: Target IP/range (e.g., 192.168.1.0/24, 10.0.0.1-254)
        ports: Ports to scan (default: 0-65535)
        rate: Packets per second (default: 10000, max: 25000000)
        output_format: Output format: list, json, xml, grepable
        exclude_ports: Ports to exclude from scan
        interface: Network interface to use
        router_mac: Router MAC address for raw sockets
        top_ports: Scan only top N most common ports
        ctf: CTF context for execution

    Returns:
        str: Scan results showing open ports

    Examples:
        # Fast scan of common ports
        masscan_scan(
            target="192.168.1.0/24",
            top_ports=100,
            rate=5000
        )

        # Full scan of single host
        masscan_scan(
            target="10.10.10.5",
            ports="1-65535",
            rate=50000
        )

        # Scan web ports on /16 network
        masscan_scan(
            target="172.16.0.0/16",
            ports="80,443,8000,8080,8443",
            rate=100000,
            output_format="json"
        )

    Security Note:
        High scan rates can overwhelm networks. Start with lower rates
        (1000-10000) and increase gradually. Always ensure you have
        permission to scan the target network.
    """
    # Build masscan command
    cmd_parts = ["masscan", target, f"-p{ports}", f"--rate {rate}"]

    # Add optional parameters
    if top_ports > 0:
        cmd_parts = ["masscan", target, f"--top-ports {top_ports}", f"--rate {rate}"]

    if exclude_ports:
        cmd_parts.append(f"--exclude-ports {exclude_ports}")

    if interface:
        cmd_parts.append(f"-e {interface}")

    if router_mac:
        cmd_parts.append(f"--router-mac {router_mac}")

    # Output format
    if output_format == "json":
        cmd_parts.append("-oJ -")
    elif output_format == "xml":
        cmd_parts.append("-oX -")
    elif output_format == "grepable":
        cmd_parts.append("-oG -")
    else:
        cmd_parts.append("-oL -")

    # Add open ports only flag
    cmd_parts.append("--open")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
