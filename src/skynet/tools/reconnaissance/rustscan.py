"""
Rustscan - Ultra-fast port scanner
===================================

Modern port scanner written in Rust. Much faster than Nmap for
initial discovery, then pipes results to Nmap for service detection.

PERFORMANCE: Results are cached with 4-hour TTL to avoid redundant
port scans and improve response times by 10-30x for repeated scans.
"""

from skynet.cache import cache_scan_result
from skynet.sdk.agents import function_tool
from skynet.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="port_scan", ttl=14400)  # Cache for 4 hours
def rustscan(
    target: str,
    ports: str = "1-65535",
    ulimit: int = 5000,
    batch_size: int = 4500,
    timeout: int = 1500,
    scripts: str = "",
    nmap_args: str = "-sV -sC",
    ctf=None,
) -> str:
    """
    Ultra-fast port scanner with automatic Nmap integration.

    CACHED: Results cached for 4 hours to avoid redundant port scans.
    Expected performance improvement: 10-30x for repeated scans.

    Rustscan quickly scans all ports, then automatically pipes open ports
    to Nmap for service detection and script scanning.

    Args:
        target: Target IP address or hostname to scan
        ports: Port range to scan (default: 1-65535 for full scan)
        ulimit: Maximum number of sockets (default: 5000)
        batch_size: Batch size for port scanning (default: 4500)
        timeout: Timeout in milliseconds (default: 1500)
        scripts: Nmap scripts to run on open ports (e.g., "default,vuln")
        nmap_args: Additional Nmap arguments (default: -sV -sC)
        ctf: CTF context for execution

    Returns:
        str: Scan results showing open ports and service information

    Examples:
        # Fast full port scan with service detection
        rustscan(target="192.168.1.1")

        # Scan specific ports with vulnerability scripts
        rustscan(
            target="10.10.10.5",
            ports="80,443,8080",
            scripts="http-vuln-*"
        )

        # Custom Nmap arguments for detailed scan
        rustscan(
            target="example.com",
            nmap_args="-sV -sC -A -O"
        )
    """
    # Build rustscan command
    cmd_parts = [
        "rustscan",
        f"-a {target}",
        f"-r {ports}",
        f"--ulimit {ulimit}",
        f"-b {batch_size}",
        f"-t {timeout}",
    ]

    # Add Nmap arguments
    if scripts:
        nmap_args = f"{nmap_args} --script {scripts}"

    cmd_parts.append(f"-- {nmap_args}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
