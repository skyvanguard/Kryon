"""
Volatility - Memory Forensics Framework
========================================

Volatility is an advanced memory forensics framework for incident response
and malware analysis. Extracts digital artifacts from RAM dumps.

PERFORMANCE: Memory forensics is NOT cached as each analysis is unique
to specific memory dumps and investigation contexts.
"""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def volatility_process_list(memory_dump: str, profile: str = "", output_format: str = "text", ctf=None) -> str:
    """
    List running processes from memory dump.

    Args:
        memory_dump: Path to memory dump file
        profile: Memory profile (Win7SP1x64, LinuxUbuntu, etc.)
        output_format: Output format (text, json, csv)
        ctf: CTF context

    Returns:
        str: Process list with PIDs, names, and timestamps

    Examples:
        # List processes
        volatility_process_list(memory_dump="/dumps/memory.raw")

        # Specific profile
        volatility_process_list(
            memory_dump="/dumps/win10.raw",
            profile="Win10x64_19041"
        )
    """
    cmd_parts = ["vol", "-f", memory_dump]

    if profile:
        cmd_parts.extend(["--profile", profile])

    cmd_parts.append("windows.pslist" if "Win" in profile else "linux.pslist")

    if output_format != "text":
        cmd_parts.extend(["--output", output_format])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def volatility_network_connections(memory_dump: str, profile: str = "", ctf=None) -> str:
    """
    Extract network connections from memory.

    Args:
        memory_dump: Path to memory dump
        profile: Memory profile
        ctf: CTF context

    Returns:
        str: Network connections (IP, ports, PIDs)

    Examples:
        # Find network activity
        volatility_network_connections(
            memory_dump="/dumps/incident.raw",
            profile="Win10x64"
        )
    """
    cmd_parts = ["vol", "-f", memory_dump]

    if profile:
        cmd_parts.extend(["--profile", profile])

    cmd_parts.append("windows.netscan")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def volatility_dump_process(
    memory_dump: str, pid: int, output_dir: str = "/tmp/volatility", profile: str = "", ctf=None
) -> str:
    """
    Dump specific process memory for analysis.

    Args:
        memory_dump: Path to memory dump
        pid: Process ID to dump
        output_dir: Output directory
        profile: Memory profile
        ctf: CTF context

    Returns:
        str: Dumped process information

    Examples:
        # Dump suspicious process
        volatility_dump_process(
            memory_dump="/dumps/memory.raw",
            pid=1234,
            output_dir="/analysis/process-1234"
        )
    """
    cmd_parts = ["vol", "-f", memory_dump]

    if profile:
        cmd_parts.extend(["--profile", profile])

    cmd_parts.extend(["windows.memmap", "--pid", str(pid), "--dump", "--output-dir", output_dir])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def volatility_find_malware(memory_dump: str, profile: str = "", scan_type: str = "malfind", ctf=None) -> str:
    """
    Detect malware and injected code in memory.

    Args:
        memory_dump: Path to memory dump
        profile: Memory profile
        scan_type: Type of scan (malfind, hollowfind, etc.)
        ctf: CTF context

    Returns:
        str: Detected malware indicators

    Examples:
        # Find injected code
        volatility_find_malware(
            memory_dump="/dumps/infected.raw",
            profile="Win10x64"
        )
    """
    cmd_parts = ["vol", "-f", memory_dump]

    if profile:
        cmd_parts.extend(["--profile", profile])

    cmd_parts.append(f"windows.{scan_type}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
