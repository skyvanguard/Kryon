"""
Log Analysis Tools
==================

Tools for analyzing system logs, Windows event logs, and security logs.

PERFORMANCE: Log analysis results are cached for 30 minutes.
"""

from skynet.cache import cache_scan_result
from skynet.sdk.agents import function_tool
from skynet.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="log_analysis", ttl=1800)
def chainsaw_hunt(evtx_path: str, rules_path: str = "/rules/sigma", output_format: str = "csv", ctf=None) -> str:
    """
    Hunt for threats in Windows event logs with Chainsaw.

    Args:
        evtx_path: Path to EVTX file or directory
        rules_path: Path to Sigma rules
        output_format: Output format (csv, json)
        ctf: CTF context

    Returns:
        str: Detected threats and IOCs

    Examples:
        # Hunt in event logs
        chainsaw_hunt(
            evtx_path="/evidence/Security.evtx",
            rules_path="/rules/sigma/windows"
        )

        # Analyze directory of logs
        chainsaw_hunt(
            evtx_path="/evidence/evtx/",
            output_format="json"
        )
    """
    cmd_parts = ["chainsaw", "hunt", evtx_path]

    if rules_path:
        cmd_parts.extend(["-s", rules_path])

    cmd_parts.extend(["--output", output_format])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="log_analysis", ttl=1800)
def chainsaw_search(evtx_path: str, search_query: str, event_id: str = "", ctf=None) -> str:
    """
    Search Windows event logs for specific events.

    Args:
        evtx_path: Path to EVTX file
        search_query: Search query string
        event_id: Specific Event ID to search
        ctf: CTF context

    Returns:
        str: Matching events

    Examples:
        # Search for PowerShell execution
        chainsaw_search(
            evtx_path="/evidence/PowerShell.evtx",
            event_id="4104"
        )

        # Search for login failures
        chainsaw_search(
            evtx_path="/evidence/Security.evtx",
            event_id="4625"
        )
    """
    cmd_parts = ["chainsaw", "search", evtx_path]

    if event_id:
        cmd_parts.extend(["--event-id", event_id])
    elif search_query:
        cmd_parts.extend(["--query", f'"{search_query}"'])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="log_analysis", ttl=1800)
def evtx_dump(evtx_file: str, output_format: str = "json", output_file: str = "", ctf=None) -> str:
    """
    Parse and dump Windows EVTX logs.

    Args:
        evtx_file: Path to EVTX file
        output_format: Output format (json, xml, csv)
        output_file: Output file path
        ctf: CTF context

    Returns:
        str: Parsed event log data

    Examples:
        # Dump to JSON
        evtx_dump(
            evtx_file="/evidence/System.evtx",
            output_format="json",
            output_file="/analysis/system-logs.json"
        )
    """
    cmd_parts = ["evtx_dump", evtx_file]

    if output_format:
        cmd_parts.extend(["--format", output_format])

    if output_file:
        cmd_parts.extend(["-o", output_file])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
