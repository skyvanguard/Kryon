"""
Network Forensics Tools
========================

Tools for analyzing network traffic captures and extracting artifacts.

PERFORMANCE: PCAP analysis results are cached for 1 hour.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="pcap_analysis", ttl=3600)
def networkminer_analyze(pcap_file: str, output_dir: str = "/tmp/networkminer", ctf=None) -> str:
    """
    Analyze PCAP file and extract artifacts with NetworkMiner.

    Args:
        pcap_file: Path to PCAP file
        output_dir: Output directory for extracted files
        ctf: CTF context

    Returns:
        str: Extracted files, credentials, and artifacts

    Examples:
        # Analyze packet capture
        networkminer_analyze(
            pcap_file="/captures/incident.pcap",
            output_dir="/analysis/artifacts"
        )
    """
    command = f"NetworkMiner --pcap {pcap_file} --output {output_dir}"
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="pcap_analysis", ttl=3600)
def zeek_analyze_traffic(pcap_file: str, output_dir: str = "/tmp/zeek", extract_files: bool = True, ctf=None) -> str:
    """
    Analyze network traffic with Zeek (formerly Bro).

    Args:
        pcap_file: Path to PCAP file
        output_dir: Output directory for logs
        extract_files: Extract files from traffic
        ctf: CTF context

    Returns:
        str: Protocol logs and analysis

    Examples:
        # Analyze with Zeek
        zeek_analyze_traffic(
            pcap_file="/captures/traffic.pcap",
            extract_files=True
        )
    """
    cmd_parts = ["zeek", "-r", pcap_file]

    if extract_files:
        cmd_parts.append("-e 'redef FileExtract::extract_all_files=T;'")

    cmd_parts.extend(["--output-dir", output_dir])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="pcap_analysis", ttl=3600)
def wireshark_filter(pcap_file: str, display_filter: str, output_file: str = "", fields: str = "", ctf=None) -> str:
    """
    Filter and analyze PCAP with tshark (Wireshark CLI).

    Args:
        pcap_file: Path to PCAP file
        display_filter: Wireshark display filter
        output_file: Save filtered packets
        fields: Specific fields to extract
        ctf: CTF context

    Returns:
        str: Filtered packets or field values

    Examples:
        # Extract HTTP requests
        wireshark_filter(
            pcap_file="/captures/traffic.pcap",
            display_filter="http.request"
        )

        # Extract specific fields
        wireshark_filter(
            pcap_file="/captures/traffic.pcap",
            display_filter="dns",
            fields="dns.qry.name"
        )

        # Save filtered packets
        wireshark_filter(
            pcap_file="/captures/all.pcap",
            display_filter="ip.addr==192.168.1.100",
            output_file="/analysis/filtered.pcap"
        )
    """
    cmd_parts = ["tshark", "-r", pcap_file]

    if display_filter:
        cmd_parts.extend(["-Y", f'"{display_filter}"'])

    if fields:
        cmd_parts.extend(["-T", "fields", "-e", fields])

    if output_file:
        cmd_parts.extend(["-w", output_file])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
