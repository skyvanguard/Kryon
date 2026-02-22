"""
Yara - Malware Identification and Classification
=================================================

Yara is a tool for identifying and classifying malware using pattern matching.

PERFORMANCE: Malware analysis results are cached for 6 hours.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="malware_analysis", ttl=21600)
def yara_scan_file(
    file_path: str,
    rules_path: str = "/usr/share/yara-rules",
    recursive: bool = False,
    print_strings: bool = False,
    print_meta: bool = True,
    ctf=None,
) -> str:
    """
    Scan file(s) with Yara rules for malware detection.

    Args:
        file_path: File or directory to scan
        rules_path: Path to Yara rules
        recursive: Scan directories recursively
        print_strings: Print matching strings
        print_meta: Print rule metadata
        ctf: CTF context

    Returns:
        str: Matching rules and malware families

    Examples:
        # Scan single file
        yara_scan_file(
            file_path="/tmp/suspicious.exe",
            rules_path="/rules/malware.yar"
        )

        # Scan directory
        yara_scan_file(
            file_path="/samples/",
            recursive=True,
            print_strings=True
        )
    """
    cmd_parts = ["yara"]

    if recursive:
        cmd_parts.append("-r")

    if print_strings:
        cmd_parts.append("-s")

    if print_meta:
        cmd_parts.append("-m")

    cmd_parts.extend([rules_path, file_path])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="malware_analysis", ttl=21600)
def yara_scan_directory(
    directory: str, rules_path: str = "/usr/share/yara-rules", fast_scan: bool = False, ctf=None
) -> str:
    """
    Recursively scan directory for malware.

    Args:
        directory: Directory to scan
        rules_path: Yara rules path
        fast_scan: Fast mode (less accurate)
        ctf: CTF context

    Returns:
        str: Detected malware and matches

    Examples:
        # Scan downloads folder
        yara_scan_directory(
            directory="/home/user/Downloads",
            rules_path="/rules/all.yar"
        )
    """
    cmd_parts = ["yara", "-r"]

    if fast_scan:
        cmd_parts.append("-f")

    cmd_parts.extend([rules_path, directory])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
