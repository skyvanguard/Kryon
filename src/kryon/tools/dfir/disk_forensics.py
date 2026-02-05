"""
Disk Forensics Tools
====================

Tools for disk image analysis, file recovery, and timeline creation.

PERFORMANCE: Disk forensics is NOT cached as each analysis is unique.
"""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def autopsy_analyze(disk_image: str, case_name: str, output_dir: str = "/tmp/autopsy", ctf=None) -> str:
    """
    Analyze disk image with Autopsy/Sleuth Kit.

    Args:
        disk_image: Path to disk image (E01, DD, VHD, etc.)
        case_name: Investigation case name
        output_dir: Output directory
        ctf: CTF context

    Returns:
        str: Analysis results and findings

    Examples:
        # Analyze disk image
        autopsy_analyze(
            disk_image="/evidence/disk.E01",
            case_name="incident-2025-01"
        )
    """
    command = f"autopsy_cli -i {disk_image} -c {case_name} -o {output_dir}"
    return run_command(command, ctf=ctf)


@function_tool
def tsk_timeline(disk_image: str, output_file: str = "/tmp/timeline.csv", timezone: str = "UTC", ctf=None) -> str:
    """
    Create filesystem timeline from disk image.

    Args:
        disk_image: Path to disk image
        output_file: Output timeline file
        timezone: Timezone for timestamps
        ctf: CTF context

    Returns:
        str: Timeline creation status

    Examples:
        # Create timeline
        tsk_timeline(
            disk_image="/evidence/disk.dd",
            output_file="/analysis/timeline.csv"
        )
    """
    command = f"fls -r -m / {disk_image} > {output_file}"
    return run_command(command, ctf=ctf)


@function_tool
def photorec_recover(device: str, output_dir: str = "/tmp/recovered", file_types: str = "all", ctf=None) -> str:
    """
    Recover deleted files with PhotoRec.

    Args:
        device: Device or image file
        output_dir: Recovery output directory
        file_types: File types to recover (all, jpg, doc, pdf, etc.)
        ctf: CTF context

    Returns:
        str: Recovery results

    Examples:
        # Recover all files
        photorec_recover(
            device="/dev/sdb1",
            output_dir="/recovery/usb"
        )

        # Recover specific types
        photorec_recover(
            device="/evidence/disk.dd",
            file_types="jpg,png,doc",
            output_dir="/recovery/documents"
        )
    """
    cmd_parts = ["photorec", "/d", output_dir]

    if file_types != "all":
        cmd_parts.extend(["/extensions", file_types])

    cmd_parts.append(device)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
