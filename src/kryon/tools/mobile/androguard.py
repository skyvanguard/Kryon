"""
Androguard - Android Analysis Framework
========================================

Androguard is a full Python tool to play with Android files including
APK, DEX, and resources. Provides detailed static analysis capabilities.

PERFORMANCE: Static analysis results are cached for 12 hours as they
represent file-based code analysis.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="static_analysis", ttl=43200)
def androguard_analyze(apk_path: str, output_dir: str = "/tmp/androguard", decompile: bool = True, ctf=None) -> str:
    """
    Comprehensive APK analysis with Androguard.

    Performs deep static analysis including DEX analysis, manifest
    parsing, resource extraction, and code decompilation.

    Args:
        apk_path: Path to APK file
        output_dir: Directory for analysis output
        decompile: Decompile DEX to Java source
        ctf: CTF context for execution

    Returns:
        str: Analysis results and extracted information

    Examples:
        # Full APK analysis
        androguard_analyze(apk_path="/tmp/app.apk")

        # Custom output directory
        androguard_analyze(
            apk_path="/tmp/app.apk",
            output_dir="/analysis/app",
            decompile=True
        )

    Analysis Components:

    Manifest Analysis:
        - Package name
        - Version info
        - Permissions
        - Components
        - Intent filters
        - Min/Target SDK

    DEX Analysis:
        - Classes and methods
        - Strings
        - API calls
        - Cross-references
        - Call graphs
        - Control flow

    Resources:
        - Strings.xml
        - Layouts
        - Assets
        - Native libraries
        - Certificates

    Security Analysis:
        - Dangerous permissions
        - Exported components
        - Crypto usage
        - Network calls
        - File operations
        - SQL queries

    Example Usage:
        # Extract all strings
        androguard_analyze(apk_path="app.apk")
        # Check output_dir/strings.txt

        # Find API endpoints
        # Look for URLs in strings and code

        # Identify sensitive data
        # Search for hardcoded keys, passwords

    Integration with Other Tools:
        apkid_detect("app.apk")           # Identify protections
        androguard_analyze("app.apk")      # Detailed analysis
        frida_hook_function(...)           # Dynamic testing
    """
    cmd_parts = ["androguard", "analyze"]

    cmd_parts.extend(["-i", apk_path])
    cmd_parts.extend(["-o", output_dir])

    if decompile:
        cmd_parts.append("--decompile")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="static_analysis", ttl=43200)
def androguard_extract_apk(
    apk_path: str, extract_type: str = "all", output_dir: str = "/tmp/extracted", ctf=None
) -> str:
    """
    Extract specific components from APK.

    Args:
        apk_path: Path to APK file
        extract_type: What to extract (all, manifest, resources, dex, libs)
        output_dir: Output directory
        ctf: CTF context

    Returns:
        str: Extraction results

    Examples:
        # Extract everything
        androguard_extract_apk(apk_path="app.apk", extract_type="all")

        # Extract manifest only
        androguard_extract_apk(apk_path="app.apk", extract_type="manifest")

        # Extract native libraries
        androguard_extract_apk(apk_path="app.apk", extract_type="libs")
    """
    cmd_parts = ["androguard", "extract"]
    cmd_parts.extend(["-i", apk_path])
    cmd_parts.extend(["-o", output_dir])
    cmd_parts.extend(["-t", extract_type])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="static_analysis", ttl=43200)
def androguard_decompile(apk_path: str, output_dir: str = "/tmp/decompiled", decompiler: str = "dad", ctf=None) -> str:
    """
    Decompile APK to Java source code.

    Args:
        apk_path: Path to APK file
        output_dir: Output directory for Java files
        decompiler: Decompiler to use (dad, dex2jar, jadx)
        ctf: CTF context

    Returns:
        str: Decompilation results

    Examples:
        # Decompile with default decompiler
        androguard_decompile(apk_path="app.apk")

        # Use specific decompiler
        androguard_decompile(
            apk_path="app.apk",
            output_dir="/analysis/source",
            decompiler="jadx"
        )

    Decompilers:
        dad: Androguard's built-in decompiler
        dex2jar: Convert DEX to JAR, then decompile
        jadx: Modern decompiler with good results
    """
    cmd_parts = ["androguard", "decompile"]
    cmd_parts.extend(["-i", apk_path])
    cmd_parts.extend(["-o", output_dir])
    cmd_parts.extend(["-d", decompiler])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
