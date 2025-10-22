"""
APKiD - Android Application Identifier
=======================================

APKiD identifies compilers, packers, obfuscators, and other weird stuff
in APK files. Essential for understanding if an app is protected and
what tools were used.

PERFORMANCE: APK identification results are cached for 24 hours as they
represent static file metadata that doesn't change.
"""

from skynet.tools.common import run_command, cache_scan_result
from skynet.sdk.agents import function_tool


@function_tool
@cache_scan_result(scan_type="app_metadata", ttl=86400)
def apkid_detect(
    apk_file: str,
    json_output: bool = True,
    verbose: bool = False,
    ctf=None
) -> str:
    """
    Identify compilers, packers, and obfuscators in APK files.

    APKiD detects various protections and build tools used in Android
    applications, helping identify obfuscation and anti-analysis techniques.

    Args:
        apk_file: Path to APK file
        json_output: Output in JSON format
        verbose: Enable verbose detection output
        ctf: CTF context for execution

    Returns:
        str: Detection results with identified tools

    Examples:
        # Basic APK identification
        apkid_detect(apk_file="/tmp/app.apk")

        # Verbose detection
        apkid_detect(
            apk_file="/tmp/protected-app.apk",
            verbose=True
        )

        # Multiple APKs
        for apk in apk_list:
            apkid_detect(apk_file=apk)

    Detected Components:

    Compilers:
        - dx (Android SDK default)
        - Jack (deprecated Android compiler)
        - D8 (modern Android compiler)
        - R8 (with optimization)

    Obfuscators:
        - ProGuard
        - DexGuard
        - Allatori
        - DashO
        - LLVM-Obfuscator

    Packers:
        - Bangcle
        - SecNeo
        - Qihoo 360
        - Tencent
        - Baidu
        - Alibaba

    Anti-Analysis:
        - Anti-debug
        - Anti-emulator
        - Root detection
        - Frida detection
        - Integrity checks

    Use Cases:

    Pre-Analysis Assessment:
        - Identify protection level
        - Plan analysis approach
        - Determine tool requirements
        - Estimate analysis difficulty

    Quick Triage:
        - Separate protected from unprotected apps
        - Prioritize analysis targets
        - Identify packer families

    Research:
        - Track obfuscation trends
        - Identify packer versions
        - Malware family attribution

    Example Output:
        {
            "files": [{
                "filename": "app.apk",
                "matches": {
                    "compiler": ["d8"],
                    "obfuscator": ["proguard"],
                    "packer": null,
                    "anti_vm": ["basic"]
                }
            }]
        }

    Detection Techniques:
        - String pattern matching
        - Bytecode signatures
        - DEX structure analysis
        - Native library inspection
        - Metadata examination

    Limitations:
        - May not detect custom protections
        - New packer versions need signature updates
        - Some obfuscation is undetectable
        - False positives possible

    Integration:
        # Use before detailed analysis
        apkid_detect(apk_file="app.apk")  # Quick check

        if "proguard" in result:
            # Expect obfuscated code
            androguard_analyze(apk_path="app.apk")

        if "dexguard" in result:
            # Needs advanced analysis
            frida_hook_function(...)

    Security Note:
        APKiD performs static analysis only. Safe to run on
        potentially malicious APKs without execution risk.
    """
    cmd_parts = ["apkid"]

    if json_output:
        cmd_parts.append("--json")

    if verbose:
        cmd_parts.append("-v")

    cmd_parts.append(apk_file)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
