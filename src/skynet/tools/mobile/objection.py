"""
Objection - Runtime Mobile Exploration
=======================================

Objection is a runtime mobile exploration toolkit built on Frida, providing
high-level commands for common mobile security testing tasks without writing code.

PERFORMANCE: Runtime operations are NOT cached as they involve live application
behavior.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def objection_explore(
    package_name: str,
    command: str = "",
    device_id: str = "",
    spawn: bool = True,
    ctf=None
) -> str:
    """
    Interactive mobile application exploration with Objection.

    Objection provides high-level commands for common mobile security
    tasks including SSL pinning bypass, jailbreak detection bypass,
    hooking, and memory operations.

    Args:
        package_name: Target application package
        command: Objection command to execute (empty for interactive)
        device_id: Device identifier
        spawn: Spawn app or attach to running process
        ctf: CTF context

    Returns:
        str: Command output and exploration results

    Examples:
        # Interactive exploration
        objection_explore(package_name="com.target.app")

        # Bypass SSL pinning
        objection_explore(
            package_name="com.banking.app",
            command="android sslpinning disable"
        )

        # List activities
        objection_explore(
            package_name="com.app.target",
            command="android hooking list activities"
        )

        # Dump keystore
        objection_explore(
            package_name="com.secure.app",
            command="android keystore list"
        )

    Common Objection Commands:

    SSL Pinning:
        android sslpinning disable

    Root/Jailbreak Detection:
        android root disable
        ios jailbreak disable

    Hooking:
        android hooking list classes
        android hooking list activities
        android hooking watch class com.example.Class
        android hooking watch class_method com.example.Class.method

    Memory:
        memory dump all /tmp/dump
        memory list modules
        memory search "pattern"

    File System:
        file download /data/data/com.app/file.db
        file upload local.txt /sdcard/remote.txt
        android intent launch_activity com.app.Activity

    SQLite:
        sqlite connect /data/data/com.app/databases/db.db
        sqlite execute query "SELECT * FROM users"

    KeyStore:
        android keystore list
        android keystore dump com.app.keyalias

    Shared Preferences:
        android sharedpreferences dump

    Clipboard:
        android clipboard monitor

    Screenshots:
        android ui screenshot /tmp/screen.png

    Workflow Examples:

    Bypass and Intercept Traffic:
        ```
        # Disable SSL pinning
        objection_explore(package="com.app", command="android sslpinning disable")

        # Then use Burp Suite/mitmproxy to intercept
        ```

    Extract Database:
        ```
        # Download database
        objection_explore(
            package="com.app",
            command="file download /data/data/com.app/databases/app.db"
        )

        # Analyze offline
        sqlite3 app.db "SELECT * FROM sensitive_table"
        ```

    Hook Sensitive Methods:
        ```
        # Watch for crypto operations
        objection_explore(
            package="com.app",
            command="android hooking watch class javax.crypto.Cipher"
        )
        ```

    Advantages Over Raw Frida:
        - No JavaScript coding required
        - Pre-built bypasses for common protections
        - Interactive exploration
        - Easy file operations
        - Built-in hooking helpers

    Requirements:
        - Rooted Android / Jailbroken iOS
        - Frida server on device
        - USB debugging enabled

    Security Note:
        Objection requires root/jailbreak and may be detected by
        anti-tampering mechanisms. Use on authorized applications only.
    """
    cmd_parts = ["objection"]

    # Device
    if device_id:
        cmd_parts.extend(["--network", device_id])

    # Mode
    if spawn:
        cmd_parts.extend(["--gadget", package_name, "explore"])
    else:
        cmd_parts.extend(["-g", package_name, "explore"])

    # Command
    if command:
        cmd_parts.extend(["-c", f'"{command}"'])

    command_str = " ".join(cmd_parts)
    return run_command(command_str, ctf=ctf)


@function_tool
def objection_bypass_root(
    package_name: str,
    device_id: str = "",
    ctf=None
) -> str:
    """
    Bypass root/jailbreak detection in mobile apps.

    Automatically patches common root detection methods including
    file checks, system property checks, and SU binary detection.

    Args:
        package_name: Target application
        device_id: Device identifier
        ctf: CTF context

    Returns:
        str: Root bypass status

    Examples:
        # Bypass root detection
        objection_bypass_root(package_name="com.banking.app")

        # On specific device
        objection_bypass_root(
            package_name="com.secure.app",
            device_id="192.168.1.100:5555"
        )

    Bypassed Detection Methods:
        - Build.TAGS contains "test-keys"
        - SU binary existence checks
        - Superuser.apk presence
        - System property checks
        - SafetyNet attestation
        - RootBeer library
        - Magisk detection

    Use Cases:
        - Test security on rooted devices
        - Analyze apps requiring root bypass
        - Penetration testing
        - Security research

    Security Note:
        Some apps use server-side checks (SafetyNet) that cannot
        be bypassed client-side. Advanced anti-root may detect bypass.
    """
    return objection_explore(
        package_name=package_name,
        command="android root disable",
        device_id=device_id,
        spawn=True,
        ctf=ctf
    )
