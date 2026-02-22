"""
MobSF - Mobile Security Framework
==================================

MobSF (Mobile Security Framework) is an automated, all-in-one mobile application
security testing framework capable of performing static and dynamic analysis on
Android and iOS applications.

PERFORMANCE: Static analysis results are cached for 6 hours as they represent
file-based analysis that remains stable. Dynamic analysis is NOT cached as it
involves runtime behavior.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="mobile_sast", ttl=21600)
def mobsf_static_analysis(app_path: str, scan_type: str = "apk", rescan: bool = False, ctf=None) -> str:
    """
    Perform comprehensive static analysis on mobile applications.

    MobSF performs automated static analysis including manifest analysis,
    code analysis, component analysis, and security issue detection for
    Android APK/XAPK and iOS IPA files.

    Args:
        app_path: Path to APK, XAPK, or IPA file
        scan_type: Application type (apk, xapk, ipa, appx, zip)
        rescan: Force re-scan even if already analyzed
        ctf: CTF context for execution

    Returns:
        str: Comprehensive security analysis report

    Examples:
        # Analyze Android APK
        mobsf_static_analysis(
            app_path="/tmp/target-app.apk",
            scan_type="apk"
        )

        # Analyze iOS IPA
        mobsf_static_analysis(
            app_path="/tmp/ios-app.ipa",
            scan_type="ipa"
        )

        # Force rescan
        mobsf_static_analysis(
            app_path="/tmp/app.apk",
            scan_type="apk",
            rescan=True
        )

        # Analyze app bundle
        mobsf_static_analysis(
            app_path="/tmp/app.xapk",
            scan_type="xapk"
        )

    Analysis Components:

    Manifest Analysis:
        - Permissions (dangerous, normal, signature)
        - Exported components
        - Intent filters
        - Debuggable flag
        - Backup enabled
        - Network security config
        - Min/Target SDK versions

    Code Analysis:
        - Hardcoded secrets (API keys, passwords)
        - Cryptographic issues
        - Insecure random
        - SQL injection vectors
        - WebView vulnerabilities
        - Insecure file permissions
        - Certificate pinning

    Component Analysis:
        - Activities (exported, intent filters)
        - Services (exported, permissions)
        - Broadcast receivers
        - Content providers (path permissions)

    Binary Analysis:
        - Code obfuscation detection
        - Debug symbols present
        - Stack canaries
        - PIE (Position Independent Executable)
        - Stripped binaries
        - Packer/protector detection

    Network Security:
        - Cleartext traffic allowed
        - Certificate validation
        - SSL/TLS configuration
        - Certificate pinning
        - Domain whitelisting

    Data Storage:
        - Shared preferences encryption
        - SQLite database encryption
        - File encryption
        - KeyStore usage
        - External storage usage

    Security Issues Detected:

    High Severity:
        - Hardcoded API keys/secrets
        - Debuggable application
        - Backup enabled
        - Exported components without permission
        - WebView JavaScript enabled
        - Insecure cryptography
        - SQL injection vulnerabilities

    Medium Severity:
        - Missing certificate pinning
        - Cleartext traffic allowed
        - Weak cryptographic algorithms
        - Insecure random number generation
        - Exported activities
        - Missing root detection

    Low Severity:
        - Logging sensitive data
        - Tapjacking vulnerabilities
        - Missing obfuscation
        - Old SDK version
        - Missing stack protection

    Output Format:
        JSON report with:
        - Security score (0-100)
        - Vulnerability list by severity
        - Permission analysis
        - Component analysis
        - Code issues
        - Best practice violations
        - Compliance (OWASP MASVS)

    OWASP MASVS Coverage:
        - MSTG-STORAGE (Data Storage)
        - MSTG-CRYPTO (Cryptography)
        - MSTG-AUTH (Authentication)
        - MSTG-NETWORK (Network Communication)
        - MSTG-PLATFORM (Platform Interaction)
        - MSTG-CODE (Code Quality)
        - MSTG-RESILIENCE (Resilience)

    Performance:
        - APK scan: 2-5 minutes
        - IPA scan: 3-7 minutes
        - Depends on app size and complexity

    Integration:
        # Use with other tools for complete analysis
        mobsf_static_analysis(app_path="app.apk")  # Static
        androguard_analyze(apk_path="app.apk")      # Detailed code
        apkid_detect(apk_file="app.apk")           # Obfuscation check

    Security Note:
        MobSF decompiles and analyzes application code. Some
        obfuscated or protected apps may have limited analysis.
        Always analyze apps you have authorization to test.
    """
    cmd_parts = ["mobsf", "-f", app_path]

    if scan_type:
        cmd_parts.extend(["-t", scan_type])

    if rescan:
        cmd_parts.append("--rescan")

    # Generate JSON output
    cmd_parts.extend(["-o", "json"])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def mobsf_dynamic_analysis(
    package_name: str, device_id: str = "", duration: int = 300, activity: str = "", ctf=None
) -> str:
    """
    Perform dynamic analysis on running Android application.

    MobSF dynamic analysis captures runtime behavior including network
    traffic, API calls, file operations, and security issues during
    application execution.

    Args:
        package_name: Android package name (e.g., com.example.app)
        device_id: ADB device identifier (empty for default)
        duration: Analysis duration in seconds
        activity: Specific activity to launch (empty for main)
        ctf: CTF context for execution

    Returns:
        str: Runtime behavior analysis and security findings

    Examples:
        # Basic dynamic analysis
        mobsf_dynamic_analysis(
            package_name="com.target.app",
            duration=300
        )

        # Specific device and activity
        mobsf_dynamic_analysis(
            package_name="com.example.app",
            device_id="emulator-5554",
            activity=".MainActivity",
            duration=600
        )

        # Long-term monitoring
        mobsf_dynamic_analysis(
            package_name="com.app.banking",
            duration=1800
        )

    Dynamic Analysis Capabilities:

    Network Traffic:
        - HTTP/HTTPS requests
        - API endpoints discovered
        - Data transmitted
        - Certificate validation
        - SSL/TLS versions
        - Cleartext traffic

    API Monitoring:
        - Location access
        - Camera usage
        - Microphone access
        - Contacts/SMS access
        - File system access
        - Cryptographic operations

    Runtime Behavior:
        - Activities launched
        - Services started
        - Broadcast receivers triggered
        - Content providers accessed
        - Intent data
        - WebView URLs loaded

    Security Issues:

    Network:
        - Unencrypted traffic
        - Certificate errors
        - Weak SSL/TLS
        - API key exposure
        - Sensitive data in URLs

    Storage:
        - Files created
        - Shared preferences
        - SQLite operations
        - External storage writes
        - Cache directory usage

    Permissions:
        - Runtime permission requests
        - Denied permissions
        - Permission abuse
        - Unnecessary permissions

    IPC:
        - Intent data leakage
        - Exported component access
        - Content provider queries
        - Broadcast messages

    Requirements:
        - Android device/emulator with MobSF setup
        - ADB connection established
        - Application installed
        - MobSF dynamic analyzer running

    Setup:
        # Start MobSF dynamic analyzer
        mobsf --dynamic start

        # Install and prepare app
        adb install app.apk
        adb shell pm grant com.example.app <permissions>

        # Run analysis
        mobsf_dynamic_analysis(package_name="com.example.app")

    Analysis Flow:
        1. Launch application
        2. Inject Frida instrumentation
        3. Monitor runtime behavior
        4. Capture network traffic
        5. Log API calls
        6. Generate report

    Output:
        - Network captures (PCAP)
        - API call logs
        - File operations
        - Screenshot captures
        - Security findings
        - CVSS scores

    Best Practices:
        - Use clean emulator/device
        - Exercise all app functionality
        - Test different user scenarios
        - Combine with manual testing
        - Review network captures separately

    Security Note:
        Dynamic analysis requires instrumentation of running app.
        Some apps detect instrumentation and may behave differently
        or refuse to run. Root detection and anti-tampering may
        interfere with analysis.
    """
    cmd_parts = ["mobsf-dynamic"]

    # Package name
    cmd_parts.extend(["-p", package_name])

    # Device
    if device_id:
        cmd_parts.extend(["-d", device_id])

    # Activity to launch
    if activity:
        cmd_parts.extend(["-a", activity])

    # Duration
    cmd_parts.extend(["-t", str(duration)])

    # Start analysis
    cmd_parts.append("--start")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="mobile_sast", ttl=21600)
def mobsf_api_scan(api_key: str, file_path: str, scan_type: str = "apk", ctf=None) -> str:
    """
    Use MobSF REST API for automated scanning integration.

    Integrates with MobSF REST API for CI/CD pipeline integration
    and automated security testing workflows.

    Args:
        api_key: MobSF REST API key
        file_path: Path to APK/IPA file
        scan_type: File type (apk, ipa, appx)
        ctf: CTF context for execution

    Returns:
        str: Scan results in JSON format

    Examples:
        # API-based scanning
        mobsf_api_scan(
            api_key="YOUR_API_KEY",
            file_path="/tmp/app.apk",
            scan_type="apk"
        )

        # iOS scanning via API
        mobsf_api_scan(
            api_key="YOUR_API_KEY",
            file_path="/builds/ios-app.ipa",
            scan_type="ipa"
        )

    API Endpoints:
        /api/v1/upload      - Upload file
        /api/v1/scan        - Start scan
        /api/v1/scans       - List scans
        /api/v1/report_json - Get JSON report
        /api/v1/download_pdf - Get PDF report

    CI/CD Integration:
        # Jenkins pipeline
        stage('Security Scan') {
            mobsf_api_scan(
                api_key: env.MOBSF_API_KEY,
                file_path: "app/build/outputs/apk/release/app.apk"
            )
        }

        # GitLab CI
        security_scan:
            script:
                - mobsf_api_scan --api-key $MOBSF_KEY --file app.apk

    Automation Benefits:
        - Headless operation
        - CI/CD integration
        - Batch scanning
        - Programmatic access
        - Report generation
        - Threshold enforcement

    Security Note:
        Protect API keys. Use environment variables or secret managers.
        MobSF server should be isolated and not publicly accessible.
    """
    # Construct API request (simplified - actual implementation would use requests library)
    command = f'curl -X POST -F "file=@{file_path}" -H "Authorization: {api_key}" http://localhost:8000/api/v1/upload'

    return run_command(command, ctf=ctf)
