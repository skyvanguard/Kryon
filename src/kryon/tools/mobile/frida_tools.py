"""
Frida - Dynamic Instrumentation Toolkit
========================================

Frida is a dynamic instrumentation toolkit for developers, reverse-engineers,
and security researchers. Inject JavaScript to explore and modify apps at runtime.

PERFORMANCE: Runtime operations are NOT cached as they involve live application
behavior that must be captured fresh each time.
"""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def frida_hook_function(
    package_name: str,
    script_file: str = "",
    script_code: str = "",
    device_id: str = "",
    spawn: bool = True,
    ctf=None,
) -> str:
    """
    Hook functions in running Android/iOS applications.

    Frida allows runtime modification of application behavior by injecting
    JavaScript code to intercept function calls, modify arguments, and
    change return values.

    Args:
        package_name: Application package (com.example.app)
        script_file: Path to Frida script file
        script_code: Inline Frida script code
        device_id: Device identifier (empty for USB device)
        spawn: Spawn app (True) or attach to running (False)
        ctf: CTF context for execution

    Returns:
        str: Hooked function output and intercepted data

    Examples:
        # Hook and log all function calls
        frida_hook_function(
            package_name="com.target.app",
            script_code='''
            Java.perform(function() {
                var MainActivity = Java.use("com.target.app.MainActivity");
                MainActivity.sensitiveMethod.implementation = function(arg) {
                    console.log("Called with: " + arg);
                    return this.sensitiveMethod(arg);
                };
            });
            '''
        )

        # Load script from file
        frida_hook_function(
            package_name="com.example.app",
            script_file="/scripts/bypass-root.js",
            spawn=True
        )

        # Hook crypto functions
        frida_hook_function(
            package_name="com.banking.app",
            script_code='''
            Java.perform(function() {
                var Cipher = Java.use("javax.crypto.Cipher");
                Cipher.doFinal.overload("[B").implementation = function(input) {
                    console.log("Encrypting: " + hexdump(input));
                    return this.doFinal(input);
                };
            });
            '''
        )

    Common Frida Use Cases:

    SSL Pinning Bypass:
        ```javascript
        Java.perform(function() {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload("java.lang.String", "java.util.List")
                .implementation = function() {
                    console.log("SSL pinning bypassed");
                };
        });
        ```

    Root Detection Bypass:
        ```javascript
        Java.perform(function() {
            var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
            RootBeer.isRooted.implementation = function() {
                return false;
            };
        });
        ```

    Log All Intents:
        ```javascript
        Java.perform(function() {
            var Intent = Java.use("android.content.Intent");
            Intent.$init.overload("android.content.Context", "java.lang.Class")
                .implementation = function(ctx, cls) {
                    console.log("Intent: " + cls.getName());
                    return this.$init(ctx, cls);
                };
        });
        ```

    Dump SharedPreferences:
        ```javascript
        Java.perform(function() {
            var Context = Java.use("android.content.Context");
            var prefs = Context.getSharedPreferences("prefs", 0);
            console.log(prefs.getAll());
        });
        ```

    Hook Native Functions:
        ```javascript
        Interceptor.attach(Module.findExportByName("libnative.so", "check_license"), {
            onEnter: function(args) {
                console.log("check_license called");
            },
            onLeave: function(retval) {
                retval.replace(1);  // Always return true
            }
        });
        ```

    Requirements:
        - Rooted Android device or jailbroken iOS
        - Frida server running on device
        - USB debugging enabled
        - App debuggable or rooted environment

    Security Note:
        Frida requires root/jailbreak. Apps with strong anti-tampering
        may detect and refuse to run. Use on authorized apps only.
    """
    cmd_parts = ["frida"]

    # Device
    if device_id:
        cmd_parts.extend(["-D", device_id])
    else:
        cmd_parts.append("-U")  # USB device

    # Spawn or attach
    if spawn:
        cmd_parts.extend(["-f", package_name])
    else:
        cmd_parts.extend(["-n", package_name])

    # Script
    if script_file:
        cmd_parts.extend(["-l", script_file])
    elif script_code:
        cmd_parts.extend(["-e", f'"{script_code}"'])

    # Auto-resume if spawning
    if spawn:
        cmd_parts.append("--no-pause")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def frida_intercept_ssl(package_name: str, device_id: str = "", ctf=None) -> str:
    """
    Bypass SSL certificate pinning in Android apps.

    Automatically disables SSL pinning for common Android networking
    libraries including OkHttp, TrustManager, and others.

    Args:
        package_name: Target application package name
        device_id: Device identifier
        ctf: CTF context

    Returns:
        str: SSL pinning bypass status

    Examples:
        # Bypass SSL pinning
        frida_intercept_ssl(package_name="com.banking.app")

        # Specific device
        frida_intercept_ssl(
            package_name="com.secure.app",
            device_id="192.168.1.100:5555"
        )

    Bypassed Libraries:
        - OkHttp3 CertificatePinner
        - TrustManager
        - SSLContext
        - Conscrypt
        - Apache HttpClient
        - Cronet

    Use with Burp Suite/mitmproxy:
        1. Set up proxy
        2. Install proxy certificate
        3. Run frida_intercept_ssl()
        4. Intercept HTTPS traffic
    """
    ssl_bypass_script = """
    Java.perform(function() {
        // OkHttp3
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function() {
                console.log("[+] OkHttp3 SSL pinning bypassed");
            };
        } catch(e) {}

        // TrustManager
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            X509TrustManager.checkServerTrusted.implementation = function() {
                console.log("[+] TrustManager bypassed");
            };
        } catch(e) {}
    });
    """

    return frida_hook_function(package_name=package_name, script_code=ssl_bypass_script, device_id=device_id, ctf=ctf)


@function_tool
def frida_dump_memory(
    package_name: str,
    search_pattern: str = "",
    output_file: str = "/tmp/memory-dump.bin",
    device_id: str = "",
    ctf=None,
) -> str:
    """
    Dump application memory for analysis.

    Search and dump memory regions containing specific patterns or
    dump entire application memory space.

    Args:
        package_name: Target application
        search_pattern: String/hex pattern to search for
        output_file: Output file for memory dump
        device_id: Device identifier
        ctf: CTF context

    Returns:
        str: Memory dump results

    Examples:
        # Dump all memory
        frida_dump_memory(package_name="com.app.target")

        # Search for API key pattern
        frida_dump_memory(
            package_name="com.app.target",
            search_pattern="AIza[0-9A-Za-z-_]{35}"
        )

        # Search for encryption keys
        frida_dump_memory(
            package_name="com.banking.app",
            search_pattern="BEGIN RSA PRIVATE KEY"
        )

    Use Cases:
        - Find hardcoded secrets
        - Extract encryption keys
        - Recover session tokens
        - Analyze data structures
        - Find hidden strings

    Security Note:
        Memory dumps may contain sensitive user data. Handle with care
        and delete when analysis is complete.
    """
    dump_script = f'''
    Java.perform(function() {{
        var pattern = "{search_pattern}";
        console.log("[*] Dumping memory...");
        Process.enumerateRanges("r--").forEach(function(range) {{
            try {{
                var data = Memory.readByteArray(range.base, Math.min(range.size, 4096));
                // Save to file
                var file = new File("{output_file}", "a");
                file.write(data);
                file.close();
            }} catch(e) {{}}
        }});
        console.log("[+] Memory dump complete");
    }});
    '''

    return frida_hook_function(
        package_name=package_name,
        script_code=dump_script,
        device_id=device_id,
        spawn=False,
        ctf=ctf,
    )
