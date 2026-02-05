"""
WFuzz - Web Application Fuzzer
===============================

WFuzz is a flexible web application fuzzer for discovering resources, testing
parameters, and identifying vulnerabilities through intelligent fuzzing.

PERFORMANCE: Results are cached with 1-hour TTL for web fuzzing operations.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="web_fuzz", ttl=3600)  # Cache for 1 hour
def wfuzz_scan(
    url: str,
    wordlist: str,
    method: str = "GET",
    headers: str = "",
    data: str = "",
    cookies: str = "",
    hide_codes: str = "404",
    show_codes: str = "",
    hide_chars: str = "",
    show_chars: str = "",
    threads: int = 30,
    follow_redirects: bool = False,
    proxy: str = "",
    output_format: str = "raw",
    output_file: str = "",
    ctf=None,
) -> str:
    """
    Advanced web application fuzzing and parameter testing.

    CACHED: Results cached for 1 hour to avoid redundant fuzzing.
    Expected performance improvement: 10-30x for repeated operations.

    WFuzz provides flexible fuzzing capabilities for web applications,
    supporting multiple fuzz points, advanced filtering, and various
    attack vectors.

    Args:
        url: Target URL with FUZZ keyword (can have multiple: FUZ2Z, FUZ3Z)
        wordlist: Wordlist file path (or multiple with -w for each FUZZ)
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        headers: Custom headers (format: "Header:Value")
        data: POST data (use FUZZ for parameter fuzzing)
        cookies: Cookie string (format: "name=value")
        hide_codes: HTTP codes to hide from results (default: 404)
        show_codes: Only show these HTTP codes
        hide_chars: Hide responses with X characters
        show_chars: Only show responses with X characters
        threads: Number of concurrent threads (default: 30)
        follow_redirects: Follow HTTP redirects
        proxy: Proxy URL (http://proxy:port)
        output_format: Output format (raw, json, html, magictree)
        output_file: Save results to file
        ctf: CTF context for execution

    Returns:
        str: Fuzzing results with discovered resources and parameters

    Examples:
        # Basic directory fuzzing
        wfuzz_scan(
            url="https://example.com/FUZZ",
            wordlist="/usr/share/wordlists/dirb/common.txt",
            hide_codes="404"
        )

        # Parameter fuzzing (GET)
        wfuzz_scan(
            url="https://example.com/api?id=FUZZ",
            wordlist="/usr/share/seclists/Fuzzing/integers.txt"
        )

        # Parameter fuzzing (POST)
        wfuzz_scan(
            url="https://example.com/login",
            method="POST",
            data="username=admin&password=FUZZ",
            wordlist="/usr/share/wordlists/passwords.txt"
        )

        # Multiple fuzz points (username and password)
        wfuzz_scan(
            url="https://example.com/login",
            method="POST",
            data="username=FUZZ&password=FUZ2Z",
            wordlist="/usr/share/wordlists/usernames.txt,/usr/share/wordlists/passwords.txt"
        )

        # Header injection
        wfuzz_scan(
            url="https://example.com/api/users",
            wordlist="/usr/share/wordlists/headers.txt",
            headers="X-Forwarded-For: FUZZ"
        )

        # Cookie fuzzing
        wfuzz_scan(
            url="https://example.com/admin",
            wordlist="/usr/share/wordlists/session-ids.txt",
            cookies="session_id=FUZZ"
        )

        # File extension fuzzing
        wfuzz_scan(
            url="https://example.com/backup.FUZZ",
            wordlist="/usr/share/seclists/Discovery/Web-Content/web-extensions.txt"
        )

        # Subdomain fuzzing
        wfuzz_scan(
            url="https://FUZZ.example.com",
            wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            hide_codes="404,000"  # Hide not found and connection errors
        )

        # Advanced filtering (hide specific response sizes)
        wfuzz_scan(
            url="https://example.com/FUZZ",
            wordlist="/usr/share/wordlists/dirs.txt",
            hide_chars="4242"  # Hide responses with exactly 4242 characters
        )

        # Authenticated fuzzing
        wfuzz_scan(
            url="https://example.com/api/FUZZ",
            wordlist="/usr/share/wordlists/api-endpoints.txt",
            headers="Authorization: Bearer eyJhbGc...",
            show_codes="200,201,202"
        )

        # Proxy-based fuzzing
        wfuzz_scan(
            url="https://example.com/FUZZ",
            wordlist="/usr/share/wordlists/common.txt",
            proxy="http://127.0.0.1:8080"  # Burp Suite
        )

        # JSON parameter fuzzing
        wfuzz_scan(
            url="https://api.example.com/v1/users",
            method="POST",
            headers="Content-Type: application/json",
            data='{"role": "FUZZ"}',
            wordlist="/usr/share/wordlists/roles.txt"
        )

    Fuzzing Use Cases:

    Directory & File Discovery:
        - Hidden directories
        - Backup files (.bak, .old, .swp)
        - Configuration files
        - Admin panels

    Parameter Discovery:
        - GET parameters
        - POST parameters
        - Hidden form fields
        - API parameters

    Authentication Bypass:
        - Username enumeration
        - Password spraying
        - Session ID brute force
        - JWT token manipulation

    Header Injection:
        - X-Forwarded-For
        - X-Original-URL
        - X-Rewrite-URL
        - Host header injection

    API Testing:
        - Endpoint discovery
        - Method fuzzing
        - Version discovery
        - Parameter tampering

    Advanced Filtering:
        --hc: Hide HTTP codes
        --sc: Show HTTP codes
        --hl: Hide lines count
        --sl: Show lines count
        --hw: Hide words count
        --sw: Show words count
        --hh: Hide chars count
        --sh: Show chars count

    Multiple Fuzz Points:
        FUZZ: First wordlist
        FUZ2Z: Second wordlist
        FUZ3Z: Third wordlist
        (up to FUZ...Z)

    Security Note:
        Web fuzzing generates significant traffic and logs.
        Use rate limiting for production systems and always
        obtain proper authorization before testing.
    """
    cmd_parts = ["wfuzz"]

    # HTTP method
    if method != "GET":
        cmd_parts.extend(["-X", method])

    # Headers
    if headers:
        for header in headers.split(";"):
            if header.strip():
                cmd_parts.extend(["-H", header.strip()])

    # POST data
    if data:
        cmd_parts.extend(["-d", data])

    # Cookies
    if cookies:
        cmd_parts.extend(["-b", cookies])

    # Response filtering
    if hide_codes:
        cmd_parts.extend(["--hc", hide_codes])

    if show_codes:
        cmd_parts.extend(["--sc", show_codes])

    if hide_chars:
        cmd_parts.extend(["--hh", hide_chars])

    if show_chars:
        cmd_parts.extend(["--sh", show_chars])

    # Performance
    cmd_parts.extend(["-t", str(threads)])

    # Follow redirects
    if follow_redirects:
        cmd_parts.append("--follow")

    # Proxy
    if proxy:
        cmd_parts.extend(["-p", proxy])

    # Output
    if output_format != "raw":
        cmd_parts.extend(["-f", output_format])

    if output_file:
        cmd_parts.extend(["-o", output_file])

    # Wordlist(s) and URL
    if "," in wordlist:
        # Multiple wordlists for multiple fuzz points
        for wl in wordlist.split(","):
            cmd_parts.extend(["-w", wl.strip()])
    else:
        cmd_parts.extend(["-w", wordlist])

    cmd_parts.append(url)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
