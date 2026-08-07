"""
Feroxbuster - Fast Content Discovery Tool
=========================================

Feroxbuster is a fast, simple, recursive content discovery tool written
in Rust. It uses brute force combined with a wordlist to search for
unlinked content in target directories.
"""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def feroxbuster_scan(
    url: str,
    wordlist: str,
    threads: int = 50,
    depth: int = 4,
    timeout: int = 7,
    extensions: str = "",
    status_codes: str = "200,204,301,302,307,308,401,403,405",
    filter_status: str = "",
    filter_size: str = "",
    filter_words: str = "",
    filter_lines: str = "",
    headers: str = "",
    cookies: str = "",
    user_agent: str = "",
    rate_limit: int = 0,
    time_limit: str = "",
    auto_tune: bool = True,
    auto_bail: bool = True,
    no_recursion: bool = False,
    extract_links: bool = True,
    insecure: bool = False,
    ctf=None,
) -> str:
    """
    Fast recursive content discovery with automatic link extraction.

    Feroxbuster excels at recursive scanning and automatically follows
    discovered directories, making it excellent for thorough enumeration.

    Args:
        url: Target URL to scan
        wordlist: Path to wordlist file
        threads: Number of concurrent threads (default: 50)
        depth: Maximum recursion depth (default: 4)
        timeout: Request timeout in seconds
        extensions: Extensions to append (e.g., php,html,txt)
        status_codes: Status codes to include (comma-separated)
        filter_status: Status codes to filter out
        filter_size: Filter responses by size
        filter_words: Filter responses by word count
        filter_lines: Filter responses by line count
        headers: Custom headers (format: "Header1: Value1,Header2: Value2")
        cookies: Cookies (format: "name1=value1; name2=value2")
        user_agent: Custom User-Agent string
        rate_limit: Maximum requests per second (0 = unlimited)
        time_limit: Maximum runtime (e.g., "10m", "1h")
        auto_tune: Automatically lower scan rate on errors
        auto_bail: Automatically stop on too many errors
        no_recursion: Disable automatic recursion
        extract_links: Extract links from response bodies
        insecure: Allow invalid TLS certificates
        ctf: CTF context for execution

    Returns:
        str: Discovered paths and directories

    Examples:
        # Fast recursive discovery
        feroxbuster_scan(
            url="http://example.com",
            wordlist="/usr/share/wordlists/dirb/common.txt"
        )

        # Deep scan with extensions
        feroxbuster_scan(
            url="http://example.com",
            wordlist="/usr/share/wordlists/raft-medium-directories.txt",
            extensions="php,html,txt,bak",
            depth=6,
            threads=100
        )

        # Controlled scan with rate limiting
        feroxbuster_scan(
            url="http://example.com",
            wordlist="/usr/share/wordlists/dirb/big.txt",
            rate_limit=100,
            time_limit="10m"
        )

        # Authenticated scan with custom headers
        feroxbuster_scan(
            url="https://example.com",
            wordlist="/usr/share/wordlists/dirb/common.txt",
            headers="Authorization: Bearer token123,X-Custom: value",
            cookies="session=abc123",
            insecure=True
        )

        # Non-recursive scan (faster for quick checks)
        feroxbuster_scan(
            url="http://example.com",
            wordlist="/usr/share/wordlists/dirb/common.txt",
            no_recursion=True,
            threads=200
        )
    """
    # Build feroxbuster command
    cmd_parts = [
        "feroxbuster",
        f"-u {url}",
        f"-w {wordlist}",
        f"-t {threads}",
        f"--depth {depth}",
        f"--timeout {timeout}",
    ]

    # Extensions
    if extensions:
        cmd_parts.append(f"-x {extensions}")

    # Status codes
    if status_codes:
        cmd_parts.append(f"-s {status_codes}")

    if filter_status:
        cmd_parts.append(f"-C {filter_status}")

    # Filtering
    if filter_size:
        cmd_parts.append(f"-S {filter_size}")
    if filter_words:
        cmd_parts.append(f"-W {filter_words}")
    if filter_lines:
        cmd_parts.append(f"-N {filter_lines}")

    # Headers
    if headers:
        for header in headers.split(","):
            cmd_parts.append(f'-H "{header.strip()}"')

    # Cookies
    if cookies:
        cmd_parts.append(f'-b "{cookies}"')

    # User agent
    if user_agent:
        cmd_parts.append(f'-a "{user_agent}"')

    # Rate limiting
    if rate_limit > 0:
        cmd_parts.append(f"--rate-limit {rate_limit}")

    # Time limit
    if time_limit:
        cmd_parts.append(f"--time-limit {time_limit}")

    # Auto-tuning
    if auto_tune:
        cmd_parts.append("--auto-tune")

    if auto_bail:
        cmd_parts.append("--auto-bail")

    # Recursion
    if no_recursion:
        cmd_parts.append("--no-recursion")

    # Link extraction
    if extract_links:
        cmd_parts.append("--extract-links")

    # TLS
    if insecure:
        cmd_parts.append("-k")

    # Silent mode for cleaner output
    cmd_parts.append("--silent")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
