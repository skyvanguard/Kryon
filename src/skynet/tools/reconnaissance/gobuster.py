"""
Gobuster - Directory/File, DNS and VHost Busting Tool
=====================================================

Gobuster is a tool used to brute-force URIs, DNS subdomains, and
virtual host names on target web servers.

PERFORMANCE: Results are cached with 2-hour TTL for web fuzzing and
12-hour TTL for DNS enumeration to avoid redundant operations.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool
from skynet.cache import cache_scan_result


@function_tool
@cache_scan_result(scan_type="web_fuzz", ttl=7200)  # Cache for 2 hours
def gobuster_dir(
    url: str,
    wordlist: str,
    extensions: str = "",
    threads: int = 10,
    timeout: int = 10,
    status_codes: str = "200,204,301,302,307,308,401,403",
    exclude_status: str = "",
    user_agent: str = "",
    username: str = "",
    password: str = "",
    cookies: str = "",
    headers: str = "",
    follow_redirects: bool = False,
    no_tls_validation: bool = False,
    expanded: bool = True,
    ctf=None
) -> str:
    """
    Directory and file brute forcing using Gobuster.

    CACHED: Results cached for 2 hours to avoid redundant fuzzing.
    Expected performance improvement: 10-30x for repeated scans.

    Discovers hidden directories, files, and paths on web servers
    through brute force enumeration.

    Args:
        url: Target URL (e.g., http://example.com)
        wordlist: Path to wordlist file
        extensions: File extensions to check (e.g., php,html,txt)
        threads: Number of concurrent threads (default: 10)
        timeout: HTTP timeout in seconds
        status_codes: Positive status codes (comma-separated)
        exclude_status: Status codes to exclude
        user_agent: Custom User-Agent string
        username: Username for Basic Auth
        password: Password for Basic Auth
        cookies: Cookies to send (format: "name1=value1; name2=value2")
        headers: Custom headers (format: "Header1: Value1,Header2: Value2")
        follow_redirects: Follow redirects
        no_tls_validation: Skip TLS certificate verification
        expanded: Show expanded output (full URLs)
        ctf: CTF context for execution

    Returns:
        str: Discovered directories and files

    Examples:
        # Basic directory discovery
        gobuster_dir(
            url="http://example.com",
            wordlist="/usr/share/wordlists/dirb/common.txt"
        )

        # File discovery with extensions
        gobuster_dir(
            url="http://example.com",
            wordlist="/usr/share/wordlists/raft-small-files.txt",
            extensions="php,html,txt,bak,old"
        )

        # Authenticated scan
        gobuster_dir(
            url="https://example.com",
            wordlist="/usr/share/wordlists/dirb/common.txt",
            username="admin",
            password="password123"
        )

        # Custom headers and cookies
        gobuster_dir(
            url="http://example.com",
            wordlist="/usr/share/wordlists/dirb/common.txt",
            headers="Authorization: Bearer token123",
            cookies="session=abc123"
        )
    """
    # Build gobuster dir command
    cmd_parts = [
        "gobuster", "dir",
        f"-u {url}",
        f"-w {wordlist}",
        f"-t {threads}",
        f"--timeout {timeout}s",
        f"-s {status_codes}"
    ]

    # Extensions
    if extensions:
        cmd_parts.append(f"-x {extensions}")

    # Exclude status codes
    if exclude_status:
        cmd_parts.append(f"-b {exclude_status}")

    # User agent
    if user_agent:
        cmd_parts.append(f'-a "{user_agent}"')

    # Authentication
    if username and password:
        cmd_parts.append(f"-U {username} -P {password}")

    # Cookies
    if cookies:
        cmd_parts.append(f'-c "{cookies}"')

    # Headers
    if headers:
        for header in headers.split(","):
            cmd_parts.append(f'-H "{header.strip()}"')

    # Redirects
    if follow_redirects:
        cmd_parts.append("-r")

    # TLS validation
    if no_tls_validation:
        cmd_parts.append("-k")

    # Expanded output
    if expanded:
        cmd_parts.append("-e")

    # Quiet mode for cleaner output
    cmd_parts.append("-q")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="subdomain_enum", ttl=43200)  # Cache for 12 hours
def gobuster_dns(
    domain: str,
    wordlist: str,
    resolvers: str = "",
    threads: int = 10,
    timeout: int = 1,
    show_ips: bool = True,
    show_cname: bool = True,
    wildcard: bool = False,
    ctf=None
) -> str:
    """
    DNS subdomain brute forcing using Gobuster.

    CACHED: Results cached for 12 hours to avoid redundant DNS enumeration.

    Discovers subdomains through brute force DNS queries.

    Args:
        domain: Target domain (e.g., example.com)
        wordlist: Path to subdomain wordlist
        resolvers: Path to file with DNS resolver IPs
        threads: Number of concurrent threads
        timeout: DNS query timeout in seconds
        show_ips: Show IP addresses
        show_cname: Show CNAME records
        wildcard: Force continued operation when wildcard found
        ctf: CTF context for execution

    Returns:
        str: Discovered subdomains

    Examples:
        # Basic subdomain enumeration
        gobuster_dns(
            domain="example.com",
            wordlist="/usr/share/wordlists/subdomains-top1million.txt"
        )

        # Fast scan with custom resolvers
        gobuster_dns(
            domain="example.com",
            wordlist="/usr/share/wordlists/subdomains.txt",
            resolvers="/etc/resolvers.txt",
            threads=50
        )

        # Wildcard domain handling
        gobuster_dns(
            domain="example.com",
            wordlist="/usr/share/wordlists/subdomains.txt",
            wildcard=True
        )
    """
    # Build gobuster dns command
    cmd_parts = [
        "gobuster", "dns",
        f"-d {domain}",
        f"-w {wordlist}",
        f"-t {threads}",
        f"--timeout {timeout}s"
    ]

    # Custom resolvers
    if resolvers:
        cmd_parts.append(f"-r {resolvers}")

    # Show IPs
    if show_ips:
        cmd_parts.append("-i")

    # Show CNAME
    if show_cname:
        cmd_parts.append("--show-cname")

    # Wildcard handling
    if wildcard:
        cmd_parts.append("--wildcard")

    # Quiet mode
    cmd_parts.append("-q")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="web_fuzz", ttl=7200)  # Cache for 2 hours
def gobuster_vhost(
    url: str,
    wordlist: str,
    threads: int = 10,
    timeout: int = 10,
    append_domain: bool = False,
    domain: str = "",
    exclude_length: str = "",
    headers: str = "",
    cookies: str = "",
    ctf=None
) -> str:
    """
    Virtual host brute forcing using Gobuster.

    CACHED: Results cached for 2 hours to avoid redundant vhost fuzzing.

    Discovers virtual hosts by fuzzing the Host header.

    Args:
        url: Target URL (e.g., http://192.168.1.100)
        wordlist: Path to vhost wordlist
        threads: Number of concurrent threads
        timeout: HTTP timeout in seconds
        append_domain: Append base domain to wordlist entries
        domain: Base domain to append
        exclude_length: Exclude responses by Content-Length
        headers: Custom headers
        cookies: Cookies to send
        ctf: CTF context for execution

    Returns:
        str: Discovered virtual hosts

    Examples:
        # Basic vhost discovery
        gobuster_vhost(
            url="http://192.168.1.100",
            wordlist="/usr/share/wordlists/subdomains.txt",
            append_domain=True,
            domain="example.com"
        )

        # With response filtering
        gobuster_vhost(
            url="http://10.10.10.5",
            wordlist="/usr/share/wordlists/vhosts.txt",
            exclude_length="1234"
        )
    """
    # Build gobuster vhost command
    cmd_parts = [
        "gobuster", "vhost",
        f"-u {url}",
        f"-w {wordlist}",
        f"-t {threads}",
        f"--timeout {timeout}s"
    ]

    # Append domain
    if append_domain and domain:
        cmd_parts.append(f"--append-domain -d {domain}")

    # Exclude by length
    if exclude_length:
        cmd_parts.append(f"--exclude-length {exclude_length}")

    # Headers
    if headers:
        for header in headers.split(","):
            cmd_parts.append(f'-H "{header.strip()}"')

    # Cookies
    if cookies:
        cmd_parts.append(f'-c "{cookies}"')

    # Quiet mode
    cmd_parts.append("-q")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
