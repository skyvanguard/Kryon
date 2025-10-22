"""
WhatWeb - Web Technology Detection
==================================

WhatWeb identifies websites. It recognizes web technologies including
content management systems (CMS), blogging platforms, statistic/analytics
packages, JavaScript libraries, web servers, and embedded devices.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def whatweb_scan(
    target: str,
    aggression: int = 1,
    plugins: str = "",
    user_agent: str = "",
    custom_headers: str = "",
    cookies: str = "",
    username: str = "",
    password: str = "",
    follow_redirects: int = 2,
    max_threads: int = 25,
    wait: int = 0,
    url_suffix: str = "",
    proxy: str = "",
    verbose: bool = False,
    log_json: bool = True,
    ctf=None
) -> str:
    """
    Identify web technologies, CMS, frameworks, and server software.

    WhatWeb detects over 1800 web technologies including CMS platforms,
    JavaScript libraries, web frameworks, server software, and more.

    Args:
        target: Target URL or file containing URLs
        aggression: Aggression level 1-4 (1=passive, 4=heavy)
        plugins: Specific plugins to use (comma-separated)
        user_agent: Custom User-Agent string
        custom_headers: Custom HTTP headers
        cookies: Cookies to send
        username: HTTP basic authentication username
        password: HTTP basic authentication password
        follow_redirects: Number of redirects to follow (0-10)
        max_threads: Maximum concurrent threads
        wait: Wait seconds between requests
        url_suffix: Append string to all target URLs
        proxy: HTTP proxy (e.g., http://proxy:8080)
        verbose: Enable verbose output
        log_json: Output results in JSON format
        ctf: CTF context for execution

    Returns:
        str: Detected web technologies and fingerprints

    Examples:
        # Basic technology detection
        whatweb_scan(target="http://example.com")

        # Aggressive deep scan
        whatweb_scan(
            target="http://example.com",
            aggression=3,
            verbose=True
        )

        # Stealthy scan
        whatweb_scan(
            target="http://example.com",
            aggression=1,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            wait=3
        )

        # Authenticated scan
        whatweb_scan(
            target="https://example.com",
            username="admin",
            password="password123",
            aggression=2
        )

        # Scan multiple URLs from file
        whatweb_scan(
            target="/path/to/urls.txt",
            aggression=2,
            max_threads=50
        )

    Aggression Levels:
        1 (Passive/Stealthy):
           - Single HTTP GET request
           - Analyzes headers, HTML, meta tags
           - Low risk of detection

        2 (Polite/Default):
           - Additional HTTP requests if plugin matches
           - More accurate identification
           - Slightly more detectable

        3 (Aggressive):
           - Makes numerous requests
           - Tests for specific vulnerabilities
           - Much more detectable
           - Better accuracy

        4 (Heavy):
           - Tests everything possible
           - Many requests per plugin
           - Highly detectable
           - Maximum accuracy

    Detected Technologies:
        - CMS: WordPress, Joomla, Drupal, etc.
        - Frameworks: Laravel, Django, Rails, etc.
        - JavaScript: jQuery, React, Angular, Vue, etc.
        - Servers: Apache, Nginx, IIS, etc.
        - Languages: PHP, Python, Ruby, ASP.NET, etc.
        - CDN: Cloudflare, Akamai, Fastly, etc.
        - Analytics: Google Analytics, Matomo, etc.
        - E-commerce: Magento, Shopify, WooCommerce, etc.
        - Security: WAF, SSL/TLS versions, etc.
    """
    # Build whatweb command
    cmd_parts = ["whatweb", f"-a {aggression}"]

    # Add target (URL or file)
    cmd_parts.append(target)

    # Plugins
    if plugins:
        cmd_parts.append(f"--plugins {plugins}")

    # User agent
    if user_agent:
        cmd_parts.append(f'-U "{user_agent}"')

    # Custom headers
    if custom_headers:
        cmd_parts.append(f'-H "{custom_headers}"')

    # Cookies
    if cookies:
        cmd_parts.append(f'--cookie "{cookies}"')

    # Authentication
    if username and password:
        cmd_parts.append(f"--user {username}:{password}")

    # Redirects
    cmd_parts.append(f"--max-redirects {follow_redirects}")

    # Threading
    cmd_parts.append(f"-t {max_threads}")

    # Wait between requests
    if wait > 0:
        cmd_parts.append(f"--wait {wait}")

    # URL suffix
    if url_suffix:
        cmd_parts.append(f"--url-suffix {url_suffix}")

    # Proxy
    if proxy:
        cmd_parts.append(f"--proxy {proxy}")

    # Output format
    if log_json:
        cmd_parts.append("--log-json=-")

    # Verbosity
    if verbose:
        cmd_parts.append("-v")

    # No errors (cleaner output)
    cmd_parts.append("--no-errors")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
