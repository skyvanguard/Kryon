"""
Wappalyzer - Technology Detection
=================================

Wappalyzer is a technology profiler that shows you what websites are
built with. It detects content management systems, ecommerce platforms,
web frameworks, server software, analytics tools and many more.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def wappalyzer_detect(
    url: str,
    recursive: bool = False,
    max_depth: int = 3,
    max_urls: int = 10,
    max_wait: int = 5000,
    proxy: str = "",
    user_agent: str = "",
    headers: str = "",
    extended: bool = False,
    ctf=None
) -> str:
    """
    Detect web technologies using Wappalyzer.

    Identifies technologies used by websites including CMS, frameworks,
    analytics, CDN, programming languages, and more.

    Args:
        url: Target URL to analyze
        recursive: Crawl internal links
        max_depth: Maximum crawl depth for recursive mode
        max_urls: Maximum URLs to analyze
        max_wait: Maximum time to wait for page load (milliseconds)
        proxy: HTTP proxy server
        user_agent: Custom User-Agent string
        headers: Custom HTTP headers (JSON format)
        extended: Include additional technology details
        ctf: CTF context for execution

    Returns:
        str: Detected technologies in JSON format

    Examples:
        # Basic technology detection
        wappalyzer_detect(url="https://example.com")

        # Recursive crawl
        wappalyzer_detect(
            url="https://example.com",
            recursive=True,
            max_depth=2,
            max_urls=20
        )

        # With custom headers
        wappalyzer_detect(
            url="https://example.com",
            headers='{"Authorization": "Bearer token123"}',
            extended=True
        )

        # Through proxy
        wappalyzer_detect(
            url="https://example.com",
            proxy="http://127.0.0.1:8080"
        )

    Detected Categories:
        - CMS: WordPress, Drupal, Joomla, etc.
        - JavaScript Frameworks: React, Vue, Angular, etc.
        - JavaScript Libraries: jQuery, Bootstrap, etc.
        - Programming Languages: PHP, Python, Ruby, Node.js, etc.
        - Web Servers: Apache, Nginx, IIS, etc.
        - Databases: MySQL, PostgreSQL, MongoDB, etc.
        - Caching: Redis, Memcached, Varnish, etc.
        - CDN: Cloudflare, Akamai, AWS CloudFront, etc.
        - Analytics: Google Analytics, Matomo, etc.
        - Advertising: Google Ads, Facebook Pixel, etc.
        - Tag Managers: Google Tag Manager, etc.
        - Security: WAF, SSL providers, etc.
        - Font Scripts: Google Font API, Adobe Fonts, etc.
        - Video Players: YouTube, Vimeo, etc.
        - E-commerce: Shopify, WooCommerce, Magento, etc.
        - Payment Processors: Stripe, PayPal, etc.
        - Marketing Automation: HubSpot, Marketo, etc.
        - Live Chat: Intercom, LiveChat, Zendesk, etc.

    Note:
        Requires wappalyzer-cli to be installed:
        npm install -g wappalyzer-cli
    """
    # Build wappalyzer command
    cmd_parts = ["wappalyzer", url]

    # Recursive crawling
    if recursive:
        cmd_parts.append("--recursive")
        cmd_parts.append(f"--max-depth {max_depth}")
        cmd_parts.append(f"--max-urls {max_urls}")

    # Timing
    cmd_parts.append(f"--max-wait {max_wait}")

    # Proxy
    if proxy:
        cmd_parts.append(f"--proxy {proxy}")

    # User agent
    if user_agent:
        cmd_parts.append(f'--user-agent "{user_agent}"')

    # Headers
    if headers:
        cmd_parts.append(f"--headers '{headers}'")

    # Extended output
    if extended:
        cmd_parts.append("--extended")

    # Pretty print JSON
    cmd_parts.append("--pretty")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
