"""OWASP ZAP — Dynamic Application Security Testing (DAST) wrapper."""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def zap_baseline_scan(
    target_url: str,
    ajax_spider: bool = False,
    minutes: int = 5,
    output_format: str = "json",
    ctf=None,
) -> str:
    """
    Run ZAP baseline scan for quick vulnerability assessment.

    The baseline scan runs the ZAP spider against the target for a limited
    time, followed by an optional Ajax spider, then a passive scan.

    Args:
        target_url: Target URL to scan (e.g. https://example.com)
        ajax_spider: Enable Ajax spider for JavaScript-heavy applications
        minutes: Spider duration in minutes (default: 5)
        output_format: Output format (json, html, xml, md)
        ctf: CTF context for execution

    Returns:
        str: ZAP baseline scan results
    """
    cmd_parts = [
        "zap-baseline.py",
        f"-t {target_url}",
        f"-m {minutes}",
    ]

    if ajax_spider:
        cmd_parts.append("-j")

    if output_format == "json":
        cmd_parts.append("-J zap-report.json")
    elif output_format == "html":
        cmd_parts.append("-r zap-report.html")
    elif output_format == "xml":
        cmd_parts.append("-x zap-report.xml")
    elif output_format == "md":
        cmd_parts.append("-w zap-report.md")

    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def zap_full_scan(
    target_url: str,
    minutes: int = 60,
    ajax_spider: bool = True,
    auth_header: str = "",
    ctf=None,
) -> str:
    """
    Run ZAP full active scan with comprehensive attack testing.

    The full scan includes active scanning which actually attacks the target
    to find vulnerabilities like SQL injection, XSS, and more.

    Args:
        target_url: Target URL to scan
        minutes: Maximum scan duration in minutes (default: 60)
        ajax_spider: Enable Ajax spider (default: True)
        auth_header: Authorization header value for authenticated scanning
        ctf: CTF context for execution

    Returns:
        str: ZAP full scan results with active findings
    """
    cmd_parts = [
        "zap-full-scan.py",
        f"-t {target_url}",
        f"-m {minutes}",
        "-J zap-full-report.json",
    ]

    if ajax_spider:
        cmd_parts.append("-j")

    if auth_header:
        cmd_parts.append(f'-z "-config replacer.full_list(0).description=auth '
                         f'-config replacer.full_list(0).enabled=true '
                         f'-config replacer.full_list(0).matchtype=REQ_HEADER '
                         f'-config replacer.full_list(0).matchstr=Authorization '
                         f'-config replacer.full_list(0).replacement={auth_header}"')

    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def zap_api_scan(
    openapi_url: str,
    target_url: str = "",
    format: str = "openapi",
    ctf=None,
) -> str:
    """
    Run ZAP API scan using an OpenAPI/Swagger specification.

    Imports the API specification and performs targeted security testing
    on all discovered API endpoints.

    Args:
        openapi_url: URL or path to OpenAPI/Swagger specification
        target_url: Override target URL (if different from spec)
        format: Specification format (openapi, soap, graphql)
        ctf: CTF context for execution

    Returns:
        str: ZAP API scan results
    """
    cmd_parts = [
        "zap-api-scan.py",
        f"-t {openapi_url}",
        f"-f {format}",
        "-J zap-api-report.json",
    ]

    if target_url:
        cmd_parts.append(f"-O {target_url}")

    return run_command(" ".join(cmd_parts), ctf=ctf)
