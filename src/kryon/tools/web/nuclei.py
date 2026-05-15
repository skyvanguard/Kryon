"""
Nuclei - Vulnerability Scanner
==============================

Nuclei is a fast, template-based vulnerability scanner with 1000+
templates for detecting security vulnerabilities across applications,
networks, and services.

PERFORMANCE: Results are cached with 12-hour TTL to avoid redundant
vulnerability scans and improve response times by 10-30x for repeated scans.
"""

import re

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command

# Markers Nuclei prints to stdout when a scan failed to actually execute.
# Detect these so the agent does NOT interpret a failed scan as "0 findings".
_NUCLEI_FATAL_PATTERNS = (
    re.compile(r"\[FTL\]"),
    re.compile(r"\[FATAL\]"),
    re.compile(r"could not find template", re.IGNORECASE),
    re.compile(r"no templates provided for scan", re.IGNORECASE),
    re.compile(r"could not run nuclei", re.IGNORECASE),
)


def _detect_nuclei_failure(output: str) -> str | None:
    """Return a short reason string if the Nuclei output indicates the scan
    didn't actually run. Otherwise return None.
    """
    if not output:
        return "empty_output"
    for pat in _NUCLEI_FATAL_PATTERNS:
        m = pat.search(output)
        if m:
            line = ""
            for raw in output.splitlines():
                if pat.search(raw):
                    line = raw.strip()
                    break
            return line or m.group(0)
    return None


def _wrap_failed_scan(reason: str, raw_output: str) -> str:
    """Prefix the raw output with an unambiguous error block so the LLM
    cannot mistake a non-executed scan for a clean result.
    """
    return (
        "[KRYON_TOOL_ERROR] nuclei_scan did NOT execute successfully.\n"
        f"Reason: {reason}\n"
        "IMPORTANT: do NOT infer 'no vulnerabilities found'. The scan never ran.\n"
        "Suggested retry: omit `templates=` for the default scan, or use `templates='cves/'`.\n"
        "\n--- raw output below ---\n"
        f"{raw_output}"
    )


@function_tool
@cache_scan_result(scan_type="vuln_scan", ttl=43200)  # Cache for 12 hours
def nuclei_scan(
    target: str,
    templates: str = "",
    workflows: str = "",
    severity: str = "critical,high,medium,low",
    tags: str = "",
    exclude_tags: str = "",
    author: str = "",
    rate_limit: int = 150,
    bulk_size: int = 25,
    concurrency: int = 25,
    timeout: int = 10,
    retries: int = 1,
    headers: str = "",
    custom_vars: str = "",
    automatic_scan: bool = False,
    new_templates: bool = False,
    template_list: str = "",
    silent: bool = False,
    verbose: bool = False,
    debug: bool = False,
    stats: bool = True,
    markdown_export: str = "",
    json_export: str = "",
    ctf=None,
) -> str:
    """
    Fast template-based vulnerability scanner with 1000+ security checks.

    CACHED: Results cached for 12 hours to avoid redundant vulnerability scans.
    Expected performance improvement: 10-30x for repeated scans.

    Nuclei uses YAML-based templates to send HTTP/DNS/TCP/etc requests
    and validates responses to detect security vulnerabilities, misconfigurations,
    and exposed services.

    Args:
        target: Target URL, IP, or file with targets
        templates: Nuclei template DIRECTORY path (must end in ``/``) or a
            specific template file. Common valid values:
            ``"cves/"``, ``"vulnerabilities/"``, ``"default-logins/"``,
            ``"exposures/"``, ``"misconfiguration/"``, ``"technologies/"``,
            ``"takeovers/"``. **Do NOT pass generic keywords like "web",
            "all", or "default"** — those are not nuclei templates and the
            scan will fail. Leave EMPTY (``""``) to use the auto-selected
            default template set, which is the right choice for most
            recon. F164 — invalid bare keywords are stripped automatically
            and the scan falls back to the default set.
        workflows: Workflow file or directory
        severity: Filter by severity (critical,high,medium,low,info)
        tags: Filter by tags (e.g., "cve,rce,sqli")
        exclude_tags: Exclude specific tags
        author: Filter by template author
        rate_limit: Maximum requests per second (default: 150)
        bulk_size: Max hosts analyzed in parallel (default: 25)
        concurrency: Max templates executed in parallel (default: 25)
        timeout: Request timeout in seconds
        retries: Number of retries for failed requests
        headers: Custom headers (e.g., "Authorization: Bearer token")
        custom_vars: Custom template variables (e.g., "username=admin")
        automatic_scan: Automatic web application technology detection
        new_templates: Run only new templates (added in last 30 days)
        template_list: File containing list of templates to execute
        silent: Display only results
        verbose: Verbose output
        debug: Debug mode
        stats: Display scan statistics
        markdown_export: Export results to markdown file
        json_export: Export results to JSON file
        ctf: CTF context for execution

    Returns:
        str: Discovered vulnerabilities and security issues

    Examples:
        # Quick vulnerability scan
        nuclei_scan(target="https://example.com")

        # Critical/High severity CVEs only
        nuclei_scan(
            target="https://example.com",
            severity="critical,high",
            tags="cve"
        )

        # SQL injection and XSS checks
        nuclei_scan(
            target="https://example.com",
            tags="sqli,xss",
            rate_limit=100
        )

        # Comprehensive scan with all templates
        nuclei_scan(
            target="https://example.com",
            automatic_scan=True,
            stats=True,
            json_export="results.json"
        )

        # Scan for specific CVE
        nuclei_scan(
            target="https://example.com",
            templates="cves/2021/CVE-2021-44228.yaml"
        )

        # Authenticated scan
        nuclei_scan(
            target="https://example.com",
            headers="Cookie: session=abc123; Authorization: Bearer token",
            tags="auth"
        )

        # Bulk scan from file
        nuclei_scan(
            target="targets.txt",
            severity="critical,high",
            bulk_size=50,
            concurrency=50,
            json_export="results.json"
        )

        # New templates only (latest vulnerabilities)
        nuclei_scan(
            target="https://example.com",
            new_templates=True,
            severity="critical,high"
        )

    Template Categories:
        - CVEs: Known CVE vulnerabilities (CVE-2021-*, CVE-2022-*, etc.)
        - Exposed Panels: Admin panels, login pages, dashboards
        - Exposures: Exposed files, directories, APIs, configs
        - Misconfigurations: Server misconfigs, cloud misconfigs
        - Default Logins: Default credentials on services
        - Takeovers: Subdomain takeovers, CORS, clickjacking
        - Technologies: Tech detection (similar to Wappalyzer)
        - Fuzzing: Parameter fuzzing, path fuzzing
        - Generic: XSS, SQLi, SSRF, LFI/RFI, etc.
        - DNS: DNS vulnerabilities and misconfigurations
        - Workflows: Multi-step attack chains

    Common Tags:
        - cve: CVE vulnerabilities
        - rce: Remote code execution
        - lfi: Local file inclusion
        - rfi: Remote file inclusion
        - ssrf: Server-side request forgery
        - sqli: SQL injection
        - xss: Cross-site scripting
        - xxe: XML external entity
        - idor: Insecure direct object reference
        - redirect: Open redirect
        - disclosure: Information disclosure
        - misconfig: Misconfiguration
        - exposure: Exposed service/file
        - takeover: Subdomain takeover
        - panel: Admin/login panels
        - token: Token exposure
        - default-login: Default credentials
        - tech: Technology detection
        - wordpress: WordPress specific
        - joomla: Joomla specific
        - drupal: Drupal specific
        - apache: Apache specific
        - nginx: Nginx specific
        - spring: Spring framework
        - tomcat: Apache Tomcat
        - iis: Microsoft IIS
        - aws: Amazon Web Services
        - azure: Microsoft Azure
        - gcp: Google Cloud Platform
        - k8s: Kubernetes
        - docker: Docker
    """
    # Build nuclei command
    cmd_parts = ["nuclei"]

    # Target (URL or file)
    if target.startswith("http://") or target.startswith("https://"):
        cmd_parts.extend(["-u", target])
    else:
        cmd_parts.extend(["-l", target])

    # Templates — F164: validate against LLM-invented bare keywords.
    # gpt-oss-20b / kryon-14b sometimes pass strings like "web", "all",
    # "default" thinking they are template categories. Nuclei rejects
    # those with "Could not find template" and the scan never runs.
    # Real nuclei template directories always contain ``/`` or end in
    # ``.yaml``. If the value looks like a bare keyword, drop it so the
    # scan falls through to the auto-selected default set.
    if templates:
        looks_like_path = "/" in templates or templates.startswith(".") or templates.endswith(".yaml")
        if looks_like_path:
            cmd_parts.extend(["-t", templates])
        # Otherwise silently fall back to default (nothing appended).
    elif workflows:
        cmd_parts.extend(["-w", workflows])
    elif automatic_scan:
        cmd_parts.append("-as")
    elif new_templates:
        cmd_parts.append("-nt")
    elif template_list:
        cmd_parts.extend(["-tl", template_list])

    # Filtering
    if severity:
        cmd_parts.extend(["-s", severity])

    if tags:
        cmd_parts.extend(["-tags", tags])

    if exclude_tags:
        cmd_parts.extend(["-etags", exclude_tags])

    if author:
        cmd_parts.extend(["-author", author])

    # Performance
    cmd_parts.extend(
        [
            "-rl",
            str(rate_limit),
            "-bs",
            str(bulk_size),
            "-c",
            str(concurrency),
            "-timeout",
            str(timeout),
            "-retries",
            str(retries),
        ]
    )

    # Headers
    if headers:
        for header in headers.split(";"):
            if header.strip():
                cmd_parts.extend(["-H", f'"{header.strip()}"'])

    # Custom variables
    if custom_vars:
        for var in custom_vars.split(","):
            if var.strip():
                cmd_parts.extend(["-V", var.strip()])

    # Output options
    if silent:
        cmd_parts.append("-silent")

    if verbose:
        cmd_parts.append("-v")

    if debug:
        cmd_parts.append("-debug")

    if stats:
        cmd_parts.append("-stats")

    # Export
    if markdown_export:
        cmd_parts.extend(["-me", markdown_export])

    if json_export:
        cmd_parts.extend(["-je", json_export])

    # Color output
    cmd_parts.append("-nc")  # No color for cleaner parsing

    command = " ".join(cmd_parts)
    output = run_command(command, ctf=ctf)
    failure = _detect_nuclei_failure(output)
    if failure:
        return _wrap_failed_scan(failure, output)
    return output


@function_tool
@cache_scan_result(scan_type="vuln_scan", ttl=43200)  # Cache for 12 hours
def nuclei_template_scan(
    target: str,
    template_path: str,
    variables: str = "",
    headers: str = "",
    rate_limit: int = 150,
    timeout: int = 10,
    verbose: bool = True,
    ctf=None,
) -> str:
    """
    Run a specific Nuclei template against target.

    CACHED: Results cached for 12 hours to avoid redundant scans.

    Useful for testing specific vulnerabilities or custom templates.

    Args:
        target: Target URL to scan
        template_path: Path to specific template file
        variables: Template variables (e.g., "username=admin,password=admin")
        headers: Custom HTTP headers
        rate_limit: Requests per second
        timeout: Request timeout
        verbose: Verbose output
        ctf: CTF context for execution

    Returns:
        str: Template scan results

    Examples:
        # Test for Log4Shell
        nuclei_template_scan(
            target="https://example.com",
            template_path="cves/2021/CVE-2021-44228.yaml"
        )

        # Custom template with variables
        nuclei_template_scan(
            target="https://example.com",
            template_path="/custom/templates/my-check.yaml",
            variables="api_key=xxx,endpoint=/api/v1"
        )
    """
    return nuclei_scan(
        target=target,
        templates=template_path,
        custom_vars=variables,
        headers=headers,
        rate_limit=rate_limit,
        timeout=timeout,
        verbose=verbose,
        ctf=ctf,
    )
