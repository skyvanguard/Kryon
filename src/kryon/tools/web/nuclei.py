"""
Nuclei - Vulnerability Scanner
==============================

Nuclei is a fast, template-based vulnerability scanner with 1000+
templates for detecting security vulnerabilities across applications,
networks, and services.

PERFORMANCE: Results are cached with 12-hour TTL to avoid redundant
vulnerability scans and improve response times by 10-30x for repeated scans.

THROTTLING (F195 — POC-safe defaults for production targets):

  KRYON_NUCLEI_RATE_LIMIT     — overrides default rate_limit=150 (req/s).
                                Banca-safe: 50.
  KRYON_NUCLEI_BULK_SIZE      — overrides default bulk_size=25 (hosts/parallel).
                                Banca-safe: 10.
  KRYON_NUCLEI_CONCURRENCY    — overrides default concurrency=25 (templates/parallel).
                                Banca-safe: 10.

Env vars only override when the caller did NOT pass an explicit value
(i.e. the value still matches the function-tool default). Explicit
LLM/operator values always win.
"""

import os
import re

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command

# Defaults exposed to the function_tool signature. F195 — env-override
# logic compares against these to decide if the caller passed a value.
_DEFAULT_RATE_LIMIT = 150
_DEFAULT_BULK_SIZE = 25
_DEFAULT_CONCURRENCY = 25


def _env_int(name: str) -> int | None:
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


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


def _is_template_not_found(reason: str) -> bool:
    """True when the failure reason is a bad/missing template PATH (as opposed
    to nuclei being absent or a network error). These are recoverable by
    retrying with the default template set."""
    low = (reason or "").lower()
    return "could not find template" in low or "no templates provided" in low


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
    rate_limit: int = _DEFAULT_RATE_LIMIT,
    bulk_size: int = _DEFAULT_BULK_SIZE,
    concurrency: int = _DEFAULT_CONCURRENCY,
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
    # F195 — env-driven throttle. Override default values only when the
    # caller did NOT pass an explicit value. Explicit LLM/operator values
    # always win (banca-safe contract).
    if rate_limit == _DEFAULT_RATE_LIMIT:
        env_rl = _env_int("KRYON_NUCLEI_RATE_LIMIT")
        if env_rl is not None:
            rate_limit = env_rl
    # Merge the global research-identification header (KRYON_HTTP_EXTRA_HEADERS,
    # e.g. X-HackerOne-Research) into nuclei's -H set — required by some VDP
    # policies on ALL traffic. Explicit per-call headers keep priority (appended).
    from kryon.util.http_headers import header_semicolon_string  # noqa: PLC0415

    _global_h = header_semicolon_string()
    if _global_h:
        headers = f"{_global_h}; {headers}" if headers else _global_h
    if bulk_size == _DEFAULT_BULK_SIZE:
        env_bs = _env_int("KRYON_NUCLEI_BULK_SIZE")
        if env_bs is not None:
            bulk_size = env_bs
    if concurrency == _DEFAULT_CONCURRENCY:
        env_c = _env_int("KRYON_NUCLEI_CONCURRENCY")
        if env_c is not None:
            concurrency = env_c

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
    #
    # Template selectors are collected SEPARATELY so a failed scan can be
    # retried with the default set (base command sans templates).
    tmpl_parts: list[str] = []
    if templates:
        looks_like_path = "/" in templates or templates.startswith(".") or templates.endswith(".yaml")
        if looks_like_path:
            tmpl_parts.extend(["-t", templates])
        # Otherwise silently fall back to default (nothing appended).
    elif workflows:
        tmpl_parts.extend(["-w", workflows])
    elif automatic_scan:
        tmpl_parts.append("-as")
    elif new_templates:
        tmpl_parts.append("-nt")
    elif template_list:
        tmpl_parts.extend(["-tl", template_list])

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

    # OPSEC: nuclei is a Go binary, so torsocks (libc LD_PRELOAD) cannot wrap it —
    # route it through the configured anonymizing proxy via its native -proxy, or
    # an anonymized engagement leaks the real IP (same class as the ffuf leak).
    from kryon.util.env import anon_proxy  # noqa: PLC0415

    _anon = anon_proxy()
    if _anon:
        cmd_parts.extend(["-proxy", _anon])

    # base_parts = everything except template selectors, so a template-path
    # failure can be retried with the default set.
    base_parts = list(cmd_parts)
    command = " ".join(base_parts + tmpl_parts)
    output = run_command(command, ctf=ctf)
    failure = _detect_nuclei_failure(output)
    if failure:
        # #3 fix — the LLM routinely passes legacy template dirs (``cves/``,
        # ``vulnerabilities/``) that nuclei v3 nests under ``http/``, so the
        # scan dies with "could not find template" and the model loops. Auto-
        # retry ONCE with the default template set before surfacing an error.
        if tmpl_parts and _is_template_not_found(failure):
            retry_output = run_command(" ".join(base_parts), ctf=ctf)
            retry_failure = _detect_nuclei_failure(retry_output)
            if not retry_failure:
                return (
                    f"[nuclei] template path inválido ({failure}); se reintentó con el "
                    f"set por defecto y funcionó.\n\n--- resultados ---\n{retry_output}"
                )
            output = retry_output
            failure = retry_failure
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
