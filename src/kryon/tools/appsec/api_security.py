"""API Security testing — OWASP API Top 10 checks."""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def api_security_scan(
    target_url: str,
    openapi_spec: str = "",
    checks: str = "all",
    auth_token: str = "",
    ctf=None,
) -> str:
    """
    Run comprehensive API security scan using nuclei with API templates.

    Tests for common API vulnerabilities including BOLA, broken authentication,
    excessive data exposure, and security misconfigurations.

    Args:
        target_url: Base URL of the API to test
        openapi_spec: Path or URL to OpenAPI/Swagger specification
        checks: Check categories (all, auth, injection, bola, rate-limit, config)
        auth_token: Bearer token for authenticated testing
        ctf: CTF context for execution

    Returns:
        str: API security scan findings
    """
    cmd_parts = ["nuclei", f"-target {target_url}", "-t http/vulnerabilities/"]

    if checks != "all":
        tag_map = {
            "auth": "auth",
            "injection": "injection",
            "bola": "idor",
            "rate-limit": "ratelimit",
            "config": "misconfig",
        }
        tags = [tag_map.get(c.strip(), c.strip()) for c in checks.split(",")]
        cmd_parts.append(f"-tags {','.join(tags)}")

    if auth_token:
        cmd_parts.append(f"-H 'Authorization: Bearer {auth_token}'")

    cmd_parts.append("-jsonl")

    result = run_command(" ".join(cmd_parts), ctf=ctf)

    if openapi_spec:
        zap_result = run_command(
            f"zap-api-scan.py -t {openapi_spec} -f openapi -J api-scan.json",
            ctf=ctf,
        )
        result += f"\n\n--- ZAP API Scan ---\n{zap_result}"

    return result


@function_tool
def owasp_api_top10_check(
    target_url: str,
    openapi_spec: str = "",
    severity_threshold: str = "medium",
    ctf=None,
) -> str:
    """
    Check API against OWASP API Security Top 10 (2023).

    Performs targeted checks for each category:
    API1-BOLA, API2-Auth, API4-Rate-Limit, API7-SSRF, API8-Misconfig.

    Args:
        target_url: Base URL of the API
        openapi_spec: Path or URL to OpenAPI specification
        severity_threshold: Minimum severity to report (critical, high, medium, low)
        ctf: CTF context for execution

    Returns:
        str: OWASP API Top 10 assessment results
    """
    checks = [
        ("API1-BOLA", f"nuclei -target {target_url} -tags idor -jsonl"),
        ("API2-Auth", f"nuclei -target {target_url} -tags auth -jsonl"),
        ("API4-Rate-Limit", f"nuclei -target {target_url} -tags ratelimit -jsonl"),
        ("API7-SSRF", f"nuclei -target {target_url} -tags ssrf -jsonl"),
        ("API8-Misconfig", f"nuclei -target {target_url} -tags misconfig -jsonl"),
    ]

    results = []
    for category, cmd in checks:
        output = run_command(cmd, ctf=ctf)
        results.append(f"=== {category} ===\n{output}")

    return "\n\n".join(results)
