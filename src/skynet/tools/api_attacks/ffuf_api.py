"""
FFuf - API Fuzzing and Testing
===============================

FFuf (Fuzz Faster U Fool) specialized for API security testing including
REST APIs, GraphQL endpoints, and API parameter fuzzing.

PERFORMANCE: Results are cached with 1-hour TTL for API endpoint discovery
and parameter fuzzing operations.
"""

from skynet.cache import cache_scan_result
from skynet.sdk.agents import function_tool
from skynet.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="api_fuzz", ttl=3600)  # Cache for 1 hour
def ffuf_api_fuzz(
    url: str,
    wordlist: str,
    method: str = "GET",
    headers: str = "",
    data: str = "",
    match_status: str = "200,201,202,204,301,302,307,401,403",
    filter_status: str = "",
    filter_size: str = "",
    filter_words: str = "",
    threads: int = 40,
    rate: int = 0,
    timeout: int = 10,
    recursion: bool = False,
    recursion_depth: int = 1,
    extensions: str = "",
    output_format: str = "json",
    output_file: str = "",
    ctf=None,
) -> str:
    """
    Advanced API endpoint and parameter fuzzing.

    CACHED: Results cached for 1 hour to avoid redundant API fuzzing.
    Expected performance improvement: 10-30x for repeated fuzzing operations.

    FFuf is optimized for API security testing, discovering hidden endpoints,
    parameters, and vulnerabilities in REST APIs, GraphQL, and web services.

    Args:
        url: Target URL with FUZZ keyword (e.g., https://api.example.com/FUZZ)
        wordlist: Wordlist file path for fuzzing
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS)
        headers: Custom headers (format: "Header1: Value1" -H "Header2: Value2")
        data: POST/PUT data body (use FUZZ for parameter fuzzing)
        match_status: HTTP status codes to match (default: success codes)
        filter_status: HTTP status codes to filter out
        filter_size: Filter responses by size
        filter_words: Filter responses by word count
        threads: Number of concurrent threads (default: 40)
        rate: Requests per second limit (0 = unlimited)
        timeout: HTTP request timeout in seconds
        recursion: Enable recursive fuzzing
        recursion_depth: Maximum recursion depth
        extensions: File extensions to append (comma-separated)
        output_format: Output format (json, html, md, csv, ecsv)
        output_file: Save results to file
        ctf: CTF context for execution

    Returns:
        str: Discovered API endpoints, parameters, and responses

    Examples:
        # Discover API endpoints
        ffuf_api_fuzz(
            url="https://api.example.com/v1/FUZZ",
            wordlist="/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
        )

        # REST API version discovery
        ffuf_api_fuzz(
            url="https://api.example.com/FUZZ/users",
            wordlist="/usr/share/wordlists/api-versions.txt"
        )

        # GraphQL endpoint discovery
        ffuf_api_fuzz(
            url="https://example.com/FUZZ",
            wordlist="/usr/share/seclists/Discovery/Web-Content/graphql.txt",
            method="POST",
            headers='"Content-Type: application/json"'
        )

        # API parameter fuzzing (GET)
        ffuf_api_fuzz(
            url="https://api.example.com/users?FUZZ=test",
            wordlist="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
        )

        # API parameter fuzzing (POST JSON)
        ffuf_api_fuzz(
            url="https://api.example.com/login",
            method="POST",
            headers='"Content-Type: application/json"',
            data='{"FUZZ": "admin"}',
            wordlist="/usr/share/wordlists/parameters.txt"
        )

        # Hidden API methods discovery
        ffuf_api_fuzz(
            url="https://api.example.com/users/123",
            method="OPTIONS",
            wordlist="/usr/share/wordlists/http-methods.txt"
        )

        # Authenticated API fuzzing
        ffuf_api_fuzz(
            url="https://api.example.com/v2/FUZZ",
            wordlist="/usr/share/wordlists/api-endpoints.txt",
            headers='"Authorization: Bearer eyJhbGc..."'
        )

        # Rate-limited API fuzzing
        ffuf_api_fuzz(
            url="https://api.example.com/FUZZ",
            wordlist="/usr/share/wordlists/endpoints.txt",
            rate=10,  # 10 requests per second
            timeout=15
        )

        # Recursive API discovery
        ffuf_api_fuzz(
            url="https://api.example.com/FUZZ",
            wordlist="/usr/share/wordlists/api-paths.txt",
            recursion=True,
            recursion_depth=2
        )

        # API file extension fuzzing
        ffuf_api_fuzz(
            url="https://api.example.com/swagger",
            wordlist="/usr/share/wordlists/files.txt",
            extensions=".json,.yaml,.yml"
        )

    API Testing Scenarios:

    REST API Discovery:
        - /api/v1/users
        - /api/v2/admin
        - /v1/internal
        - /api/debug

    GraphQL Endpoints:
        - /graphql
        - /graphiql
        - /api/graphql
        - /v1/gql

    API Documentation:
        - /swagger.json
        - /api-docs
        - /openapi.json
        - /redoc

    Hidden Parameters:
        - debug=1
        - admin=true
        - internal=yes
        - test_mode=1

    Common API Patterns:
        - /api/{version}/{resource}
        - /v{version}/{resource}
        - /{version}/api/{resource}
        - /api/{resource}/{id}

    HTTP Methods to Test:
        - GET, POST, PUT, DELETE (standard CRUD)
        - PATCH (partial updates)
        - OPTIONS (CORS, method discovery)
        - HEAD (metadata only)

    Authentication Headers:
        - Authorization: Bearer {token}
        - X-API-Key: {api_key}
        - X-Auth-Token: {token}
        - Cookie: session={session_id}

    Security Note:
        API fuzzing can trigger rate limiting, logging, and alerts.
        Always use appropriate rate limiting and obtain authorization
        before testing production APIs.
    """
    cmd_parts = ["ffuf", "-u", url, "-w", wordlist]

    # HTTP method
    if method != "GET":
        cmd_parts.extend(["-X", method])

    # Custom headers
    if headers:
        for header in headers.split("-H"):
            header = header.strip()
            if header:
                cmd_parts.extend(["-H", header])

    # POST/PUT data
    if data:
        cmd_parts.extend(["-d", data])

    # Matching filters
    if match_status:
        cmd_parts.extend(["-mc", match_status])

    # Negative filters
    if filter_status:
        cmd_parts.extend(["-fc", filter_status])

    if filter_size:
        cmd_parts.extend(["-fs", filter_size])

    if filter_words:
        cmd_parts.extend(["-fw", filter_words])

    # Performance options
    cmd_parts.extend(["-t", str(threads)])

    if rate > 0:
        cmd_parts.extend(["-rate", str(rate)])

    cmd_parts.extend(["-timeout", str(timeout)])

    # Recursion
    if recursion:
        cmd_parts.extend(["-recursion"])
        cmd_parts.extend(["-recursion-depth", str(recursion_depth)])

    # Extensions
    if extensions:
        cmd_parts.extend(["-e", extensions])

    # Output
    if output_format:
        cmd_parts.extend(["-of", output_format])

    if output_file:
        cmd_parts.extend(["-o", output_file])

    # Silent mode for cleaner output
    cmd_parts.append("-s")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
