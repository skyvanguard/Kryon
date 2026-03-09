"""VM Scanner Import Tools — import findings from vulnerability management platforms.

Provides tools to import and normalize findings from:
- Qualys VM Detection API
- Tenable.io Vulnerability Export API
- Rapid7 InsightVM API
- Nmap XML output files
- Nuclei JSONL output files

All tools return a unified format:
    {source: str, findings: [{title, severity, target, details}], count: int}
"""

from __future__ import annotations

import json
import subprocess
import defusedxml.ElementTree as ET  # noqa: N817

from kryon.sdk.agents import function_tool
from kryon.tools.common._url_validation import validate_external_url

# ---------------------------------------------------------------------------
# Severity mappings
# ---------------------------------------------------------------------------

_QUALYS_SEVERITY_MAP = {
    "1": "info",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "critical",
}

_TENABLE_SEVERITY_MAP = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

_RAPID7_SEVERITY_MAP = {
    "critical": "critical",
    "severe": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "info": "info",
}

_NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _http_request(
    url: str,
    headers: dict | None = None,
    method: str = "GET",
    body: str | None = None,
    timeout: int = 60,
) -> str:
    """Execute an HTTP request via curl and return the response body.

    Uses subprocess + curl to avoid adding requests as a dependency.
    This is the single point of network access so tests can easily mock it.
    """
    cmd_parts = ["curl", "-s", "-S", "--max-time", str(timeout), "-X", method]
    if headers:
        for key, value in headers.items():
            cmd_parts.extend(["-H", f"{key}: {value}"])
    if body:
        cmd_parts.extend(["-d", body])
    cmd_parts.append(url)

    try:
        result = subprocess.run(  # noqa: S603
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
        if result.returncode != 0 and result.stderr:
            return json.dumps({"error": f"curl failed: {result.stderr.strip()}"})
        return result.stdout
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"HTTP request timed out after {timeout}s"})
    except Exception as e:
        return json.dumps({"error": f"HTTP request failed: {e}"})


def _build_response(source: str, findings: list[dict]) -> str:
    """Build a standardized JSON response string."""
    return json.dumps({"source": source, "findings": findings, "count": len(findings)})


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@function_tool(strict_mode=False)
def import_qualys_findings(
    api_url: str,
    api_key: str,
    scan_id: str = "",
) -> str:
    """Import vulnerability findings from the Qualys VM Detection API.

    Connects to a Qualys platform instance and retrieves host-level
    vulnerability detections. Maps QID severity (1-5) to KRYON severity
    (info/low/medium/high/critical).

    Args:
        api_url: Base URL of the Qualys API (e.g. https://qualysapi.qualys.com)
        api_key: Qualys API key or Basic auth token
        scan_id: Optional scan reference ID to filter results

    Returns:
        str: JSON with source, findings list [{title, severity, target, details}], count
    """
    ssrf_err = validate_external_url(api_url)
    if ssrf_err:
        return json.dumps({"error": ssrf_err})

    endpoint = f"{api_url.rstrip('/')}/api/2.0/fo/asset/host/vm/detection/"
    params = "action=list&output_format=JSON"
    if scan_id:
        params += f"&scan_ref={scan_id}"

    url = f"{endpoint}?{params}"
    headers = {"X-Requested-With": "KRYON", "Authorization": f"Basic {api_key}"}

    raw = _http_request(url, headers=headers)

    findings: list[dict] = []
    try:
        data = json.loads(raw)
        # Navigate Qualys nested response structure
        host_list = (
            data.get("HOST_LIST_VM_DETECTION_OUTPUT", {})
            .get("RESPONSE", {})
            .get("HOST_LIST", {})
            .get("HOST", [])
        )
        # Ensure host_list is always a list (single host comes as dict)
        if isinstance(host_list, dict):
            host_list = [host_list]

        for host in host_list:
            ip = host.get("IP", "unknown")
            detections = host.get("DETECTION_LIST", {}).get("DETECTION", [])
            if isinstance(detections, dict):
                detections = [detections]

            for det in detections:
                severity_raw = str(det.get("SEVERITY", "1"))
                findings.append(
                    {
                        "title": det.get("TITLE", f"QID-{det.get('QID', 'unknown')}"),
                        "severity": _QUALYS_SEVERITY_MAP.get(severity_raw, "info"),
                        "target": ip,
                        "details": {
                            "qid": det.get("QID"),
                            "type": det.get("TYPE"),
                            "first_found": det.get("FIRST_FOUND_DATETIME"),
                            "last_found": det.get("LAST_FOUND_DATETIME"),
                            "results": det.get("RESULTS", ""),
                        },
                    }
                )
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return json.dumps(
            {"source": "qualys", "error": f"Failed to parse Qualys response: {e}", "findings": [], "count": 0}
        )

    return _build_response("qualys", findings)


@function_tool(strict_mode=False)
def import_tenable_findings(
    api_url: str,
    access_key: str,
    secret_key: str,
    scan_id: str = "",
) -> str:
    """Import vulnerability findings from the Tenable.io Vulnerability API.

    Connects to Tenable.io and retrieves vulnerability data for a scan.
    Maps Tenable severity (0-4) to KRYON severity.

    Args:
        api_url: Base URL of Tenable.io API (e.g. https://cloud.tenable.com)
        access_key: Tenable.io API access key
        secret_key: Tenable.io API secret key
        scan_id: Scan ID to retrieve results for (optional)

    Returns:
        str: JSON with source, findings list [{title, severity, target, details}], count
    """
    ssrf_err = validate_external_url(api_url)
    if ssrf_err:
        return json.dumps({"error": ssrf_err})

    if scan_id:
        endpoint = f"{api_url.rstrip('/')}/scans/{scan_id}/vulnerabilities"
    else:
        endpoint = f"{api_url.rstrip('/')}/workbenches/vulnerabilities"

    headers = {
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
        "Accept": "application/json",
    }

    raw = _http_request(endpoint, headers=headers)

    findings: list[dict] = []
    try:
        data = json.loads(raw)
        vulns = data.get("vulnerabilities", [])

        for vuln in vulns:
            severity_raw = vuln.get("severity", 0)
            if isinstance(severity_raw, str):
                severity_raw = int(severity_raw)
            findings.append(
                {
                    "title": vuln.get("plugin_name", f"Plugin-{vuln.get('plugin_id', 'unknown')}"),
                    "severity": _TENABLE_SEVERITY_MAP.get(severity_raw, "info"),
                    "target": vuln.get("hostname", vuln.get("host_id", "unknown")),
                    "details": {
                        "plugin_id": vuln.get("plugin_id"),
                        "plugin_family": vuln.get("plugin_family"),
                        "count": vuln.get("count", 1),
                        "vpr_score": vuln.get("vpr_score"),
                    },
                }
            )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        return json.dumps(
            {"source": "tenable", "error": f"Failed to parse Tenable response: {e}", "findings": [], "count": 0}
        )

    return _build_response("tenable", findings)


@function_tool(strict_mode=False)
def import_rapid7_findings(
    api_url: str,
    api_key: str,
    site_id: str = "",
) -> str:
    """Import vulnerability findings from the Rapid7 InsightVM API.

    Connects to InsightVM and retrieves vulnerability data for a site.
    Maps Rapid7 severity labels to KRYON severity.

    Args:
        api_url: Base URL of InsightVM API (e.g. https://insightvm.example.com:3780)
        api_key: Rapid7 InsightVM API key
        site_id: Site ID to retrieve vulnerabilities for (optional)

    Returns:
        str: JSON with source, findings list [{title, severity, target, details}], count
    """
    ssrf_err = validate_external_url(api_url)
    if ssrf_err:
        return json.dumps({"error": ssrf_err})

    if site_id:
        endpoint = f"{api_url.rstrip('/')}/api/3/sites/{site_id}/vulnerabilities"
    else:
        endpoint = f"{api_url.rstrip('/')}/api/3/vulnerabilities"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }

    raw = _http_request(endpoint, headers=headers)

    findings: list[dict] = []
    try:
        data = json.loads(raw)
        resources = data.get("resources", [])

        for vuln in resources:
            severity_raw = str(vuln.get("severity", "info")).lower()
            findings.append(
                {
                    "title": vuln.get("title", f"Vuln-{vuln.get('id', 'unknown')}"),
                    "severity": _RAPID7_SEVERITY_MAP.get(severity_raw, "info"),
                    "target": vuln.get("host", vuln.get("asset", "unknown")),
                    "details": {
                        "id": vuln.get("id"),
                        "instances": vuln.get("instances", 0),
                        "cvss_score": vuln.get("cvss", {}).get("v3", {}).get("score")
                        if isinstance(vuln.get("cvss"), dict)
                        else None,
                        "references": vuln.get("references", []),
                    },
                }
            )
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return json.dumps(
            {"source": "rapid7", "error": f"Failed to parse Rapid7 response: {e}", "findings": [], "count": 0}
        )

    return _build_response("rapid7", findings)


@function_tool(strict_mode=False)
def import_nmap_xml(
    xml_file: str,
) -> str:
    """Import scan results from an nmap XML output file.

    Parses nmap XML format to extract hosts, open ports, services,
    and script output. Each host with open ports becomes a finding.

    Args:
        xml_file: Path to the nmap XML output file

    Returns:
        str: JSON with source, findings list [{title, severity, target, details}], count
    """
    findings: list[dict] = []

    try:
        tree = ET.parse(xml_file)  # noqa: S314
        root = tree.getroot()

        for host_elem in root.findall(".//host"):
            # Get host address
            addr_elem = host_elem.find("address")
            if addr_elem is None:
                continue
            host_ip = addr_elem.get("addr", "unknown")

            # Get hostname if available
            hostname = host_ip
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                hn = hostnames_elem.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", host_ip)

            # Parse ports
            ports_data = []
            for port_elem in host_elem.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_id = port_elem.get("portid", "?")
                protocol = port_elem.get("protocol", "tcp")
                service_elem = port_elem.find("service")
                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                service_product = service_elem.get("product", "") if service_elem is not None else ""
                service_version = service_elem.get("version", "") if service_elem is not None else ""

                # Collect script output
                scripts = []
                for script_elem in port_elem.findall("script"):
                    scripts.append(
                        {
                            "id": script_elem.get("id", ""),
                            "output": script_elem.get("output", ""),
                        }
                    )

                ports_data.append(
                    {
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                        "scripts": scripts,
                    }
                )

            if ports_data:
                # Determine severity based on services found
                severity = "info"
                high_risk_services = {"ftp", "telnet", "rlogin", "rexec", "vnc", "rdp", "smb", "ms-sql", "mysql"}
                service_names = {p["service"] for p in ports_data}
                if service_names & high_risk_services:
                    severity = "medium"

                port_summary = ", ".join(f"{p['port']}/{p['protocol']} ({p['service']})" for p in ports_data)
                findings.append(
                    {
                        "title": f"Open ports on {hostname}: {port_summary}",
                        "severity": severity,
                        "target": host_ip,
                        "details": {
                            "hostname": hostname,
                            "ports": ports_data,
                            "port_count": len(ports_data),
                        },
                    }
                )

    except ET.ParseError as e:
        return json.dumps(
            {"source": "nmap", "error": f"Failed to parse nmap XML: {e}", "findings": [], "count": 0}
        )
    except FileNotFoundError:
        return json.dumps(
            {"source": "nmap", "error": f"File not found: {xml_file}", "findings": [], "count": 0}
        )
    except Exception as e:
        return json.dumps(
            {"source": "nmap", "error": f"Error processing nmap file: {e}", "findings": [], "count": 0}
        )

    return _build_response("nmap", findings)


@function_tool(strict_mode=False)
def import_nuclei_jsonl(
    jsonl_file: str,
) -> str:
    """Import scan results from a nuclei JSONL output file.

    Parses nuclei's JSON Lines format where each line is a separate
    JSON finding with info.name, info.severity, host, and matched-at fields.

    Args:
        jsonl_file: Path to the nuclei JSONL output file

    Returns:
        str: JSON with source, findings list [{title, severity, target, details}], count
    """
    findings: list[dict] = []

    try:
        with open(jsonl_file) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    info = entry.get("info", {})
                    severity_raw = str(info.get("severity", "info")).lower()

                    findings.append(
                        {
                            "title": info.get("name", f"nuclei-finding-{line_num}"),
                            "severity": _NUCLEI_SEVERITY_MAP.get(severity_raw, "info"),
                            "target": entry.get("host", "unknown"),
                            "details": {
                                "template_id": entry.get("template-id", entry.get("templateID", "")),
                                "matched_at": entry.get("matched-at", entry.get("matched", "")),
                                "matcher_name": entry.get("matcher-name", ""),
                                "description": info.get("description", ""),
                                "tags": info.get("tags", []),
                                "reference": info.get("reference", []),
                                "curl_command": entry.get("curl-command", ""),
                            },
                        }
                    )
                except json.JSONDecodeError:
                    # Skip malformed lines
                    continue

    except FileNotFoundError:
        return json.dumps(
            {"source": "nuclei", "error": f"File not found: {jsonl_file}", "findings": [], "count": 0}
        )
    except Exception as e:
        return json.dumps(
            {"source": "nuclei", "error": f"Error processing nuclei file: {e}", "findings": [], "count": 0}
        )

    return _build_response("nuclei", findings)
