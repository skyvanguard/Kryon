"""Detection validation — verify SIEM/EDR alerts fire after attack simulation."""

import json
import logging
import shlex

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command
from kryon.tools.common._url_validation import validate_external_url

_log = logging.getLogger(__name__)
_VALID_SIEM_TYPES = {"elastic", "splunk"}


@function_tool
def validate_detection(
    technique_id: str,
    siem_type: str = "elastic",
    siem_endpoint: str = "",
    time_window_minutes: int = 15,
    ctf=None,
) -> str:
    """
    Validate that a SIEM detects a specific ATT&CK technique.

    After simulating an attack, check if the SIEM generated an alert
    for the corresponding technique within the time window.

    Args:
        technique_id: MITRE ATT&CK technique ID that was simulated
        siem_type: SIEM platform (elastic, splunk)
        siem_endpoint: SIEM API endpoint URL
        time_window_minutes: Time window to search for alerts
        ctf: CTF context

    Returns:
        str: Detection validation results (detected/not detected + details)
    """
    if siem_type not in _VALID_SIEM_TYPES:
        return f"Error: Unsupported SIEM type '{siem_type}'. Supported: {sorted(_VALID_SIEM_TYPES)}"

    if not siem_endpoint:
        return (
            f"Detection validation for {technique_id}:\n"
            f"SIEM type: {siem_type}\n"
            f"Status: SKIPPED — no SIEM endpoint configured.\n"
            f"Configure siem_endpoint to enable live validation."
        )

    if not validate_external_url(siem_endpoint):
        return f"Error: SIEM endpoint URL blocked by SSRF policy: {siem_endpoint}"

    safe_endpoint = shlex.quote(siem_endpoint)

    if siem_type == "elastic":
        query = json.dumps(
            {
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"threat.technique.id": technique_id}},
                            {"range": {"@timestamp": {"gte": f"now-{int(time_window_minutes)}m"}}},
                        ]
                    }
                },
                "size": 10,
            }
        )
        cmd = f"curl -s -X POST {safe_endpoint}/_search -H 'Content-Type: application/json' -d {shlex.quote(query)}"
    else:  # splunk
        search_query = f'search index=* mitre_technique_id="{technique_id}" earliest=-{int(time_window_minutes)}m'
        cmd = f"curl -s -k {safe_endpoint}/services/search/jobs/export -d {shlex.quote(f'search={search_query}&output_mode=json')}"

    result = run_command(cmd, ctf=ctf)
    return (
        f"Detection validation for {technique_id}:\nSIEM: {siem_type}\nTime window: {time_window_minutes}m\n\n{result}"
    )


@function_tool
def check_siem_alert(
    query: str,
    siem_type: str = "elastic",
    siem_endpoint: str = "",
    time_range: str = "15m",
    ctf=None,
) -> str:
    """
    Run a custom SIEM query to check for alerts or events.

    Args:
        query: Search query (Elasticsearch DSL, Splunk SPL, or KQL)
        siem_type: SIEM platform (elastic, splunk)
        siem_endpoint: SIEM API endpoint URL
        time_range: Time range to search (e.g. 15m, 1h, 24h)
        ctf: CTF context

    Returns:
        str: Query results from the SIEM
    """
    if siem_type not in _VALID_SIEM_TYPES:
        return f"Error: Unsupported SIEM type '{siem_type}'"

    if not siem_endpoint:
        return "Error: No SIEM endpoint configured. Set siem_endpoint parameter."

    if not validate_external_url(siem_endpoint):
        return f"Error: SIEM endpoint URL blocked by SSRF policy: {siem_endpoint}"

    safe_endpoint = shlex.quote(siem_endpoint)
    safe_query = shlex.quote(query)

    if siem_type == "elastic":
        cmd = f"curl -s -X POST {safe_endpoint}/_search -H 'Content-Type: application/json' -d {safe_query}"
    else:  # splunk
        cmd = f"curl -s -k {safe_endpoint}/services/search/jobs/export -d {shlex.quote(f'search={query}&output_mode=json')}"

    return run_command(cmd, ctf=ctf)
