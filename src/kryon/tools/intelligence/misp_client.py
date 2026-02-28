"""MISP — Malware Information Sharing Platform client."""

import json
import os

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def misp_search_events(
    query: str = "",
    type_attribute: str = "",
    limit: int = 50,
    ctf=None,
) -> str:
    """
    Search MISP for threat intelligence events.

    Args:
        query: Search query (event info, attribute value, tag)
        type_attribute: Filter by attribute type (ip-src, domain, md5, etc.)
        limit: Maximum results
        ctf: CTF context

    Returns:
        str: MISP events matching the query
    """
    misp_url = os.getenv("MISP_URL", "")
    misp_key = os.getenv("MISP_KEY", "")

    if not misp_url or not misp_key:
        return "Error: MISP_URL and MISP_KEY environment variables required."

    search_body = {"limit": limit, "returnFormat": "json"}
    if query:
        search_body["value"] = query
    if type_attribute:
        search_body["type_attribute"] = type_attribute

    body_json = json.dumps(search_body)
    cmd = (
        f"curl -s -X POST '{misp_url}/events/restSearch' "
        f"-H 'Authorization: {misp_key}' "
        f"-H 'Content-Type: application/json' "
        f"-H 'Accept: application/json' "
        f"-d '{body_json}'"
    )

    return run_command(cmd, ctf=ctf)


@function_tool
def misp_add_event(
    title: str,
    description: str,
    threat_level: int = 3,
    attributes_json: str = "[]",
    ctf=None,
) -> str:
    """
    Create a new MISP event with attributes.

    Args:
        title: Event title/info
        description: Event description
        threat_level: Threat level (1=High, 2=Medium, 3=Low, 4=Undefined)
        attributes_json: JSON array of attributes [{type, value, category}]
        ctf: CTF context

    Returns:
        str: Created event details
    """
    misp_url = os.getenv("MISP_URL", "")
    misp_key = os.getenv("MISP_KEY", "")

    if not misp_url or not misp_key:
        return "Error: MISP_URL and MISP_KEY environment variables required."

    try:
        attributes = json.loads(attributes_json) if isinstance(attributes_json, str) else attributes_json
    except json.JSONDecodeError:
        return "Error: Invalid JSON for attributes"

    event_body = {
        "Event": {
            "info": title,
            "threat_level_id": str(threat_level),
            "analysis": "0",
            "distribution": "0",
            "Attribute": [
                {
                    "type": attr.get("type", "text"),
                    "value": attr.get("value", ""),
                    "category": attr.get("category", "External analysis"),
                }
                for attr in attributes
            ],
        }
    }

    body_json = json.dumps(event_body)
    cmd = (
        f"curl -s -X POST '{misp_url}/events/add' "
        f"-H 'Authorization: {misp_key}' "
        f"-H 'Content-Type: application/json' "
        f"-H 'Accept: application/json' "
        f"-d '{body_json}'"
    )

    return run_command(cmd, ctf=ctf)
