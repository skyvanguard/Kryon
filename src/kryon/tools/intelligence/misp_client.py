"""MISP — Malware Information Sharing Platform client."""

import json
import os

from kryon.sdk.agents import function_tool
from kryon.server.logging_config import get_logger
from kryon.tools.common import run_command

logger = get_logger(__name__)


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
    logger.info("misp_search_events called query=%s type_attribute=%s limit=%d", query, type_attribute, limit)
    misp_url = os.getenv("MISP_URL", "")
    misp_key = os.getenv("MISP_KEY", "")

    if not misp_url or not misp_key:
        return json.dumps({"error": "MISP_URL and MISP_KEY environment variables required", "status": "failed"})

    try:
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
    except Exception as exc:
        logger.error("misp_search_events failed: %s", exc)
        return json.dumps({"error": str(exc), "status": "failed"})


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
    logger.info("misp_add_event called title=%s threat_level=%d", title, threat_level)
    misp_url = os.getenv("MISP_URL", "")
    misp_key = os.getenv("MISP_KEY", "")

    if not misp_url or not misp_key:
        return json.dumps({"error": "MISP_URL and MISP_KEY environment variables required", "status": "failed"})

    try:
        attributes = json.loads(attributes_json) if isinstance(attributes_json, str) else attributes_json
    except json.JSONDecodeError:
        logger.error("misp_add_event: invalid JSON for attributes")
        return json.dumps({"error": "Invalid JSON for attributes", "status": "failed"})

    try:
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
    except Exception as exc:
        logger.error("misp_add_event failed: %s", exc)
        return json.dumps({"error": str(exc), "status": "failed"})
