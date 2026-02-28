"""STIX/TAXII 2.1 — Threat intelligence sharing format and protocol."""

import json
import uuid
from datetime import datetime, timezone

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def create_stix_indicator(
    ioc_type: str,
    ioc_value: str,
    name: str = "",
    confidence: int = 75,
    tlp: str = "TLP:AMBER",
    ctf=None,
) -> str:
    """
    Create a STIX 2.1 Indicator object from an IOC.

    Args:
        ioc_type: IOC type (ipv4-addr, domain-name, url, file:hashes.MD5, email-addr)
        ioc_value: The IOC value
        name: Indicator name/title
        confidence: Confidence level (0-100)
        tlp: Traffic Light Protocol marking
        ctf: CTF context

    Returns:
        str: STIX 2.1 Indicator JSON
    """
    pattern_map = {
        "ipv4-addr": f"[ipv4-addr:value = '{ioc_value}']",
        "domain-name": f"[domain-name:value = '{ioc_value}']",
        "url": f"[url:value = '{ioc_value}']",
        "file:hashes.MD5": f"[file:hashes.MD5 = '{ioc_value}']",
        "file:hashes.SHA-256": f"[file:hashes.'SHA-256' = '{ioc_value}']",
        "email-addr": f"[email-addr:value = '{ioc_value}']",
    }

    pattern = pattern_map.get(ioc_type, f"[{ioc_type}:value = '{ioc_value}']")
    now = datetime.now(timezone.utc).isoformat() + "Z"

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": name or f"Indicator: {ioc_type} = {ioc_value}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "confidence": confidence,
        "object_marking_refs": [_tlp_to_marking(tlp)],
    }

    return json.dumps(indicator, indent=2)


def _tlp_to_marking(tlp: str) -> str:
    """Convert TLP label to STIX marking-definition ID."""
    tlp_map = {
        "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    }
    return tlp_map.get(tlp.upper(), tlp_map["TLP:AMBER"])


@function_tool
def create_stix_bundle(
    indicators_json: str,
    include_relationships: bool = True,
    ctf=None,
) -> str:
    """
    Create a STIX 2.1 Bundle from multiple indicators.

    Args:
        indicators_json: JSON array of STIX indicators
        include_relationships: Auto-generate relationships between indicators
        ctf: CTF context

    Returns:
        str: STIX 2.1 Bundle JSON
    """
    try:
        indicators = json.loads(indicators_json) if isinstance(indicators_json, str) else indicators_json
    except json.JSONDecodeError:
        return "Error: Invalid JSON for indicators"

    if not isinstance(indicators, list):
        indicators = [indicators]

    objects = list(indicators)

    if include_relationships and len(indicators) > 1:
        for i in range(len(indicators) - 1):
            rel = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat() + "Z",
                "modified": datetime.now(timezone.utc).isoformat() + "Z",
                "relationship_type": "related-to",
                "source_ref": indicators[i].get("id", ""),
                "target_ref": indicators[i + 1].get("id", ""),
            }
            objects.append(rel)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }

    return json.dumps(bundle, indent=2)


@function_tool
def taxii_poll_feed(
    server_url: str,
    collection_id: str = "",
    api_root: str = "",
    added_after: str = "",
    ctf=None,
) -> str:
    """
    Poll a TAXII 2.1 feed for threat intelligence.

    Args:
        server_url: TAXII server URL
        collection_id: Collection ID to poll (empty = list collections)
        api_root: API root path
        added_after: Only fetch objects added after this timestamp
        ctf: CTF context

    Returns:
        str: STIX objects from the TAXII feed
    """
    if not collection_id:
        # List available collections
        cmd = f"curl -s '{server_url}/{api_root}/collections/' -H 'Accept: application/taxii+json;version=2.1'"
        return run_command(cmd, ctf=ctf)

    url = f"{server_url}/{api_root}/collections/{collection_id}/objects/"
    if added_after:
        url += f"?added_after={added_after}"

    cmd = f"curl -s '{url}' -H 'Accept: application/taxii+json;version=2.1'"
    return run_command(cmd, ctf=ctf)
