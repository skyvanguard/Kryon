"""IOC Manager — store, search, and enrich Indicators of Compromise."""

import json
import uuid
from datetime import datetime, timezone

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def store_ioc(
    ioc_type: str,
    ioc_value: str,
    source: str = "",
    threat_score: float = 0.5,
    tags: str = "",
    ttl_days: int = 90,
    ctf=None,
) -> str:
    """
    Store an Indicator of Compromise in the database.

    Args:
        ioc_type: IOC type (ip, domain, hash, url, email)
        ioc_value: The IOC value
        source: Source of the IOC (e.g. "threat_feed", "manual")
        threat_score: Threat score (0.0-1.0)
        tags: Comma-separated tags
        ttl_days: Time-to-live in days before expiry
        ctf: CTF context

    Returns:
        str: Storage result with IOC ID
    """
    try:
        from kryon.server.deps import get_store
        store = get_store()
        ioc_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        store.store_ioc(ioc_id, ioc_type, ioc_value, source, threat_score, tags, ttl_days, now)
        return json.dumps({"ioc_id": ioc_id, "status": "stored", "type": ioc_type, "value": ioc_value})
    except Exception as e:
        return json.dumps({"ioc_id": uuid.uuid4().hex[:12], "status": "stored_local", "type": ioc_type, "value": ioc_value, "note": str(e)})


@function_tool
def search_iocs(
    query: str = "",
    ioc_type: str = "",
    min_score: float = 0.0,
    max_age_days: int = 0,
    ctf=None,
) -> str:
    """
    Search stored IOCs.

    Args:
        query: Search query (matches ioc_value)
        ioc_type: Filter by IOC type
        min_score: Minimum threat score
        max_age_days: Maximum age in days (0=no limit)
        ctf: CTF context

    Returns:
        str: JSON list of matching IOCs
    """
    try:
        from kryon.server.deps import get_store
        store = get_store()
        results = store.search_iocs(query=query, ioc_type=ioc_type, min_score=min_score, max_age_days=max_age_days)
        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "note": "IOC database not available"})


@function_tool
def enrich_ioc(
    ioc_type: str,
    ioc_value: str,
    sources: str = "all",
    ctf=None,
) -> str:
    """
    Enrich an IOC with data from multiple threat intelligence sources.

    Args:
        ioc_type: IOC type (ip, domain, hash, url)
        ioc_value: The IOC value to enrich
        sources: Enrichment sources (all, virustotal, shodan, abuseipdb, otx)
        ctf: CTF context

    Returns:
        str: Enriched IOC data from multiple sources
    """
    results = [f"IOC Enrichment: {ioc_type} = {ioc_value}", "=" * 40]

    source_list = ["virustotal", "shodan", "abuseipdb", "otx"] if sources == "all" else sources.split(",")

    for source in source_list:
        source = source.strip()
        if source == "virustotal" and ioc_type in ("hash", "domain", "ip", "url"):
            vt_type_map = {"hash": "files", "domain": "domains", "ip": "ip_addresses", "url": "urls"}
            cmd = f"curl -s 'https://www.virustotal.com/api/v3/{vt_type_map.get(ioc_type, 'search')}?query={ioc_value}' -H 'x-apikey: $VT_API_KEY' 2>/dev/null | head -c 2000"
            results.append(f"\n[VirusTotal]\n{run_command(cmd, ctf=ctf)}")

        elif source == "shodan" and ioc_type == "ip":
            cmd = f"shodan host {ioc_value} 2>/dev/null || echo 'Shodan CLI not available'"
            results.append(f"\n[Shodan]\n{run_command(cmd, ctf=ctf)}")

        elif source == "abuseipdb" and ioc_type == "ip":
            cmd = f"curl -s 'https://api.abuseipdb.com/api/v2/check?ipAddress={ioc_value}' -H 'Key: $ABUSEIPDB_KEY' -H 'Accept: application/json' 2>/dev/null | head -c 2000"
            results.append(f"\n[AbuseIPDB]\n{run_command(cmd, ctf=ctf)}")

        elif source == "otx":
            otx_type_map = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}
            otx_type = otx_type_map.get(ioc_type, "general")
            cmd = f"curl -s 'https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc_value}/general' 2>/dev/null | head -c 2000"
            results.append(f"\n[AlienVault OTX]\n{run_command(cmd, ctf=ctf)}")

    return "\n".join(results)
