"""Intelligence tools for KRYON agents — MITRE mapping, CVE enrichment, IoC checking."""

from __future__ import annotations

import json

from kryon.sdk.agents import RunContextWrapper, function_tool


@function_tool
async def map_to_mitre(
    ctx: RunContextWrapper, finding: str, tool_name: str = ""
) -> str:
    """Map a security finding to MITRE ATT&CK techniques.

    Args:
        finding: Description of the security finding.
        tool_name: Name of the tool that produced the finding (e.g. nmap, sqlmap).

    Returns:
        JSON array of MITRE ATT&CK technique mappings.
    """
    from kryon.intelligence.mitre import MITREMapper

    mapper = MITREMapper()
    mappings = mapper.map_finding(finding, tool_name=tool_name)
    return json.dumps([m.model_dump() for m in mappings], indent=2)


@function_tool
async def enrich_cve(ctx: RunContextWrapper, cve_id: str) -> str:
    """Get enriched CVE details including EPSS score and exploit availability.

    Args:
        cve_id: CVE identifier (e.g. CVE-2024-12345).

    Returns:
        JSON with EPSS score, CISA KEV status, and exploit references.
    """
    from kryon.intelligence.cve_enrichment import CVEEnricher

    enricher = CVEEnricher()
    detail = await enricher.enrich(cve_id)
    return json.dumps(detail.model_dump(), indent=2)


@function_tool
async def check_ioc(ctx: RunContextWrapper, indicator: str) -> str:
    """Check an IP, domain, or hash against threat intelligence feeds.

    Args:
        indicator: The indicator value (IP address, domain, or file hash).

    Returns:
        JSON with threat feed results.
    """
    from kryon.intelligence.threat_feeds import ThreatFeedAggregator

    feeds = ThreatFeedAggregator()

    # Auto-detect indicator type
    import re

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
        result = await feeds.check_ip(indicator)
    elif re.match(r"^[a-fA-F0-9]{32,64}$", indicator):
        result = await feeds.check_hash(indicator)
    else:
        result = await feeds.check_domain(indicator)

    return json.dumps(result, indent=2)


@function_tool
async def get_attack_surface_mapping(
    ctx: RunContextWrapper, findings_json: str
) -> str:
    """Generate MITRE ATT&CK coverage map from a list of findings.

    Args:
        findings_json: JSON array of finding objects with 'title', 'description', and 'tool_source' fields.

    Returns:
        JSON with tactic coverage summary and technique details.
    """
    from kryon.intelligence.mitre import MITREMapper

    mapper = MITREMapper()
    findings = json.loads(findings_json)
    all_mappings = []

    for f in findings:
        text = f"{f.get('title', '')} {f.get('description', '')}"
        tool = f.get("tool_source", "")
        mappings = mapper.map_finding(text, tool_name=tool)
        all_mappings.extend(mappings)

    summary = mapper.get_tactic_summary(all_mappings)
    techniques = list({m.technique_id: m.model_dump() for m in all_mappings}.values())

    return json.dumps(
        {
            "tactic_coverage": summary,
            "tactics_covered": len(summary),
            "tactics_total": 14,
            "techniques_mapped": len(techniques),
            "techniques": techniques,
        },
        indent=2,
    )
