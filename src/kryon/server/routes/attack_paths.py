"""Attack path visualization API routes."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from kryon.server.auth import require_api_key
from kryon.server.deps import get_store
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["attack_paths"], dependencies=[Depends(require_api_key)])


class AnalyzeBody(BaseModel):
    finding_ids: list[str] = []


@router.post("/attack-paths/analyze")
async def analyze_attack_paths(body: AnalyzeBody) -> dict:
    """Analyze findings and return D3-compatible graph data."""
    store = get_store()
    findings = []
    for fid in body.finding_ids:
        f = store.get_finding_by_id(fid)
        if f:
            try:
                parsed = json.loads(f.finding_json) if f.finding_json else {}
                parsed["id"] = f.id
                findings.append(parsed)
            except (json.JSONDecodeError, TypeError):
                continue

    if not findings:
        return {"nodes": [], "edges": [], "chains": [], "risk_amplification": 0.0}

    from kryon.tools.intelligence.vulnerability_correlator import correlate_vulnerabilities_impl

    correlation = correlate_vulnerabilities_impl(json.dumps(findings))

    from kryon.intelligence.graph_formatter import format_graph_for_d3

    logger.info("Attack paths analyzed: %d findings", len(findings))
    return format_graph_for_d3(correlation)


@router.get("/attack-paths/client/{client_id}")
async def client_attack_paths(client_id: str) -> dict:
    """Auto-analyze all findings for a client."""
    store = get_store()
    raw_findings = store.get_client_findings(client_id, status="open")
    if not raw_findings:
        return {"nodes": [], "edges": [], "chains": [], "risk_amplification": 0.0}

    findings = []
    for f in raw_findings:
        try:
            parsed = json.loads(f.finding_json) if f.finding_json else {}
            parsed["id"] = f.id
            findings.append(parsed)
        except (json.JSONDecodeError, TypeError):
            continue

    from kryon.tools.intelligence.vulnerability_correlator import correlate_vulnerabilities_impl

    correlation = correlate_vulnerabilities_impl(json.dumps(findings))

    from kryon.intelligence.graph_formatter import format_graph_for_d3

    return format_graph_for_d3(correlation)


@router.get("/attack-paths/chains/{client_id}")
async def client_chains(client_id: str) -> dict:
    """List detected attack chains for a client."""
    store = get_store()
    raw_findings = store.get_client_findings(client_id)
    findings = []
    for f in raw_findings:
        try:
            parsed = json.loads(f.finding_json) if f.finding_json else {}
            parsed["id"] = f.id
            findings.append(parsed)
        except (json.JSONDecodeError, TypeError):
            continue

    from kryon.tools.intelligence.vulnerability_correlator import correlate_vulnerabilities_impl

    result = json.loads(correlate_vulnerabilities_impl(json.dumps(findings)))

    from kryon.intelligence.graph_formatter import format_kill_chain

    chains = []
    for chain in result.get("attack_chains", []):
        chains.append(
            {
                "type": chain.get("chain_type"),
                "description": chain.get("description"),
                "impact": chain.get("impact"),
                "steps": format_kill_chain(chain),
            }
        )

    return {"chains": chains, "total": len(chains)}
