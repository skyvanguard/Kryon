"""Format vulnerability correlation data for D3.js visualization."""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)


def format_graph_for_d3(correlation_result: dict | str) -> dict:
    """Convert correlation engine output to D3 force-directed graph format.

    Returns: {nodes: [...], edges: [...], chains: [...], risk_amplification: float}
    """
    if isinstance(correlation_result, str):
        try:
            correlation_result = json.loads(correlation_result)
        except (json.JSONDecodeError, TypeError):
            return {"nodes": [], "edges": [], "chains": [], "risk_amplification": 0.0}

    nodes = []
    edges = []
    node_ids = set()

    # Build nodes from exploitation_priority or analyzed vulns
    for vuln in correlation_result.get("exploitation_priority", []):
        vid = vuln.get("id", str(len(nodes)))
        if vid not in node_ids:
            nodes.append(
                {
                    "id": vid,
                    "label": vuln.get("type", "unknown"),
                    "severity": vuln.get("severity", "medium"),
                    "group": _severity_group(vuln.get("severity", "medium")),
                }
            )
            node_ids.add(vid)

    # Build edges from relationships
    for rel in correlation_result.get("relationships", []):
        source = rel.get("vulnerability_1")
        target = rel.get("vulnerability_2")
        if source and target:
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "type": rel.get("relationship_type", "related"),
                    "label": rel.get("description", ""),
                }
            )

    # Build chain data
    chains = []
    for chain in correlation_result.get("attack_chains", []):
        stages = chain.get("stages", [])
        chain_data = {
            "type": chain.get("chain_type", "unknown"),
            "description": chain.get("description", ""),
            "impact": chain.get("impact", "medium"),
            "steps": [{"id": s.get("id"), "type": s.get("type")} for s in stages],
        }
        chains.append(chain_data)

        # Add chain edges
        for i in range(len(stages) - 1):
            edges.append(
                {
                    "source": stages[i].get("id"),
                    "target": stages[i + 1].get("id"),
                    "type": "chain",
                    "label": chain.get("chain_type", ""),
                }
            )

    risk_amp = correlation_result.get("combined_impact_score", 0.0)

    return {
        "nodes": nodes,
        "edges": edges,
        "chains": chains,
        "risk_amplification": risk_amp,
    }


def format_kill_chain(chain: dict) -> list[dict]:
    """Format a single attack chain as a linear kill chain timeline."""
    steps = []
    stages = chain.get("stages", chain.get("steps", []))

    for i, stage in enumerate(stages):
        steps.append(
            {
                "order": i + 1,
                "id": stage.get("id", f"step-{i}"),
                "type": stage.get("type", "unknown"),
                "severity": stage.get("severity", "medium"),
                "description": stage.get("description", ""),
                "is_first": i == 0,
                "is_last": i == len(stages) - 1,
            }
        )

    return steps


def _severity_group(severity: str) -> int:
    """Map severity to D3 group number for coloring."""
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity.lower(), 2)
