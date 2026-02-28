"""MITRE ATT&CK Navigator layer export — generates Navigator JSON from findings."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from kryon.intelligence.models import Finding, MITREMapping


class NavigatorLayer:
    """Builder for MITRE ATT&CK Navigator JSON layers."""

    def __init__(self, name: str = "KRYON Assessment", description: str = ""):
        self.name = name
        self.description = description
        self._techniques: dict[str, dict] = {}  # technique_id -> {score, color, comment, ...}

    def add_technique(
        self,
        technique_id: str,
        tactic_id: str = "",
        score: int = 1,
        color: str = "",
        comment: str = "",
        metadata: list[dict] | None = None,
    ) -> None:
        """Add or update a technique in the layer."""
        key = f"{technique_id}|{tactic_id}"
        existing = self._techniques.get(key)
        if existing:
            existing["score"] = max(existing["score"], score)
            if comment:
                existing["comment"] = f"{existing.get('comment', '')}\n{comment}".strip()
        else:
            entry: dict = {"techniqueID": technique_id, "score": score}
            if tactic_id:
                tactic_name = _TACTIC_ID_TO_NAME.get(tactic_id, "")
                if tactic_name:
                    entry["tactic"] = tactic_name
            if color:
                entry["color"] = color
            if comment:
                entry["comment"] = comment
            if metadata:
                entry["metadata"] = metadata
            self._techniques[key] = entry

    def add_from_mappings(self, mappings: list[MITREMapping], comment: str = "") -> None:
        """Add techniques from a list of MITREMapping objects."""
        for m in mappings:
            score = int(m.confidence * 100)
            self.add_technique(
                technique_id=m.technique_id,
                tactic_id=m.tactic_id,
                score=score,
                comment=comment,
            )

    def export_json(self) -> str:
        """Export as Navigator JSON string."""
        layer = {
            "name": self.name,
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": self.description,
            "filters": {"platforms": ["Linux", "macOS", "Windows", "Network", "Cloud"]},
            "sorting": 0,
            "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": list(self._techniques.values()),
            "gradient": {
                "colors": ["#ffffff", "#66b1ff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Not tested", "color": "#ffffff"},
                {"label": "Low confidence", "color": "#66b1ff"},
                {"label": "High confidence", "color": "#ff6666"},
            ],
            "metadata": [
                {"name": "generated_by", "value": "KRYON"},
                {"name": "generated_at", "value": datetime.now(timezone.utc).isoformat()},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": False,
            "selectSubtechniquesWithParent": False,
        }
        return json.dumps(layer, indent=2)

    def export_to_file(self, filepath: str) -> str:
        """Export Navigator JSON to a file."""
        content = self.export_json()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath


# Tactic ID to Navigator tactic name mapping
_TACTIC_ID_TO_NAME: dict[str, str] = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0011": "command-and-control",
    "TA0010": "exfiltration",
    "TA0040": "impact",
}


def generate_navigator_layer(findings: list[Finding], layer_name: str = "") -> str:
    """Generate a Navigator JSON layer from a list of findings."""
    from kryon.intelligence.mitre import MITREMapper

    mapper = MITREMapper()
    name = layer_name or f"KRYON Assessment — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
    layer = NavigatorLayer(name=name, description=f"Auto-generated from {len(findings)} findings")

    for finding in findings:
        # Use existing MITRE mappings from the finding
        if finding.mitre:
            layer.add_from_mappings(finding.mitre, comment=finding.title)
        else:
            # Try to map the finding
            mappings = mapper.map_finding(
                f"{finding.title} {finding.description}",
                tool_name=finding.tool_source,
            )
            layer.add_from_mappings(mappings, comment=finding.title)

    return layer.export_json()


def generate_detection_coverage_layer(
    detected: list[str],
    all_techniques: list[str] | None = None,
) -> str:
    """Generate a coverage layer showing detected vs undetected techniques."""
    layer = NavigatorLayer(
        name="Detection Coverage",
        description="Green = detected, Red = not detected",
    )

    detected_set = set(detected)

    for tid in detected:
        layer.add_technique(tid, score=100, color="#00ff00", comment="Detected")

    if all_techniques:
        for tid in all_techniques:
            if tid not in detected_set:
                layer.add_technique(tid, score=0, color="#ff0000", comment="Not detected")

    return layer.export_json()
