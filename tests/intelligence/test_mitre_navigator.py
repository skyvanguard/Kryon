"""Tests for intelligence.mitre_navigator — Navigator layer export."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.intelligence.mitre_navigator import (
    NavigatorLayer,
    generate_detection_coverage_layer,
    generate_navigator_layer,
)
from kryon.intelligence.models import Finding, MITREMapping, Severity

# ---------------------------------------------------------------------------
# NavigatorLayer
# ---------------------------------------------------------------------------


def test_empty_layer():
    """Empty layer exports valid JSON with no techniques."""
    layer = NavigatorLayer(name="Empty Test")
    data = json.loads(layer.export_json())
    assert data["name"] == "Empty Test"
    assert data["techniques"] == []
    assert data["domain"] == "enterprise-attack"


def test_add_technique():
    """Adding a technique appears in exported JSON."""
    layer = NavigatorLayer()
    layer.add_technique("T1046", tactic_id="TA0007", score=85, comment="Port scan")
    data = json.loads(layer.export_json())
    assert len(data["techniques"]) == 1
    tech = data["techniques"][0]
    assert tech["techniqueID"] == "T1046"
    assert tech["score"] == 85
    assert tech["comment"] == "Port scan"
    assert tech["tactic"] == "discovery"


def test_add_from_mappings():
    """add_from_mappings converts MITREMapping list to techniques."""
    layer = NavigatorLayer()
    mappings = [
        MITREMapping(
            tactic="Discovery",
            tactic_id="TA0007",
            technique="Network Service Discovery",
            technique_id="T1046",
            confidence=0.9,
        ),
        MITREMapping(
            tactic="Initial Access",
            tactic_id="TA0001",
            technique="Exploit Public-Facing Application",
            technique_id="T1190",
            confidence=0.85,
        ),
    ]
    layer.add_from_mappings(mappings, comment="Test finding")
    data = json.loads(layer.export_json())
    assert len(data["techniques"]) == 2
    technique_ids = [t["techniqueID"] for t in data["techniques"]]
    assert "T1046" in technique_ids
    assert "T1190" in technique_ids


def test_export_json_structure():
    """Exported JSON has required Navigator fields."""
    layer = NavigatorLayer(name="Test", description="Test layer")
    layer.add_technique("T1046", score=50)
    data = json.loads(layer.export_json())
    assert "versions" in data
    assert "domain" in data
    assert "gradient" in data
    assert "legendItems" in data
    assert "metadata" in data


def test_export_json_has_techniques():
    """Techniques are properly serialized."""
    layer = NavigatorLayer()
    layer.add_technique("T1046", score=100, color="#ff0000")
    layer.add_technique("T1190", score=50, color="#00ff00")
    data = json.loads(layer.export_json())
    assert len(data["techniques"]) == 2


def test_layer_with_name_description():
    """Name and description are set correctly."""
    layer = NavigatorLayer(name="My Assessment", description="Quarterly pentest")
    data = json.loads(layer.export_json())
    assert data["name"] == "My Assessment"
    assert data["description"] == "Quarterly pentest"


def test_add_duplicate_technique_merges_score():
    """Adding same technique ID+tactic merges by keeping max score."""
    layer = NavigatorLayer()
    layer.add_technique("T1046", tactic_id="TA0007", score=50, comment="First")
    layer.add_technique("T1046", tactic_id="TA0007", score=90, comment="Second")
    data = json.loads(layer.export_json())
    # Should have 1 technique (merged)
    assert len(data["techniques"]) == 1
    tech = data["techniques"][0]
    assert tech["score"] == 90  # max of 50 and 90
    assert "First" in tech["comment"]
    assert "Second" in tech["comment"]


def test_export_to_file(tmp_path):
    """export_to_file writes JSON to disk."""
    layer = NavigatorLayer(name="File Export")
    layer.add_technique("T1046", score=75)
    filepath = str(tmp_path / "layer.json")
    result = layer.export_to_file(filepath)
    assert result == filepath
    assert os.path.exists(filepath)
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)
    assert data["name"] == "File Export"
    assert len(data["techniques"]) == 1


# ---------------------------------------------------------------------------
# generate_navigator_layer
# ---------------------------------------------------------------------------


def test_generate_from_findings():
    """generate_navigator_layer creates layer from findings with MITRE mappings."""
    findings = [
        Finding(
            title="Port scan finding",
            description="Open ports detected",
            severity=Severity.MEDIUM,
            affected_asset="10.0.0.1",
            tool_source="nmap",
            mitre=[
                MITREMapping(
                    tactic="Discovery",
                    tactic_id="TA0007",
                    technique="Network Service Discovery",
                    technique_id="T1046",
                    confidence=0.9,
                ),
            ],
        ),
    ]
    result = generate_navigator_layer(findings, layer_name="Test Layer")
    data = json.loads(result)
    assert data["name"] == "Test Layer"
    assert len(data["techniques"]) >= 1
    assert any(t["techniqueID"] == "T1046" for t in data["techniques"])


# ---------------------------------------------------------------------------
# generate_detection_coverage_layer
# ---------------------------------------------------------------------------


def test_generate_detection_coverage():
    """Detection coverage layer marks detected green and undetected red."""
    detected = ["T1046", "T1190"]
    all_techniques = ["T1046", "T1190", "T1110", "T1059"]
    result = generate_detection_coverage_layer(detected, all_techniques)
    data = json.loads(result)
    assert data["name"] == "Detection Coverage"

    technique_map = {t["techniqueID"]: t for t in data["techniques"]}
    assert technique_map["T1046"]["color"] == "#00ff00"
    assert technique_map["T1046"]["score"] == 100
    assert technique_map["T1110"]["color"] == "#ff0000"
    assert technique_map["T1110"]["score"] == 0
