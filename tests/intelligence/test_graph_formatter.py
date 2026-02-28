"""Tests for graph formatting utilities."""

import pytest
from kryon.intelligence.graph_formatter import format_graph_for_d3, format_kill_chain


def test_empty_input():
    result = format_graph_for_d3({})
    assert result["nodes"] == []
    assert result["edges"] == []
    assert result["chains"] == []


def test_string_input():
    result = format_graph_for_d3('{"exploitation_priority": []}')
    assert result["nodes"] == []


def test_invalid_string():
    result = format_graph_for_d3("not json")
    assert result["nodes"] == []


def test_nodes_from_priority():
    data = {"exploitation_priority": [
        {"id": "v1", "type": "sqli", "severity": "high"},
        {"id": "v2", "type": "rce", "severity": "critical"},
    ]}
    result = format_graph_for_d3(data)
    assert len(result["nodes"]) == 2
    assert result["nodes"][0]["id"] == "v1"
    assert result["nodes"][0]["severity"] == "high"


def test_edges_from_relationships():
    data = {
        "exploitation_priority": [{"id": "v1", "type": "sqli", "severity": "high"}],
        "relationships": [
            {"vulnerability_1": "v1", "vulnerability_2": "v2", "relationship_type": "enables", "description": "Enables attack"},
        ],
    }
    result = format_graph_for_d3(data)
    assert len(result["edges"]) == 1
    assert result["edges"][0]["source"] == "v1"
    assert result["edges"][0]["target"] == "v2"


def test_chain_edges():
    data = {
        "exploitation_priority": [],
        "attack_chains": [{
            "chain_type": "sqli_to_rce",
            "description": "SQL injection to RCE",
            "impact": "critical",
            "stages": [
                {"id": "s1", "type": "sqli"},
                {"id": "s2", "type": "rce"},
            ],
        }],
    }
    result = format_graph_for_d3(data)
    assert len(result["chains"]) == 1
    # Chain edges
    chain_edges = [e for e in result["edges"] if e["type"] == "chain"]
    assert len(chain_edges) == 1


def test_kill_chain_format():
    chain = {"stages": [
        {"id": "s1", "type": "recon", "severity": "info"},
        {"id": "s2", "type": "exploit", "severity": "high"},
    ]}
    steps = format_kill_chain(chain)
    assert len(steps) == 2
    assert steps[0]["order"] == 1
    assert steps[0]["is_first"] is True
    assert steps[0]["is_last"] is False
    assert steps[1]["is_last"] is True


def test_risk_amplification():
    data = {"combined_impact_score": 7.5, "exploitation_priority": []}
    result = format_graph_for_d3(data)
    assert result["risk_amplification"] == 7.5


def test_duplicate_nodes():
    data = {"exploitation_priority": [
        {"id": "v1", "type": "sqli", "severity": "high"},
        {"id": "v1", "type": "sqli", "severity": "high"},
    ]}
    result = format_graph_for_d3(data)
    assert len(result["nodes"]) == 1  # Deduped
