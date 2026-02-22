"""Tests for MITRE ATT&CK mapper."""

from kryon.intelligence.mitre import MITREMapper


def test_map_tool_nmap():
    mapper = MITREMapper()
    mappings = mapper.map_tool("nmap")
    assert len(mappings) >= 1
    ids = [m.technique_id for m in mappings]
    assert "T1046" in ids


def test_map_tool_sqlmap():
    mapper = MITREMapper()
    mappings = mapper.map_tool("sqlmap")
    assert len(mappings) >= 1
    ids = [m.technique_id for m in mappings]
    assert "T1190" in ids


def test_map_tool_hydra():
    mapper = MITREMapper()
    mappings = mapper.map_tool("hydra")
    ids = [m.technique_id for m in mappings]
    assert "T1110" in ids


def test_map_finding_sql_injection():
    mapper = MITREMapper()
    mappings = mapper.map_finding("SQL injection vulnerability found in login form")
    assert len(mappings) >= 1
    ids = [m.technique_id for m in mappings]
    assert "T1190" in ids


def test_map_finding_privilege_escalation():
    mapper = MITREMapper()
    mappings = mapper.map_finding("Privilege escalation via SUID binary")
    ids = [m.technique_id for m in mappings]
    assert "T1068" in ids


def test_map_finding_with_tool():
    mapper = MITREMapper()
    mappings = mapper.map_finding("Port 22 open - SSH", tool_name="nmap")
    ids = [m.technique_id for m in mappings]
    # Should match both tool mapping (nmap → T1046) and keyword (port scan → T1046)
    assert "T1046" in ids


def test_map_finding_deduplicates():
    mapper = MITREMapper()
    mappings = mapper.map_finding(
        "nmap port scan discovered open ports", tool_name="nmap"
    )
    ids = [m.technique_id for m in mappings]
    # T1046 should appear only once despite matching both tool and keyword
    assert ids.count("T1046") == 1


def test_tactic_summary():
    mapper = MITREMapper()
    from kryon.intelligence.models import MITREMapping

    mappings = [
        MITREMapping(tactic="Discovery", tactic_id="TA0007", technique="T1", technique_id="T1046", confidence=0.9),
        MITREMapping(tactic="Discovery", tactic_id="TA0007", technique="T2", technique_id="T1083", confidence=0.8),
        MITREMapping(tactic="Initial Access", tactic_id="TA0001", technique="T3", technique_id="T1190", confidence=0.9),
    ]
    summary = mapper.get_tactic_summary(mappings)
    assert summary["Discovery"] == 2
    assert summary["Initial Access"] == 1


def test_get_technique_detail():
    mapper = MITREMapper()
    detail = mapper.get_technique_detail("T1046")
    assert detail.get("name") == "Network Service Discovery"


def test_get_all_tactics():
    mapper = MITREMapper()
    tactics = mapper.get_all_tactics()
    assert len(tactics) == 14
    ids = [t["id"] for t in tactics]
    assert "TA0001" in ids
    assert "TA0040" in ids


def test_map_finding_no_match():
    mapper = MITREMapper()
    mappings = mapper.map_finding("Everything looks fine, no issues found")
    assert mappings == []
