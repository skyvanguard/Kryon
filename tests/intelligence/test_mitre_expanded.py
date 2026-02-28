"""Tests for expanded MITRE ATT&CK mapper — new tools and keyword patterns."""

import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.intelligence.mitre import MITREMapper


@pytest.fixture
def mapper():
    return MITREMapper()


# ---------------------------------------------------------------------------
# Tool-based mapping (new tools)
# ---------------------------------------------------------------------------


def test_map_semgrep(mapper):
    """Semgrep maps to T1190 Exploit Public-Facing Application."""
    results = mapper.map_tool("semgrep")
    assert len(results) > 0
    assert any(r.technique_id == "T1190" for r in results)


def test_map_syft(mapper):
    """Syft maps to T1592.002 Gather Victim Host Information: Software."""
    results = mapper.map_tool("syft")
    assert len(results) > 0
    assert any(r.technique_id == "T1592.002" for r in results)


def test_map_grype(mapper):
    """Grype maps to T1190 Exploit Public-Facing Application."""
    results = mapper.map_tool("grype")
    assert len(results) > 0
    assert any(r.technique_id == "T1190" for r in results)


def test_map_fofa(mapper):
    """FOFA maps to T1596 Search Open Technical Databases."""
    results = mapper.map_tool("fofa")
    assert len(results) > 0
    assert any(r.technique_id == "T1596" for r in results)


def test_map_prowler(mapper):
    """Prowler maps to T1580 Cloud Infrastructure Discovery."""
    results = mapper.map_tool("prowler")
    assert len(results) > 0
    assert any(r.technique_id == "T1580" for r in results)


def test_map_censys(mapper):
    """Censys maps to T1596 Search Open Technical Databases."""
    results = mapper.map_tool("censys")
    assert len(results) > 0
    assert any(r.technique_id == "T1596" for r in results)


def test_map_credential_spray(mapper):
    """credential_spray maps to T1110.003 Password Spraying."""
    results = mapper.map_tool("credential_spray")
    assert len(results) > 0
    assert any(r.technique_id == "T1110.003" for r in results)


# ---------------------------------------------------------------------------
# Keyword-based mapping (new patterns)
# ---------------------------------------------------------------------------


def test_keyword_supply_chain(mapper):
    """Supply chain keyword maps to T1195.001."""
    results = mapper.map_finding("Detected supply chain vulnerability in dependency")
    assert any(r.technique_id == "T1195.001" for r in results)


def test_keyword_container_escape(mapper):
    """Container escape keyword maps to T1611."""
    results = mapper.map_finding("Container escape via Docker breakout exploit")
    assert any(r.technique_id == "T1611" for r in results)


def test_keyword_cloud_metadata(mapper):
    """Cloud metadata keyword maps to T1552.005."""
    results = mapper.map_finding("IMDS accessible at 169.254.169.254, cloud metadata exposed")
    assert any(r.technique_id == "T1552.005" for r in results)


def test_keyword_jwt_attack(mapper):
    """JWT attack keyword maps to T1606 Forge Web Credentials."""
    results = mapper.map_finding("JWT none algorithm attack succeeded, token forgery possible")
    assert any(r.technique_id == "T1606" for r in results)


def test_keyword_prompt_injection(mapper):
    """Prompt injection keyword maps to T1059."""
    results = mapper.map_finding("Prompt injection vulnerability in LLM endpoint")
    assert any(r.technique_id == "T1059" for r in results)


def test_keyword_kerberoast(mapper):
    """Kerberoast keyword maps to T1558 Steal or Forge Kerberos Tickets."""
    results = mapper.map_finding("Kerberoasting attack found SPN tickets")
    assert any(r.technique_id == "T1558" for r in results)


# ---------------------------------------------------------------------------
# Tactic summary
# ---------------------------------------------------------------------------


def test_tactic_summary(mapper):
    """get_tactic_summary aggregates findings by tactic."""
    mappings = mapper.map_finding("SQL injection in web app, also found brute force attempts")
    summary = mapper.get_tactic_summary(mappings)
    assert isinstance(summary, dict)
    assert len(summary) > 0
    # All values should be positive integers
    assert all(v > 0 for v in summary.values())
