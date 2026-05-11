"""Anti-hallucination filters for search_vulnerabilities.

Regression tests for a real production incident: kryon-14b synthesised an
"Apache" CVE report citing CVE-2017-20224 (Telesquare router upload bug)
and CVE-2017-20218 (Serviio media server) because the underlying RAG tool
returned them with score < -250 and the agent accepted them as Apache CVEs.
These tests pin the filtering behaviour that prevents that.
"""

from __future__ import annotations

import json
import os
from typing import Any

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.knowledge.rag_tools import (
    _SEARCH_VULNS_HARD_DISCARD,
    _SEARCH_VULNS_HIGH_CONFIDENCE,
    _confidence_label,
    _tech_match,
    search_vulnerabilities,
)


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


def _fake_query_factory(sources: list[dict[str, Any]]):
    def _fake_query(question: str, top_k: int, source_filter=None, use_llm: bool = False):
        return {
            "question": question,
            "answer": "",
            "sources": sources[:top_k],
            "context_used": "",
        }

    return _fake_query


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestTechMatch:
    def test_finds_tech_in_content(self):
        assert _tech_match("apache", "Apache HTTP Server 2.4.49 vulnerability")

    def test_case_insensitive(self):
        assert _tech_match("APACHE", "apache httpd module flaw")

    def test_rejects_when_tech_missing(self):
        # The real RAG hit that fooled the agent in production
        assert not _tech_match("apache", "Telesquare router file upload bug")
        assert not _tech_match("apache", "Serviio media server privilege escalation")

    def test_checks_multiple_fields(self):
        assert _tech_match("nginx", None, "nginx-stable package", None)

    def test_empty_query_skips_check(self):
        assert _tech_match("", "anything")

    def test_stopword_skips_check(self):
        # "http" alone is too generic to be a useful match — fall through.
        assert _tech_match("http", "any random content")


class TestConfidenceLabel:
    def test_high_when_above_threshold(self):
        assert _confidence_label(_SEARCH_VULNS_HIGH_CONFIDENCE + 0.1) == "high"

    def test_medium_in_grey_zone(self):
        assert _confidence_label(-150.0) == "medium"

    def test_low_below_hard_discard(self):
        assert _confidence_label(_SEARCH_VULNS_HARD_DISCARD - 0.1) == "low"


# ---------------------------------------------------------------------------
# Tool integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drops_results_below_min_score(monkeypatch):
    """Telesquare-style hits with very negative score must be discarded."""
    import kryon.knowledge as knowledge_pkg

    monkeypatch.setattr(
        knowledge_pkg,
        "query_knowledge",
        _fake_query_factory(
            [
                {
                    "metadata": {"cve_id": "CVE-2017-20224", "severity": "CRITICAL", "cvss_score": 9.8},
                    "content": "Telesquare router unrestricted file upload",
                    "score": -269.83,
                },
            ]
        ),
        raising=False,
    )

    raw = await _invoke(search_vulnerabilities, {"technology": "apache"})
    result = raw if isinstance(raw, dict) else json.loads(raw)

    assert result["count"] == 0
    assert result["vulnerabilities"] == []
    assert result["discarded_count"] == 1
    assert "low_relevance" in result["discarded"][0]["reason"]


@pytest.mark.asyncio
async def test_drops_results_with_tech_mismatch(monkeypatch):
    """An above-threshold score is not enough — the tech name must appear."""
    import kryon.knowledge as knowledge_pkg

    monkeypatch.setattr(
        knowledge_pkg,
        "query_knowledge",
        _fake_query_factory(
            [
                {
                    "metadata": {"cve_id": "CVE-2017-20218", "severity": "HIGH", "cvss_score": 7.8},
                    "content": "Serviio media server unquoted search path privilege escalation",
                    "score": -50.0,
                },
            ]
        ),
        raising=False,
    )

    raw = await _invoke(search_vulnerabilities, {"technology": "apache"})
    result = raw if isinstance(raw, dict) else json.loads(raw)

    assert result["count"] == 0
    assert result["discarded_count"] == 1
    assert "tech_mismatch" in result["discarded"][0]["reason"]


@pytest.mark.asyncio
async def test_keeps_genuine_hits(monkeypatch):
    """Real Apache CVE with plausible relevance score must pass through."""
    import kryon.knowledge as knowledge_pkg

    monkeypatch.setattr(
        knowledge_pkg,
        "query_knowledge",
        _fake_query_factory(
            [
                {
                    "metadata": {
                        "cve_id": "CVE-2021-44228",
                        "severity": "CRITICAL",
                        "cvss_score": 10.0,
                    },
                    "content": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP",
                    "score": -45.0,
                },
            ]
        ),
        raising=False,
    )

    raw = await _invoke(search_vulnerabilities, {"technology": "apache"})
    result = raw if isinstance(raw, dict) else json.loads(raw)

    assert result["count"] == 1
    assert result["vulnerabilities"][0]["cve_id"] == "CVE-2021-44228"
    assert result["vulnerabilities"][0]["confidence"] == "high"
    assert result["discarded_count"] == 0


@pytest.mark.asyncio
async def test_marks_medium_confidence_in_grey_zone(monkeypatch):
    """Borderline scores are kept but flagged as medium confidence."""
    import kryon.knowledge as knowledge_pkg

    monkeypatch.setattr(
        knowledge_pkg,
        "query_knowledge",
        _fake_query_factory(
            [
                {
                    "metadata": {"cve_id": "CVE-9999-0001", "severity": "HIGH", "cvss_score": 7.5},
                    "content": "Apache Tomcat session fixation bug",
                    "score": -150.0,
                },
            ]
        ),
        raising=False,
    )

    raw = await _invoke(search_vulnerabilities, {"technology": "apache"})
    result = raw if isinstance(raw, dict) else json.loads(raw)

    assert result["count"] == 1
    assert result["vulnerabilities"][0]["confidence"] == "medium"


@pytest.mark.asyncio
async def test_severity_min_is_still_honoured(monkeypatch):
    import kryon.knowledge as knowledge_pkg

    monkeypatch.setattr(
        knowledge_pkg,
        "query_knowledge",
        _fake_query_factory(
            [
                {
                    "metadata": {"cve_id": "CVE-LOW-1", "severity": "LOW", "cvss_score": 3.0},
                    "content": "Apache info disclosure of minor scope",
                    "score": -40.0,
                },
                {
                    "metadata": {"cve_id": "CVE-CRIT-1", "severity": "CRITICAL", "cvss_score": 9.8},
                    "content": "Apache RCE in mod_proxy",
                    "score": -42.0,
                },
            ]
        ),
        raising=False,
    )

    raw = await _invoke(
        search_vulnerabilities,
        {"technology": "apache", "severity_min": "HIGH"},
    )
    result = raw if isinstance(raw, dict) else json.loads(raw)

    cve_ids = [v["cve_id"] for v in result["vulnerabilities"]]
    assert cve_ids == ["CVE-CRIT-1"]
    assert any("below_severity_min" in d["reason"] for d in result["discarded"])


@pytest.mark.asyncio
async def test_can_disable_tech_match_when_caller_knows_better(monkeypatch):
    import kryon.knowledge as knowledge_pkg

    monkeypatch.setattr(
        knowledge_pkg,
        "query_knowledge",
        _fake_query_factory(
            [
                {
                    "metadata": {"cve_id": "CVE-X", "severity": "HIGH", "cvss_score": 7.8},
                    "content": "Some unrelated payload",
                    "score": -40.0,
                },
            ]
        ),
        raising=False,
    )

    raw = await _invoke(
        search_vulnerabilities,
        {"technology": "apache", "require_tech_match": False},
    )
    result = raw if isinstance(raw, dict) else json.loads(raw)

    assert result["count"] == 1
