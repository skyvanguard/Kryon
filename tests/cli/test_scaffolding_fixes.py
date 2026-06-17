"""Scaffolding correctness fixes (pre-DeepSeek audit).

Covers the confirmed bugs where the agentic harness failed to deliver context to
the model — a paid model with broken scaffolding underperforms.
"""

from __future__ import annotations

from types import SimpleNamespace

from kryon.cli.investigate import _format_findings_for_prompt
from kryon.cli.reflective_runner import _salvage_chunk_intel

# ---------------------------------------------------------------------------
# #1 / #3 — fact salvage from the in-flight capture (raw tool outputs)
# ---------------------------------------------------------------------------


class _Hooks:
    def __init__(self, items):
        self.captured_items = items


def test_salvage_pulls_facts_from_captured_tool_output():
    """The intel pipeline must see the RAW tool output (▸-marked), not the model's
    final_output. _salvage feeds _chunk_text_from_capture into the fact extractor."""
    from kryon.intelligence.fact_extractor import ExtractedFacts

    hooks = _Hooks(
        [
            {
                "type": "tool_call",
                "tool": "ldapsearch",
                "output_preview": (
                    "userPrincipalName: svc-sql@CORP.LOCAL\n"
                    "userPrincipalName: admin@CORP.LOCAL\n"
                    "userPrincipalName: jdoe@CORP.LOCAL"
                ),
            }
        ]
    )
    facts = _salvage_chunk_intel(hooks, ExtractedFacts(), [])
    assert {"svc-sql", "admin", "jdoe"} <= set(facts.users)


def test_salvage_is_safe_on_empty_capture():
    from kryon.intelligence.fact_extractor import ExtractedFacts

    facts = _salvage_chunk_intel(_Hooks([]), ExtractedFacts(), [])
    assert facts.is_empty()


# ---------------------------------------------------------------------------
# #5 — the evidence field reaches the prompt
# ---------------------------------------------------------------------------


def test_format_findings_renders_evidence_and_full_message():
    f = SimpleNamespace(
        cwe="CWE-918",
        rule_id="SSRF-CONFIRMED",
        severity="CRITICAL",
        host="beta.creative.thm",
        message="SSRF confirmed via POST url=. " + "x" * 300 + " Pivot: 127.0.0.1:1337",
        evidence="/etc/passwd leak: root:x:0:0:root",
    )
    out = _format_findings_for_prompt([f])
    assert "evidencia: /etc/passwd leak: root:x:0:0:root" in out
    # message rendered to 400 chars (not 200) so the pivot survives
    assert "Pivot: 127.0.0.1:1337" in out


def test_format_findings_empty():
    assert _format_findings_for_prompt([]) == ""
