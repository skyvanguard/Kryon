"""F180 — integration test for the F173 applicability wire in engage.

The F178/F179 bench showed gpt-oss-20b consistently emits CVE-2013-6235
(JAMon JSP XSS) as a finding against the Node.js Juice Shop target.
F173's filter exists in ``cve_applicability.py`` with 19 unit tests
but was never wired to the engage parser, so the FP kept reaching
the report.

These tests pin the wire-up: ``_parse_agent_findings`` must drop the
JAMon CVE when the LLM narration mentions Express / Node.js but
NOT when the narration mentions Java / JSP.
"""

from __future__ import annotations

import pytest

from kryon.cli.engage import _parse_agent_findings


_JAMON_FP_BLOCK = """
WhatWeb output: OWASP Juice Shop, X-Powered-By: Express, HTML5.

```json
[
  {
    "severity": "HIGH",
    "cwe": "CWE-79",
    "rule_id": "CVE-2013-6235",
    "host": "http://juice_shop:3000",
    "message": "Cross-site scripting vulnerability in JAMonAdmin.jsp",
    "evidence": "JAMon 2.7 and earlier"
  },
  {
    "severity": "HIGH",
    "cwe": "CWE-200",
    "rule_id": "Missing-CSP",
    "host": "http://juice_shop:3000",
    "message": "Content-Security-Policy header missing"
  }
]
```
"""

_JAMON_LEGIT_BLOCK = """
Server scan: Apache Tomcat 9.0, JSP runtime detected, JAMon profiler
exposed at /JAMonAdmin.jsp on port 8080.

```json
[
  {
    "severity": "HIGH",
    "cwe": "CWE-79",
    "rule_id": "CVE-2013-6235",
    "host": "http://target:8080",
    "message": "Reflected XSS in JAMonAdmin.jsp",
    "evidence": "Tomcat 9.0 hosting vulnerable JAMon 2.5"
  }
]
```
"""


# ---------------------------------------------------------------------------
# F180 — JAMon CVE dropped when the stack is Node.js / Express
# ---------------------------------------------------------------------------


def test_jamon_cve_dropped_for_express_target():
    findings = _parse_agent_findings(_JAMON_FP_BLOCK, target_host="juice_shop")
    rule_ids = [f.rule_id for f in findings]
    assert "CVE-2013-6235" not in rule_ids
    # The legitimate Missing-CSP finding survives — the gate is
    # CVE-specific.
    assert "Missing-CSP" in rule_ids


def test_jamon_cve_kept_for_tomcat_jsp_target():
    """When the narration legitimately mentions JAMon + Tomcat + JSP,
    the CVE applies and must NOT be dropped."""
    findings = _parse_agent_findings(_JAMON_LEGIT_BLOCK, target_host="target")
    rule_ids = [f.rule_id for f in findings]
    assert "CVE-2013-6235" in rule_ids


# ---------------------------------------------------------------------------
# F180 — non-CVE findings always pass (gate is CVE-specific)
# ---------------------------------------------------------------------------


def test_security_header_findings_pass_through():
    block = """
    Express server detected.
    ```json
    [
      {"severity":"HIGH","cwe":"CWE-200","rule_id":"Missing-HSTS","host":"x","message":"HSTS missing"},
      {"severity":"HIGH","cwe":"CWE-200","rule_id":"Exposed-htpasswd","host":"x","message":".htpasswd exposed"}
    ]
    ```
    """
    findings = _parse_agent_findings(block, target_host="x")
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"Missing-HSTS", "Exposed-htpasswd"}


# ---------------------------------------------------------------------------
# F180 — applicability filter respects KRYON_CVE_APPLICABILITY=false
# ---------------------------------------------------------------------------


def test_applicability_filter_can_be_disabled(monkeypatch):
    monkeypatch.setenv("KRYON_CVE_APPLICABILITY", "false")
    findings = _parse_agent_findings(_JAMON_FP_BLOCK, target_host="juice_shop")
    rule_ids = [f.rule_id for f in findings]
    # With the gate off, the JAMon CVE survives even against Node.js stack.
    assert "CVE-2013-6235" in rule_ids


# ---------------------------------------------------------------------------
# F180 — empty narration → no tech stack → conservative pass
# ---------------------------------------------------------------------------


def test_empty_narration_passes_cves_conservatively():
    """If the model doesn't dump any recon output before the findings
    block, tech_stack is empty and F173 falls through conservatively."""
    bare_block = """
    ```json
    [{"severity":"HIGH","cwe":"CWE-79","rule_id":"CVE-2013-6235","host":"x","message":"XSS"}]
    ```
    """
    findings = _parse_agent_findings(bare_block, target_host="x")
    rule_ids = [f.rule_id for f in findings]
    # No stack info → can't disprove applicability → CVE survives.
    assert "CVE-2013-6235" in rule_ids
