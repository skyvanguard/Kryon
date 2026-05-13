"""F107 — TDD contract for the DOM XSS Sink Detector."""

from __future__ import annotations

import pytest

from kryon.tools.api.dom_xss import (
    ALL_DOM_RULES,
    DomXssAnalysis,
    DomXssFinding,
    JsSnippet,
    _classify_snippet,
    _line_has_source,
    analyze_dom_xss,
)


def _s(body: str, path: str = "app.js") -> JsSnippet:
    return JsSnippet(file_path=path, body=body)


# =====================================================================
# Source line detection
# =====================================================================


@pytest.mark.parametrize(
    "line,expected",
    [
        ("const hash = location.hash;", True),
        ("var q = location.search;", True),
        ("let ref = document.referrer;", True),
        ("const c = document.cookie;", True),
        ("const n = window.name;", True),
        ("const v = localStorage.getItem('x');", True),
        ("const data = event.data;", True),
        ("const sum = a + b;", False),
        ("const x = api.fetch();", False),
    ],
)
def test_line_has_source(line, expected):
    assert _line_has_source(line) is expected


# =====================================================================
# Each rule POSITIVE
# =====================================================================


def test_dom_001_eval_from_location_critical():
    body = "eval(location.hash.substr(1));"
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-001" and f.severity == "CRITICAL" for f in findings)


def test_dom_001_function_constructor():
    body = "const f = new Function(location.search);"
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-001" for f in findings)


def test_dom_002_innerhtml_from_referrer():
    body = "div.innerHTML = document.referrer;"
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-002" and f.severity == "HIGH" for f in findings)


def test_dom_002_document_write():
    body = "document.write(location.hash);"
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-002" for f in findings)


def test_dom_003_settimeout_string():
    body = 'setTimeout("alert(1)", 100);'
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-003" for f in findings)


def test_dom_003_settimeout_function_safe():
    body = "setTimeout(function() { alert('safe'); }, 100);"
    findings = _classify_snippet(_s(body))
    assert not any(f.rule_id == "DOM-003" for f in findings)


def test_dom_004_location_href_from_hash():
    body = "window.location.href = location.hash.slice(1);"
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-004" for f in findings)


def test_dom_005_jquery_html_from_search():
    body = "$('#out').html(location.search);"
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-005" for f in findings)


def test_dom_005_jquery_append():
    body = "$('#out').append(document.cookie);"
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-005" for f in findings)


def test_dom_006_insertadjacenthtml():
    body = "el.insertAdjacentHTML('beforeend', location.hash);"
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-006" for f in findings)


def test_dom_007_dangerously_set_inner_html():
    body = (
        "const userBio = localStorage.getItem('bio');\n"
        "return <div dangerouslySetInnerHTML={{__html: userBio}} />;"
    )
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-007" for f in findings)


def test_dom_008_script_src_from_location():
    body = "script.src = location.hash.substr(1);"
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-008" for f in findings)


def test_dom_009_postmessage_without_origin_check():
    body = "window.addEventListener('message', function(e) { div.innerHTML = e.data; });"
    findings = _classify_snippet(_s(body))
    ids = {f.rule_id for f in findings}
    assert "DOM-009" in ids


def test_dom_009_postmessage_with_origin_check_silent():
    body = (
        "window.addEventListener('message', function(e) {\n"
        "  if (e.origin !== 'https://trusted.example') return;\n"
        "  console.log(e.data);\n"
        "});"
    )
    findings = _classify_snippet(_s(body))
    assert not any(f.rule_id == "DOM-009" for f in findings)


def test_dom_010_eval_without_explicit_source():
    body = "const x = eval(getUserInput());"
    findings = _classify_snippet(_s(body))
    assert any(f.rule_id == "DOM-010" for f in findings)


# =====================================================================
# Negative — clean code
# =====================================================================


def test_clean_code_no_findings():
    body = """
function add(a, b) {
    return a + b;
}
const arr = [1, 2, 3].map(x => x * 2);
"""
    findings = _classify_snippet(_s(body))
    assert findings == []


def test_innerhtml_with_constant_silent():
    body = 'div.innerHTML = "<b>hello</b>";'
    findings = _classify_snippet(_s(body))
    # The constant case still might fire if there's a source nearby,
    # but with no source it should be silent.
    assert not any(f.rule_id == "DOM-002" for f in findings)


def test_comment_lines_skipped():
    body = "// eval(location.hash);\n// document.write(location.search);"
    findings = _classify_snippet(_s(body))
    assert findings == []


# =====================================================================
# Aggregation
# =====================================================================


def test_analyze_dom_xss_sorts_by_severity():
    snippets = [
        _s("div.innerHTML = location.search;"),  # HIGH
        _s("eval(location.hash);"),  # CRITICAL
    ]
    analysis = analyze_dom_xss(snippets)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[f.severity] for f in analysis.findings]
    assert ranks == sorted(ranks)


def test_analyze_dom_xss_empty():
    analysis = analyze_dom_xss([])
    assert analysis.findings == ()


def test_line_offset_applied():
    snippet = JsSnippet(file_path="x.js", body="eval(location.hash);", line_offset=100)
    findings = _classify_snippet(snippet)
    eval_findings = [f for f in findings if f.rule_id == "DOM-001"]
    assert eval_findings and eval_findings[0].line == 101


# =====================================================================
# Pin + frozen
# =====================================================================


def test_all_rules_pinned():
    expected = {f"DOM-{n:03d}" for n in range(1, 11)}
    assert expected == ALL_DOM_RULES


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    s = JsSnippet(file_path="x.js", body="x")
    with pytest.raises(FrozenInstanceError):
        s.body = "y"  # type: ignore[misc]
