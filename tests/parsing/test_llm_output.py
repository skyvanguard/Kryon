"""F150 — R1-tolerant parser tests."""

from __future__ import annotations

from kryon.parsing.llm_output import (
    extract_finding_json_blocks,
    is_finding_shape,
    is_tool_call_shape,
    strip_think_tags,
)

# ---------------------------------------------------------------------------
# strip_think_tags
# ---------------------------------------------------------------------------


def test_strip_no_think_tags_returns_unchanged():
    assert strip_think_tags("Plain text without think tags") == "Plain text without think tags"


def test_strip_single_think_block():
    text = "<think>Internal reasoning here</think>\nActual finding output"
    result = strip_think_tags(text)
    assert "Internal reasoning" not in result
    assert "Actual finding output" in result


def test_strip_multiline_think_block():
    text = """Before
<think>
multi
line
reasoning
</think>
After"""
    result = strip_think_tags(text)
    assert "reasoning" not in result
    assert "Before" in result
    assert "After" in result


def test_strip_multiple_think_blocks():
    text = "<think>first</think>middle<think>second</think>end"
    result = strip_think_tags(text)
    assert "first" not in result
    assert "second" not in result
    assert "middle" in result
    assert "end" in result


def test_strip_case_insensitive():
    text = "<THINK>upper</THINK><Think>mixed</Think>after"
    result = strip_think_tags(text)
    assert "upper" not in result
    assert "mixed" not in result
    assert "after" in result


def test_strip_empty_input():
    assert strip_think_tags("") == ""


# ---------------------------------------------------------------------------
# is_finding_shape / is_tool_call_shape
# ---------------------------------------------------------------------------


def test_is_finding_shape_classic():
    assert is_finding_shape({"cwe": "CWE-1", "severity": "HIGH", "rule_id": "x"}) is True


def test_is_finding_shape_strong_marker_without_severity():
    # A cwe/rule_id identifies a finding on its own — severity is NOT required.
    # Regression: requiring severity dropped {cwe, message, host} findings.
    assert is_finding_shape({"cwe": "CWE-1", "rule_id": "x"}) is True
    assert is_finding_shape({"cwe": "CWE-89", "message": "SQLi en /login", "host": "t"}) is True
    assert is_finding_shape({"rule_id": "WEB-ENUM-DIR", "host": "t"}) is True


def test_is_finding_shape_severity_plus_descriptive_without_marker():
    # No cwe/rule_id → still a finding if severity + a descriptive field.
    assert is_finding_shape({"severity": "high", "title": "SQL injection"}) is True
    assert is_finding_shape({"severity": "medium", "message": "x"}) is True


def test_is_finding_shape_severity_alone_not_enough():
    # Need at least one of cwe/rule_id/message/host/title.
    assert is_finding_shape({"severity": "HIGH"}) is False


def test_is_finding_shape_rejects_non_dict():
    assert is_finding_shape("string") is False
    assert is_finding_shape([{"severity": "HIGH"}]) is False
    assert is_finding_shape(None) is False


def test_is_tool_call_shape_classic():
    obj = {"name": "nuclei_scan", "arguments": {"target": "x"}}
    assert is_tool_call_shape(obj) is True


def test_is_tool_call_shape_accepts_alternatives():
    assert is_tool_call_shape({"name": "x", "parameters": {}}) is True
    assert is_tool_call_shape({"name": "x", "args": []}) is True


def test_is_tool_call_shape_requires_name_and_args():
    assert is_tool_call_shape({"name": "x"}) is False
    assert is_tool_call_shape({"arguments": {}}) is False


# ---------------------------------------------------------------------------
# extract_finding_json_blocks
# ---------------------------------------------------------------------------


def test_extract_from_bare_array():
    text = '[{"cwe": "CWE-1", "severity": "HIGH", "rule_id": "x", "message": "m"}]'
    out = extract_finding_json_blocks(text)
    assert len(out) == 1
    assert out[0]["cwe"] == "CWE-1"


def test_extract_from_envelope_shape():
    text = '{"summary": "x", "findings": [{"severity": "HIGH", "rule_id": "a"}]}'
    out = extract_finding_json_blocks(text)
    assert len(out) == 1
    assert out[0]["rule_id"] == "a"


def test_extract_from_single_finding_dict():
    text = '{"cwe": "CWE-1", "severity": "HIGH", "rule_id": "x"}'
    out = extract_finding_json_blocks(text)
    assert len(out) == 1


def test_extract_rejects_tool_call_json():
    text = """
    First I'll call this tool:
    {"name": "nuclei_scan", "arguments": {"target": "x"}}
    No findings here.
    """
    out = extract_finding_json_blocks(text)
    assert out == []


def test_extract_skips_think_block_first():
    text = """<think>
    Let me reason about this. I think I should call nuclei_scan.
    {"name": "nuclei_scan", "arguments": {"target": "x"}}
    </think>
    [{"cwe": "CWE-319", "severity": "HIGH", "rule_id": "http-plaintext", "message": "HTTP en plain"}]
    """
    out = extract_finding_json_blocks(text)
    assert len(out) == 1
    assert out[0]["rule_id"] == "http-plaintext"


def test_extract_handles_mixed_finding_and_tool_call():
    text = """
    First tool call: {"name": "scan", "arguments": {"t": "x"}}
    Now findings:
    [{"cwe": "CWE-1", "severity": "HIGH", "rule_id": "a"},
     {"cwe": "CWE-2", "severity": "MEDIUM", "rule_id": "b"}]
    Another tool: {"name": "verify", "parameters": {}}
    """
    out = extract_finding_json_blocks(text)
    assert len(out) == 2
    rule_ids = {f["rule_id"] for f in out}
    assert rule_ids == {"a", "b"}


def test_extract_empty_input():
    assert extract_finding_json_blocks("") == []


def test_extract_no_json_returns_empty():
    assert extract_finding_json_blocks("Just plain text, no JSON.") == []


def test_extract_malformed_json_skipped_not_raised():
    text = """
    {malformed: not valid json}
    But this is valid: [{"severity": "HIGH", "rule_id": "x"}]
    {also malformed
    """
    out = extract_finding_json_blocks(text)
    assert len(out) == 1
    assert out[0]["rule_id"] == "x"


def test_extract_handles_nested_dict_finding():
    text = '{"findings": [{"severity": "HIGH", "rule_id": "a", "evidence": {"detail": "nested"}}]}'
    out = extract_finding_json_blocks(text)
    assert len(out) == 1
    assert isinstance(out[0]["evidence"], dict)


def test_extract_r1_realistic_output():
    """Simulate the exact R1 output shape we saw in the Juice Shop bench."""
    text = """
    Now that I've completed the recon phase, I will run nuclei_scan with
    broader scope and validate any vulnerabilities found.
    {
      "name": "duckduckgo_search",
      "arguments": {
        "query": "Juice Shop technology stack",
        "region": "es-es"
      }
    }
    {
      "name": "nuclei_scan",
      "arguments": {
        "target": "http://juice_shop:3000",
        "severity": "critical,high,medium,low"
      }
    }
    Based on the scan results, here are the findings:
    [
      {
        "cwe": "CWE-89",
        "severity": "HIGH",
        "host": "http://juice_shop:3000",
        "rule_id": "sqli-login",
        "message": "SQL injection in /rest/user/login endpoint",
        "evidence": "Login bypass via ' or 1=1--",
        "remediation": "Use parameterised queries"
      }
    ]
    """
    out = extract_finding_json_blocks(text)
    # Should find the 1 finding, NOT the 2 tool-call shapes.
    assert len(out) == 1
    assert out[0]["cwe"] == "CWE-89"
    assert out[0]["rule_id"] == "sqli-login"
