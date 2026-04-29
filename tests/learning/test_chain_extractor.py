"""Tests for kryon.learning.chain_extractor.

Pure tests — fabricates message histories in both supported shapes
(OpenAI chat tool_calls + Responses-API function_call items) and
verifies that the extractor produces the same chain + outcome.
"""

from __future__ import annotations

import pytest

from kryon.learning.chain_extractor import extract_chain_from_history


# ---------- Shape: OpenAI chat tool_calls ----------


def _openai_history(tool_name: str, args: str, result: str) -> list[dict]:
    """One assistant tool_call followed by its tool result message."""
    return [
        {"role": "user", "content": "go"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_001",
                "function": {"name": tool_name, "arguments": args},
            }],
        },
        {"role": "tool", "tool_call_id": "call_001", "content": result},
    ]


def test_openai_shape_extracts_single_tool_call() -> None:
    history = _openai_history("nmap", '{"target": "x"}', "22/tcp open ssh\n")
    out = extract_chain_from_history(history)
    assert len(out["chain"]) == 1
    step = out["chain"][0]
    assert step["tool"] == "nmap"
    assert step["status"] == "ok"


def test_openai_error_in_output_marks_step_error() -> None:
    history = _openai_history("nmap", "{}", "error: connection refused")
    out = extract_chain_from_history(history)
    assert out["chain"][0]["status"] == "error"


# ---------- Shape: Responses-API items ----------


def _responses_history(tool_name: str, args: str, result: str) -> list[dict]:
    return [
        {"type": "message", "role": "user", "content": "go"},
        {"type": "function_call", "call_id": "fc_001", "name": tool_name, "arguments": args},
        {"type": "function_call_output", "call_id": "fc_001", "output": result},
    ]


def test_responses_api_shape_extracts_single_tool_call() -> None:
    history = _responses_history("whatweb", '{"url": "x"}', "Apache nginx")
    out = extract_chain_from_history(history)
    assert len(out["chain"]) == 1
    assert out["chain"][0]["tool"] == "whatweb"
    assert out["chain"][0]["status"] == "ok"


def test_responses_api_error_output() -> None:
    history = _responses_history("nmap", "{}", "error parsing args")
    out = extract_chain_from_history(history)
    assert out["chain"][0]["status"] == "error"


# ---------- Mixed shapes ----------


def test_mixed_openai_and_responses_shapes_both_captured() -> None:
    history = (
        _openai_history("nmap", "{}", "open: 80")
        + _responses_history("nuclei", "{}", "0 findings")
    )
    out = extract_chain_from_history(history)
    tools = [step["tool"] for step in out["chain"]]
    assert tools == ["nmap", "nuclei"]


# ---------- Pending tool calls (interrupted) ----------


def test_tool_call_without_output_marked_no_output() -> None:
    history = [
        {
            "role": "assistant",
            "tool_calls": [{
                "id": "call_x",
                "function": {"name": "long_running", "arguments": "{}"},
            }],
        },
        # no matching tool result message — call was interrupted
    ]
    out = extract_chain_from_history(history)
    assert len(out["chain"]) == 1
    assert out["chain"][0]["status"] == "no-output"


def test_orphan_tool_output_without_call_recorded() -> None:
    history = [
        {"role": "tool", "tool_call_id": "ghost", "content": "stale output"},
    ]
    out = extract_chain_from_history(history)
    assert len(out["chain"]) == 1
    assert out["chain"][0]["status"] == "orphan-output"


# ---------- Outcome classification ----------


def test_outcome_success_when_shell_signal_present() -> None:
    history = _openai_history(
        "exploit", "{}",
        "got shell\nuid=0(root) gid=0(root)\n",
    )
    out = extract_chain_from_history(history)
    assert out["outcome"] == "success"
    assert out["outcome_signals"]["shell_gained"] is True


def test_outcome_success_when_flag_signal_present() -> None:
    history = _openai_history("exfil", "{}", "found flag{my_secret_flag_value}")
    out = extract_chain_from_history(history)
    assert out["outcome"] == "success"
    assert out["outcome_signals"]["flag_found"] is True


def test_outcome_partial_with_cve_and_directories() -> None:
    history = _openai_history(
        "scan", "{}",
        "CVE-2023-12345 found in stack\nfound 5 directories\n",
    )
    out = extract_chain_from_history(history)
    assert out["outcome"] == "partial"
    assert "CVE-2023-12345" in out["outcome_signals"]["cve_confirmed"]
    assert out["outcome_signals"]["directories_found"] == 5


def test_outcome_recon_only_without_signals() -> None:
    history = _openai_history("nmap", "{}", "scan completed, 22/tcp open ssh")
    out = extract_chain_from_history(history)
    assert out["outcome"] == "recon-only"


def test_outcome_fail_when_chain_is_empty() -> None:
    history = [{"role": "user", "content": "hi"}]
    out = extract_chain_from_history(history)
    assert out["outcome"] == "fail"
    assert out["chain"] == []


# ---------- Signals: CVE deduplication ----------


def test_cves_are_deduped_and_sorted() -> None:
    history = _openai_history(
        "scan", "{}",
        "CVE-2023-1234\nCVE-2024-5678\nCVE-2023-1234 mentioned again\n",
    )
    out = extract_chain_from_history(history)
    cves = out["outcome_signals"]["cve_confirmed"]
    assert cves == ["CVE-2023-1234", "CVE-2024-5678"]


def test_directories_count_falls_back_to_status_2xx_lines() -> None:
    text = (
        "/admin            (Status: 200)\n"
        "/login            (Status: 200)\n"
        "/api              (Status: 204)\n"
    )
    history = _openai_history("gobuster", "{}", text)
    out = extract_chain_from_history(history)
    assert out["outcome_signals"]["directories_found"] >= 3


# ---------- Summary ----------


def test_summary_includes_target_and_chain_and_outcome() -> None:
    history = _openai_history(
        "nmap", "{}",
        "Nmap scan report for victim.local (10.0.0.1)\n80/tcp open http\n",
    )
    out = extract_chain_from_history(history)
    summary = out["summary"]
    assert "victim.local" in summary
    assert "nmap" in summary
    assert out["outcome"] in summary


def test_summary_dedupes_consecutive_same_tool() -> None:
    history = (
        _openai_history("nmap", "1", "open")
        + _openai_history("nmap", "2", "open")
    )
    # Build a single history ourselves to avoid call_id collision
    h: list[dict] = []
    for i, payload in enumerate(("first", "second")):
        h.append({
            "role": "assistant",
            "tool_calls": [{
                "id": f"c_{i}",
                "function": {"name": "nmap", "arguments": "{}"},
            }],
        })
        h.append({"role": "tool", "tool_call_id": f"c_{i}", "content": payload})
    out = extract_chain_from_history(h)
    # Two nmap calls but summary collapses consecutive duplicates.
    assert out["summary"].count("nmap") == 1


def test_agent_path_is_propagated_to_output() -> None:
    history = _openai_history("nmap", "{}", "ok")
    out = extract_chain_from_history(history, agent_path=["recon-scout", "pentest"])
    assert out["agent_path"] == ["recon-scout", "pentest"]


# ---------- Robustness ----------


def test_history_with_unusual_items_does_not_crash() -> None:
    history = [
        None,
        {},
        "raw string",
        {"role": "user", "content": None},
        {"role": "user", "content": [{"text": "hello"}, "world"]},
    ]
    out = extract_chain_from_history(history)
    # No tool calls in noise → empty chain, fail outcome.
    assert out["chain"] == []
    assert out["outcome"] == "fail"
