"""Anti-hallucination guard for nuclei_scan failures.

Regression test for a real production incident: nuclei printed
`[FTL] Could not run nuclei: no templates provided for scan` and
`[ERR] Could not find template 'web-technologies'`, the tool returned
that string verbatim, and the agent interpreted it as "0 findings"
instead of "scan never executed".
"""

from __future__ import annotations

import json
import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.web import nuclei as nuclei_module
from kryon.tools.web.nuclei import (
    _detect_nuclei_failure,
    _wrap_failed_scan,
    nuclei_scan,
)


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestDetectNucleiFailure:
    def test_detects_missing_template(self):
        out = (
            "nuclei v3.8.0\n"
            "[ERR] Could not find template 'web-technologies': no such path\n"
            "[INF] Targets loaded for current scan: 2\n"
        )
        reason = _detect_nuclei_failure(out)
        assert reason is not None
        assert "Could not find template" in reason

    def test_detects_ftl(self):
        out = "[FTL] Could not run nuclei: no templates provided for scan\n"
        reason = _detect_nuclei_failure(out)
        assert reason is not None
        assert "FTL" in reason or "Could not run" in reason

    def test_detects_no_templates_message(self):
        reason = _detect_nuclei_failure("error: no templates provided for scan")
        assert reason is not None

    def test_empty_output_is_a_failure(self):
        assert _detect_nuclei_failure("") == "empty_output"

    def test_clean_output_is_not_a_failure(self):
        out = (
            "[INF] Current nuclei version: v3.8.0 (latest)\n"
            "[INF] Targets loaded for current scan: 1\n"
            "[INF] Templates loaded for scan: 9000\n"
            "[CRITICAL] CVE-2021-44228 detected at https://example.com/\n"
        )
        assert _detect_nuclei_failure(out) is None


class TestWrapFailedScan:
    def test_prefix_is_unambiguous(self):
        wrapped = _wrap_failed_scan("template_not_found", "raw stuff")
        assert wrapped.startswith("[KRYON_TOOL_ERROR] nuclei_scan did NOT execute")
        assert "template_not_found" in wrapped
        assert "do NOT infer" in wrapped
        assert "raw stuff" in wrapped


# ---------------------------------------------------------------------------
# Tool integration (cache makes things tricky — we patch run_command and use
# unique target URLs so the @cache_scan_result decorator can't replay results
# from earlier tests.)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nuclei_scan_wraps_failed_template(monkeypatch):
    failure_output = (
        "nuclei v3.8.0\n"
        "[ERR] Could not find template 'web-technologies': no such path\n"
        "[FTL] Could not run nuclei: no templates provided for scan\n"
    )

    def fake_run(cmd, **kwargs):
        return failure_output

    monkeypatch.setattr(nuclei_module, "run_command", fake_run)

    result = await _invoke(
        nuclei_scan,
        {
            "target": "https://nuclei-fail-test-1.example.invalid",
            "templates": "web-technologies",
        },
    )

    assert "[KRYON_TOOL_ERROR]" in str(result)
    assert "did NOT execute" in str(result)
    assert "raw output below" in str(result)


@pytest.mark.asyncio
async def test_nuclei_scan_passes_through_real_findings(monkeypatch):
    success_output = (
        "[INF] Current nuclei version: v3.8.0\n"
        "[INF] Templates loaded for scan: 9000\n"
        "[CRITICAL] CVE-2021-44228 detected at https://nuclei-ok-test-1.example.invalid\n"
    )

    def fake_run(cmd, **kwargs):
        return success_output

    monkeypatch.setattr(nuclei_module, "run_command", fake_run)

    result = await _invoke(
        nuclei_scan,
        {
            "target": "https://nuclei-ok-test-1.example.invalid",
        },
    )

    assert "[KRYON_TOOL_ERROR]" not in str(result)
    assert "CVE-2021-44228" in str(result)


@pytest.mark.asyncio
async def test_nuclei_scan_wraps_empty_output(monkeypatch):
    """An empty stdout is a silent failure too — never let the agent
    interpret it as 'scan ran with zero findings'."""

    def fake_run(cmd, **kwargs):
        return ""

    monkeypatch.setattr(nuclei_module, "run_command", fake_run)

    result = await _invoke(
        nuclei_scan,
        {"target": "https://nuclei-empty-test-1.example.invalid"},
    )

    assert "[KRYON_TOOL_ERROR]" in str(result)
    assert "empty_output" in str(result)
