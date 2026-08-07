"""F110 — TDD contract for the Nuclei wrapper."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from kryon.tools.nuclei.runner import (
    NucleiFinding,
    NucleiResult,
    NuclieConfig,
    is_nuclei_available,
    parse_nuclei_jsonl,
    run_nuclei,
    severity_normalize,
)

# =====================================================================
# Severity normalization
# =====================================================================


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("critical", "CRITICAL"),
        ("high", "HIGH"),
        ("Medium", "MEDIUM"),
        ("LOW", "LOW"),
        ("info", "INFO"),
        ("informative", "INFO"),
        ("unknown", "INFO"),
        ("", "INFO"),
        ("nonsense", "INFO"),
    ],
)
def test_severity_normalize(raw, expected):
    assert severity_normalize(raw) == expected


# =====================================================================
# JSONL parser
# =====================================================================


def _sample_event(
    template_id: str = "wordpress-detect",
    name: str = "WordPress Detected",
    severity: str = "info",
    matched_at: str = "https://example.com/",
    tags: list[str] | None = None,
    cve: str | None = None,
) -> str:
    evt: dict = {
        "template-id": template_id,
        "matched-at": matched_at,
        "host": "example.com",
        "info": {
            "name": name,
            "severity": severity,
            "tags": tags or ["tech", "wordpress"],
            "description": "Detected WordPress instance",
            "reference": ["https://wordpress.org"],
        },
    }
    if cve:
        evt["info"]["classification"] = {
            "cve-id": [cve],
            "cvss-score": 9.8,
        }
    return json.dumps(evt)


def test_parse_single_event():
    findings = parse_nuclei_jsonl(_sample_event())
    assert len(findings) == 1
    f = findings[0]
    assert f.template_id == "wordpress-detect"
    assert f.severity == "INFO"
    assert f.nuclei_severity == "info"
    assert "tech" in f.tags
    assert "wordpress" in f.tags
    assert f.reference == ("https://wordpress.org",)


def test_parse_multiple_events():
    body = "\n".join(
        [
            _sample_event(template_id="wp-detect", severity="info"),
            _sample_event(
                template_id="cve-2021-1234",
                name="Critical RCE",
                severity="critical",
                cve="CVE-2021-1234",
            ),
            _sample_event(template_id="exposed-env", severity="high"),
        ]
    )
    findings = parse_nuclei_jsonl(body)
    assert len(findings) == 3
    severities = {f.severity for f in findings}
    assert severities == {"INFO", "CRITICAL", "HIGH"}


def test_parse_cve_classification():
    line = _sample_event(
        template_id="cve-2024-1234",
        severity="critical",
        cve="CVE-2024-1234",
    )
    findings = parse_nuclei_jsonl(line)
    assert findings[0].cve_id == "CVE-2024-1234"
    assert findings[0].cvss_score == pytest.approx(9.8)


def test_parse_skips_malformed_lines():
    body = "\n".join(
        [
            _sample_event(),
            "not valid json {",
            "[1, 2, 3]",  # valid JSON but not a dict
            _sample_event(template_id="other"),
        ]
    )
    findings = parse_nuclei_jsonl(body)
    assert len(findings) == 2


def test_parse_empty_returns_empty():
    assert parse_nuclei_jsonl("") == []
    assert parse_nuclei_jsonl("\n\n\n") == []


def test_parse_tags_as_string():
    """Some nuclei versions emit tags as comma-separated string."""
    evt = json.dumps(
        {
            "template-id": "x",
            "matched-at": "https://example.com/",
            "info": {"name": "x", "severity": "low", "tags": "tech,cms,wordpress"},
        }
    )
    findings = parse_nuclei_jsonl(evt)
    assert findings[0].tags == ("tech", "cms", "wordpress")


def test_parse_reference_as_string():
    evt = json.dumps(
        {
            "template-id": "x",
            "matched-at": "https://example.com/",
            "info": {"name": "x", "severity": "low", "reference": "https://foo.example/x"},
        }
    )
    findings = parse_nuclei_jsonl(evt)
    assert findings[0].reference == ("https://foo.example/x",)


def test_parse_handles_missing_info():
    """Defensive: missing info dict shouldn't crash the parser."""
    evt = json.dumps({"template-id": "x", "matched-at": "https://example.com/"})
    findings = parse_nuclei_jsonl(evt)
    assert len(findings) == 1
    assert findings[0].severity == "INFO"


# =====================================================================
# is_nuclei_available
# =====================================================================


def test_is_nuclei_available_real():
    """Whatever the real environment is, this should return a bool
    without raising."""
    result = is_nuclei_available()
    assert isinstance(result, bool)


# =====================================================================
# run_nuclei — uses subprocess.run mock
# =====================================================================


def test_run_nuclei_missing_binary():
    """When binary doesn't exist, returns nuclei_missing=True."""
    cfg = NuclieConfig(
        targets=("https://example.com",),
        nuclei_binary="nuclei-definitely-not-installed-xyz123",
    )
    result = run_nuclei(cfg)
    assert result.nuclei_missing is True
    assert result.findings == ()


def test_run_nuclei_no_targets():
    """No targets should short-circuit."""
    cfg = NuclieConfig(targets=())
    # Pretend nuclei exists so we don't short-circuit on availability
    with patch("kryon.tools.nuclei.runner.is_nuclei_available", return_value=True):
        result = run_nuclei(cfg)
    assert result.exit_code == -2
    assert result.findings == ()


def test_run_nuclei_parses_subprocess_output():
    """Mock subprocess.run to return canned JSONL; verify parsing."""
    fake_stdout = "\n".join(
        [
            _sample_event(template_id="t1", severity="high"),
            _sample_event(template_id="t2", severity="critical"),
        ]
    )

    class _FakeProc:
        stdout = fake_stdout
        stderr = ""
        returncode = 0

    cfg = NuclieConfig(targets=("https://example.com",))
    with (
        patch("kryon.tools.nuclei.runner.is_nuclei_available", return_value=True),
        patch("kryon.tools.nuclei.runner.subprocess.run", return_value=_FakeProc()),
    ):
        result = run_nuclei(cfg)
    assert result.nuclei_missing is False
    assert len(result.findings) == 2
    assert result.exit_code == 0
    # Sorted: CRITICAL first
    assert result.findings[0].severity == "CRITICAL"
    assert result.findings[1].severity == "HIGH"


def test_run_nuclei_handles_timeout():
    import subprocess

    cfg = NuclieConfig(
        targets=("https://example.com",),
        overall_timeout_seconds=1,
    )

    def _raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nuclei", timeout=1)

    with (
        patch("kryon.tools.nuclei.runner.is_nuclei_available", return_value=True),
        patch("kryon.tools.nuclei.runner.subprocess.run", side_effect=_raise_timeout),
    ):
        result = run_nuclei(cfg)
    assert result.exit_code == -3


def test_run_nuclei_command_includes_banca_safe_flags():
    """The constructed nuclei command should include -no-interactsh,
    -exclude-tags=code (etc), -jsonl."""
    captured_args: list[list[str]] = []

    class _FakeProc:
        stdout = ""
        stderr = ""
        returncode = 0

    def _capture(args, **kwargs):
        captured_args.append(args)
        return _FakeProc()

    cfg = NuclieConfig(targets=("https://example.com",))
    with (
        patch("kryon.tools.nuclei.runner.is_nuclei_available", return_value=True),
        patch("kryon.tools.nuclei.runner.subprocess.run", side_effect=_capture),
    ):
        run_nuclei(cfg)
    args = captured_args[0]
    assert "-jsonl" in args
    assert "-no-interactsh" in args
    assert "-exclude-tags" in args
    excl_idx = args.index("-exclude-tags")
    assert "code" in args[excl_idx + 1]
    assert "headless" in args[excl_idx + 1]
    assert "unsafe" in args[excl_idx + 1]


def test_run_nuclei_severity_filter_applied():
    """`-severity` flag should reflect the configured set."""
    captured: list[list[str]] = []

    class _FakeProc:
        stdout = ""
        stderr = ""
        returncode = 0

    def _cap(args, **kwargs):
        captured.append(args)
        return _FakeProc()

    cfg = NuclieConfig(targets=("https://example.com",), severities=("high", "critical"))
    with (
        patch("kryon.tools.nuclei.runner.is_nuclei_available", return_value=True),
        patch("kryon.tools.nuclei.runner.subprocess.run", side_effect=_cap),
    ):
        run_nuclei(cfg)
    args = captured[0]
    assert "-severity" in args
    sev_idx = args.index("-severity")
    assert args[sev_idx + 1] == "high,critical"


def test_run_nuclei_findings_sorted_by_severity():
    fake = "\n".join(
        [
            _sample_event(template_id="info-one", severity="info"),
            _sample_event(template_id="crit-one", severity="critical"),
            _sample_event(template_id="med-one", severity="medium"),
            _sample_event(template_id="high-one", severity="high"),
        ]
    )

    class _FakeProc:
        stdout = fake
        stderr = ""
        returncode = 0

    cfg = NuclieConfig(targets=("https://example.com",))
    with (
        patch("kryon.tools.nuclei.runner.is_nuclei_available", return_value=True),
        patch("kryon.tools.nuclei.runner.subprocess.run", return_value=_FakeProc()),
    ):
        result = run_nuclei(cfg)
    severities = [f.severity for f in result.findings]
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[s] for s in severities]
    assert ranks == sorted(ranks)


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    f = NucleiFinding(
        template_id="x",
        name="x",
        severity="LOW",
        nuclei_severity="low",
        matched_at="x",
        target="x",
    )
    with pytest.raises(FrozenInstanceError):
        f.severity = "HIGH"  # type: ignore[misc]
