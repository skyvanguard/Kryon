"""F203.J — Tests for lab_scoreboard."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

# Add scripts/ to path so we can import lab_scoreboard
_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import pytest
from lab_scoreboard import (  # noqa: E402
    GROUND_TRUTH,
    ScoreResult,
    extract_cwes,
    format_report,
    infer_target_from_text,
    main,
    score_text,
)

# ---------------------------------------------------------------------------
# extract_cwes
# ---------------------------------------------------------------------------


class TestExtractCWEs:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("Found CWE-79 in /search", {"CWE-79"}),
            ("CWE-89 SQL injection + CWE-306 admin", {"CWE-89", "CWE-306"}),
            ("cwe-1004 cookie missing flag", {"CWE-1004"}),
            ("CWE_319 plaintext + CWE 200 disclosure", {"CWE-319", "CWE-200"}),
            ("No CWE here", set()),
            ("", set()),
        ],
    )
    def test_extraction(self, text, expected):
        assert extract_cwes(text) == expected

    def test_dedups(self):
        text = "CWE-79 first time + CWE-79 second time + CWE-89 once"
        assert extract_cwes(text) == {"CWE-79", "CWE-89"}

    def test_normalizes_leading_zeros(self):
        # CWE-079 → CWE-79
        assert extract_cwes("CWE-079 padded") == {"CWE-79"}


# ---------------------------------------------------------------------------
# infer_target_from_text
# ---------------------------------------------------------------------------


class TestInferTarget:
    def test_web_port_8080(self):
        assert infer_target_from_text("audit http://127.0.0.1:8080/") == "web"

    def test_ssh_port_2222(self):
        assert infer_target_from_text("ssh -p 2222 admin@host") == "ssh"

    def test_db_port_33060(self):
        assert infer_target_from_text("mysql -P 33060 -u app") == "db"

    def test_no_port_returns_none(self):
        assert infer_target_from_text("audit my application") is None


# ---------------------------------------------------------------------------
# score_text — core scoring
# ---------------------------------------------------------------------------


class TestScoreText:
    def test_perfect_score(self):
        text = "Found CWE-319, CWE-1004, CWE-306, CWE-200 in target"
        r = score_text(text, "web")
        assert r.tp == {"CWE-319", "CWE-1004", "CWE-306", "CWE-200"}
        assert r.fp == set()
        assert r.fn == set()
        assert r.precision == 1.0
        assert r.recall == 1.0
        assert r.f1 == 1.0

    def test_partial_match(self):
        # 2/4 detected
        text = "Found CWE-319 plaintext + CWE-306 admin without auth"
        r = score_text(text, "web")
        assert r.tp == {"CWE-319", "CWE-306"}
        assert r.fn == {"CWE-1004", "CWE-200"}
        assert r.fp == set()
        assert r.recall == 0.5
        assert r.precision == 1.0

    def test_false_positives(self):
        # 1 TP + 2 FP (CWE-89 SQLi not in web ground truth)
        text = "Found CWE-319 plus CWE-89 SQLi and CWE-79 XSS"
        r = score_text(text, "web")
        assert "CWE-319" in r.tp
        assert {"CWE-89", "CWE-79"} <= r.fp

    def test_zero_emitted(self):
        text = "no CWE mentions here"
        r = score_text(text, "web")
        assert r.tp == set()
        assert r.fn == GROUND_TRUTH["web"]
        assert r.recall == 0.0
        assert r.precision == 0.0  # 0/0 → 0

    def test_unknown_target_raises(self):
        with pytest.raises(ValueError):
            score_text("anything", "nonexistent")


# ---------------------------------------------------------------------------
# Wilson lower bound
# ---------------------------------------------------------------------------


class TestWilsonLowerBound:
    def test_perfect_recall_high_wilson(self):
        # 4/4 → wilson should be > 0.4 (Wilson at n=4, p=1.0)
        text = "CWE-319, CWE-1004, CWE-306, CWE-200"
        r = score_text(text, "web")
        # Wilson at p=1.0, n=4, z=1.96:
        # lower = (1 + 1.96²/8 - 1.96·sqrt(0/4 + 1.96²/64))/(1 + 1.96²/4)
        #       = (1 + 0.48 - 1.96·0.245)/(1 + 0.96) ≈ 1.0/1.96 ≈ 0.51
        assert r.wilson_lower_95 > 0.4

    def test_zero_recall_zero_wilson(self):
        text = "no mentions"
        r = score_text(text, "web")
        assert r.wilson_lower_95 == 0.0

    def test_empty_ground_truth_zero(self):
        # Manufacture an empty ground truth (not possible via GROUND_TRUTH but
        # via ScoreResult direct construction).
        r = ScoreResult(target="x", ground_truth=set(), emitted=set(), tp=set(), fp=set(), fn=set())
        assert r.wilson_lower_95 == 0.0


# ---------------------------------------------------------------------------
# format_report
# ---------------------------------------------------------------------------


class TestFormatReport:
    def test_includes_target(self):
        r = score_text("CWE-319", "web")
        report = format_report(r)
        assert "target: web" in report

    def test_includes_metrics(self):
        r = score_text("CWE-319", "web")
        report = format_report(r)
        assert "Precision:" in report
        assert "Recall:" in report
        assert "F1:" in report
        assert "Wilson" in report

    def test_handles_empty_cases(self):
        r = score_text("nothing", "web")
        report = format_report(r)
        assert "TP (0)" in report
        assert "(none)" in report


# ---------------------------------------------------------------------------
# main CLI
# ---------------------------------------------------------------------------


class TestMainCLI:
    def test_text_arg_explicit_target(self, capsys):
        rc = main(["--text", "CWE-319 found", "--target", "web"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Lab Scoreboard" in out
        assert "target: web" in out

    def test_json_output(self, capsys):
        rc = main(["--text", "CWE-319 CWE-1004", "--target", "web", "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["target"] == "web"
        assert "CWE-319" in data["tp"]
        assert "CWE-1004" in data["tp"]

    def test_inferred_target_from_text(self, capsys):
        rc = main(["--text", "audit http://127.0.0.1:8080/ found CWE-319"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "target: web" in out

    def test_no_target_inferable_errors(self, capsys):
        rc = main(["--text", "no port or url"])
        assert rc == 2

    def test_no_input_errors(self, capsys):
        rc = main([])
        assert rc == 2

    def test_transcript_file(self, capsys, tmp_path):
        f = tmp_path / "t.md"
        f.write_text("# Investigate http://127.0.0.1:8080\n\nFound CWE-306 + CWE-319.\n")
        rc = main(["--transcript", str(f)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "TP (2)" in out

    def test_missing_transcript_errors(self, capsys):
        rc = main(["--transcript", "/nonexistent/path.md"])
        assert rc == 2


# ---------------------------------------------------------------------------
# CWE parent/child normalization (862 → 285)
# ---------------------------------------------------------------------------


def test_child_cwe_credits_parent_in_ground_truth():
    # juice_shop GT has CWE-285; emitting its child CWE-862 should score as TP
    # against 285 and NOT count as a false positive.
    text = "Found CWE-862 missing authorization on /balances and CWE-89 sqli."
    res = score_text(text, "juice_shop")
    assert "CWE-285" in res.tp
    assert "CWE-862" not in res.fp
    assert "CWE-285" not in res.fn


def test_unmapped_emitted_cwe_still_false_positive():
    # CWE-918 (SSRF) is not in juice_shop GT and has no parent mapping → FP.
    res = score_text("Detected CWE-918 ssrf.", "juice_shop")
    assert "CWE-918" in res.fp
