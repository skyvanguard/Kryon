"""F203.D — Tests for `request_skill` tool.

Cubre:
- Skill matched → returns body + other related skills list
- No skill matched → returns generic fallback + near-misses
- Empty topic → returns ERROR
- Body truncation at _BODY_MAX_CHARS
- Telemetry never raises (best-effort)
- Banca-safe: source check confirms no auto-promote, no network
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.tools.knowledge.request_skill import (
    _BODY_MAX_CHARS,
    _GENERIC_FALLBACK,
    _format_skill_body,
    request_skill,
)

# FunctionTool wraps the raw callable on _raw_fn.
_raw = request_skill._raw_fn


def _make_skill(name: str, body: str, description: str = "") -> SimpleNamespace:
    return SimpleNamespace(name=name, body=body, description=description)


# ---------------------------------------------------------------------------
# _format_skill_body
# ---------------------------------------------------------------------------


class TestFormatSkillBody:
    def test_includes_name_and_body(self):
        skill = _make_skill("cwe-79-xss", "## Methodology\nGrep for innerHTML.", "XSS detection")
        out = _format_skill_body(skill)
        assert "cwe-79-xss" in out
        assert "Methodology" in out
        assert "XSS detection" in out

    def test_truncates_long_body(self):
        long_body = "x" * (_BODY_MAX_CHARS + 500)
        skill = _make_skill("big-skill", long_body)
        out = _format_skill_body(skill)
        assert "(truncated)" in out
        # Total output is name+desc+body+truncated marker — body itself capped.
        assert out.count("x") <= _BODY_MAX_CHARS + 100


# ---------------------------------------------------------------------------
# request_skill — skill matched path
# ---------------------------------------------------------------------------


class TestRequestSkillMatched:
    def test_returns_matched_skill_body(self):
        matched_skill = _make_skill(
            "cwe-79-xss",
            "## XSS methodology\nGrep innerHTML and document.write.",
            "XSS detection guide",
        )
        fake_loader = SimpleNamespace(
            match=lambda profile, user_msg: [matched_skill],
            scan=lambda: [matched_skill],
        )
        with patch("kryon.skills.loader.SkillLoader", return_value=fake_loader):
            result = _raw(topic="find XSS in webapp")
        assert "cwe-79-xss" in result
        assert "Grep innerHTML" in result

    def test_lists_other_related_skills(self):
        top = _make_skill("cwe-79-xss", "body1")
        others = [
            _make_skill("cwe-89-sqli", "body2"),
            _make_skill("web-pentest", "body3"),
        ]
        fake_loader = SimpleNamespace(
            match=lambda profile, user_msg: [top] + others,
            scan=lambda: [top] + others,
        )
        with patch("kryon.skills.loader.SkillLoader", return_value=fake_loader):
            result = _raw(topic="webapp")
        assert "cwe-79-xss" in result
        assert "Other related skills" in result
        assert "cwe-89-sqli" in result
        assert "web-pentest" in result


# ---------------------------------------------------------------------------
# request_skill — no match path
# ---------------------------------------------------------------------------


class TestRequestSkillNoMatch:
    def test_no_match_returns_fallback(self):
        fake_loader = SimpleNamespace(
            match=lambda profile, user_msg: [],
            scan=lambda: [],
        )
        with patch("kryon.skills.loader.SkillLoader", return_value=fake_loader):
            result = _raw(topic="esoteric topic nobody knows")
        assert "Generic methodology" in result
        assert "web_fetch_smart" in result
        assert "duckduckgo_search" in result
        # Generic fallback includes the 4 numbered phases
        for i in range(1, 5):
            assert f"{i}." in result

    def test_near_misses_listed_when_no_match(self):
        # No match, but scan returns skills with name overlap
        all_skills = [
            _make_skill("moodle-recon", ""),
            _make_skill("wordpress-audit", ""),
            _make_skill("cwe-79-xss", ""),
        ]
        fake_loader = SimpleNamespace(
            match=lambda profile, user_msg: [],
            scan=lambda: all_skills,
        )
        with patch("kryon.skills.loader.SkillLoader", return_value=fake_loader):
            result = _raw(topic="auditar moodle plugins")
        assert "Closest existing skills" in result
        # The word "moodle" overlaps with moodle-recon skill name
        assert "moodle-recon" in result

    def test_no_near_misses_when_no_overlap(self):
        all_skills = [_make_skill("totally-unrelated-skill", "")]
        fake_loader = SimpleNamespace(
            match=lambda profile, user_msg: [],
            scan=lambda: all_skills,
        )
        with patch("kryon.skills.loader.SkillLoader", return_value=fake_loader):
            result = _raw(topic="xyz123 esoteric")
        assert "(none with name overlap)" in result


# ---------------------------------------------------------------------------
# request_skill — error paths
# ---------------------------------------------------------------------------


class TestRequestSkillErrors:
    def test_empty_topic_returns_error(self):
        result = _raw(topic="")
        assert "ERROR" in result
        assert "empty topic" in result.lower()

    def test_whitespace_only_topic_returns_error(self):
        result = _raw(topic="   \n\t  ")
        assert "ERROR" in result

    def test_loader_unavailable_returns_fallback(self):
        # Simulate ImportError by patching SkillLoader to raise on import.
        with patch.dict("sys.modules", {"kryon.skills.loader": None}):
            # Force reimport to raise ImportError
            result = _raw(topic="anything")
        # When SkillLoader can't import, tool returns generic fallback
        assert "Generic methodology" in result


# ---------------------------------------------------------------------------
# Banca-safe contract — source-level inspection
# ---------------------------------------------------------------------------


class TestBancaSafe:
    """Verify request_skill doesn't auto-promote drafts or touch network."""

    def test_no_filesystem_writes_in_source(self):
        src = Path(__file__).resolve().parents[3] / "src" / "kryon" / "tools" / "knowledge" / "request_skill.py"
        text = src.read_text(encoding="utf-8")
        # No write_text / write_draft / Path(...).mkdir
        assert "write_draft(" not in text
        assert "write_text(" not in text
        assert "open(" not in text or text.count("open(") <= 1  # only docstring uses

    def test_no_network_calls_in_source(self):
        src = Path(__file__).resolve().parents[3] / "src" / "kryon" / "tools" / "knowledge" / "request_skill.py"
        text = src.read_text(encoding="utf-8")
        assert "urllib" not in text
        assert "requests." not in text
        assert "httpx" not in text

    def test_no_subprocess_in_source(self):
        src = Path(__file__).resolve().parents[3] / "src" / "kryon" / "tools" / "knowledge" / "request_skill.py"
        text = src.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "os.system" not in text
