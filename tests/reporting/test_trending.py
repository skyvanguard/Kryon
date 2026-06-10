"""Tests for historical trending (F3.3)."""

from __future__ import annotations

from kryon.reporting.trending import (
    build_trend,
    format_trend_markdown,
    load_trend,
    record_trend_point,
)


def test_record_and_load_roundtrip(tmp_path):
    record_trend_point("banco_x", "2026-01-01", {"HIGH": 3, "LOW": 1}, base_dir=tmp_path)
    record_trend_point("banco_x", "2026-02-01", {"HIGH": 1}, base_dir=tmp_path)
    points = load_trend("banco_x", base_dir=tmp_path)
    assert len(points) == 2
    assert points[0].total == 4
    assert points[1].total == 1


def test_build_trend_detects_improvement(tmp_path):
    record_trend_point("c", "d1", {"CRITICAL": 2, "HIGH": 2}, base_dir=tmp_path)
    record_trend_point("c", "d2", {"CRITICAL": 1, "HIGH": 1}, base_dir=tmp_path)
    trend = build_trend(load_trend("c", base_dir=tmp_path))
    assert trend["direction"] == "improving"
    assert trend["delta_critical_high"] == -2


def test_build_trend_detects_worsening(tmp_path):
    record_trend_point("c", "d1", {"HIGH": 1}, base_dir=tmp_path)
    record_trend_point("c", "d2", {"HIGH": 4}, base_dir=tmp_path)
    trend = build_trend(load_trend("c", base_dir=tmp_path))
    assert trend["direction"] == "worsening"
    assert trend["delta_total"] == 3


def test_single_run_is_baseline(tmp_path):
    record_trend_point("c", "d1", {"HIGH": 2}, base_dir=tmp_path)
    trend = build_trend(load_trend("c", base_dir=tmp_path))
    assert trend["direction"] == "baseline"
    assert trend["runs"] == 1


def test_series_aligned_to_severity_order(tmp_path):
    record_trend_point("c", "d1", {"CRITICAL": 1, "HIGH": 2}, base_dir=tmp_path)
    record_trend_point("c", "d2", {"CRITICAL": 0, "HIGH": 1}, base_dir=tmp_path)
    trend = build_trend(load_trend("c", base_dir=tmp_path))
    assert trend["series"]["CRITICAL"] == [1, 0]
    assert trend["series"]["HIGH"] == [2, 1]


def test_format_markdown_renders_direction(tmp_path):
    record_trend_point("c", "d1", {"HIGH": 3}, base_dir=tmp_path)
    record_trend_point("c", "d2", {"HIGH": 1}, base_dir=tmp_path)
    md = format_trend_markdown(build_trend(load_trend("c", base_dir=tmp_path)))
    assert "## Trend" in md
    assert "improving" in md


def test_empty_trend_renders_empty():
    assert format_trend_markdown(build_trend([])) == ""
