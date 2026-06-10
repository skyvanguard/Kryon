"""Tests for the engage post-report artifacts helper (F3.3/F2.4/F3.2 wiring)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from kryon.cli.engage import emit_post_report_artifacts


def _findings(*sevs):
    return [SimpleNamespace(severity=s) for s in sevs]


def test_trend_recorded_and_emitted_after_two_runs(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    trends = tmp_path / "trends"
    common = dict(out_dir=out_dir, engagement_id="e1", client="banco_x", auditor="A", do_sign=False)

    # First run — baseline, no trend section yet.
    emit_post_report_artifacts(findings=_findings("HIGH", "HIGH"), paths={}, trend_base_dir=trends, **common)
    paths2: dict[str, str] = {}
    msgs = emit_post_report_artifacts(findings=_findings("HIGH"), paths=paths2, trend_base_dir=trends, **common)

    assert "trend" in paths2
    assert (out_dir / "kryon-e1-trend.md").exists()
    assert any("trend" in m for m in msgs)


def test_no_trend_without_client(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    paths: dict[str, str] = {}
    emit_post_report_artifacts(
        findings=_findings("HIGH"),
        out_dir=out_dir,
        engagement_id="e1",
        client="",
        auditor="A",
        do_sign=False,
        paths=paths,
        trend_base_dir=tmp_path / "t",
    )
    assert "trend" not in paths


def test_evidence_appendix_emitted_when_artifacts_exist(tmp_path):
    from kryon.evidence.store import EvidenceStore

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    EvidenceStore(out_dir).add_text("FGT-1.1", "config.txt", "set admin ''")
    paths: dict[str, str] = {}
    emit_post_report_artifacts(
        findings=_findings("HIGH"),
        out_dir=out_dir,
        engagement_id="e1",
        client="",
        auditor="A",
        do_sign=False,
        paths=paths,
        trend_base_dir=tmp_path / "t",
    )
    assert "evidence_appendix" in paths
    assert (out_dir / "kryon-e1-evidence.md").exists()


def test_no_evidence_appendix_when_empty(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    paths: dict[str, str] = {}
    emit_post_report_artifacts(
        findings=[],
        out_dir=out_dir,
        engagement_id="e1",
        client="",
        auditor="A",
        do_sign=False,
        paths=paths,
        trend_base_dir=tmp_path / "t",
    )
    assert "evidence_appendix" not in paths


def test_signing_signs_pdf_when_requested(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    # Keep the signing key inside tmp_path.
    monkeypatch.setattr("kryon.reporting.signing._default_key_path", lambda: tmp_path / "key.pem")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    pdf = out_dir / "report.pdf"
    pdf.write_bytes(b"%PDF fake")
    paths = {"pdf": str(pdf)}
    emit_post_report_artifacts(
        findings=_findings("HIGH"),
        out_dir=out_dir,
        engagement_id="e1",
        client="",
        auditor="auditor",
        do_sign=True,
        paths=paths,
        trend_base_dir=tmp_path / "t",
    )
    assert "pdf_sig" in paths
    from kryon.reporting.signing import verify_signature

    assert verify_signature(pdf) is True


def test_no_signing_when_flag_off(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    pdf = out_dir / "report.pdf"
    pdf.write_bytes(b"%PDF")
    paths = {"pdf": str(pdf)}
    emit_post_report_artifacts(
        findings=_findings("HIGH"),
        out_dir=out_dir,
        engagement_id="e1",
        client="",
        auditor="A",
        do_sign=False,
        paths=paths,
        trend_base_dir=tmp_path / "t",
    )
    assert "pdf_sig" not in paths
