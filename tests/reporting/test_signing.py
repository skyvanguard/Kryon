"""Tests for detached Ed25519 report signing (F3.2)."""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from kryon.reporting.signing import ReportSigner, verify_signature


def test_sign_and_verify_roundtrip(tmp_path):
    report = tmp_path / "report.pdf"
    report.write_bytes(b"%PDF fake report bytes")
    signer = ReportSigner(key_path=tmp_path / "key.pem")
    sidecar = signer.sign_file(report, signer="SkyVanguard", timestamp="2026-06-10T00:00:00Z")
    assert sidecar.exists()
    assert verify_signature(report) is True


def test_verify_detects_tampered_file(tmp_path):
    report = tmp_path / "report.pdf"
    report.write_bytes(b"original")
    ReportSigner(key_path=tmp_path / "key.pem").sign_file(report)
    report.write_bytes(b"tampered")  # change after signing
    assert verify_signature(report) is False


def test_verify_missing_sidecar(tmp_path):
    report = tmp_path / "report.pdf"
    report.write_bytes(b"x")
    assert verify_signature(report) is False


def test_sidecar_has_expected_fields(tmp_path):
    import json

    report = tmp_path / "r.pdf"
    report.write_bytes(b"data")
    sidecar = ReportSigner(key_path=tmp_path / "key.pem").sign_file(report, signer="auditor")
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    assert meta["algo"] == "Ed25519"
    assert meta["signer"] == "auditor"
    assert len(meta["sha256"]) == 64
    assert meta["public_key"] and meta["signature"]


def test_key_is_reused_across_instances(tmp_path):
    kp = tmp_path / "key.pem"
    pub1 = ReportSigner(key_path=kp).public_key_hex()
    pub2 = ReportSigner(key_path=kp).public_key_hex()
    assert pub1 == pub2  # persisted key, stable identity


def test_tampered_signature_fails(tmp_path):
    import json

    report = tmp_path / "r.pdf"
    report.write_bytes(b"data")
    sidecar = ReportSigner(key_path=tmp_path / "key.pem").sign_file(report)
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    meta["signature"] = "00" * 64  # forge
    sidecar.write_text(json.dumps(meta), encoding="utf-8")
    assert verify_signature(report) is False
