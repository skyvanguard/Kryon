"""Tests for the evidence store + chain-of-custody (F2.4)."""

from __future__ import annotations

from kryon.evidence.store import EvidenceStore, render_appendix_markdown


def test_add_text_and_hash(tmp_path):
    store = EvidenceStore(tmp_path)
    item = store.add_text("FGT-1.1", "config.txt", "set admin-password ''")
    assert item.finding_id == "FGT-1.1"
    assert item.kind == "text"
    assert len(item.sha256) == 64
    # File written under evidence/<finding>/<name>
    assert (tmp_path / item.rel_path).read_text(encoding="utf-8") == "set admin-password ''"


def test_add_bytes_screenshot(tmp_path):
    store = EvidenceStore(tmp_path)
    item = store.add_bytes("WIN-1.1", "rdp.png", b"\x89PNG fake", kind="screenshot")
    assert item.kind == "screenshot"
    assert (tmp_path / item.rel_path).read_bytes() == b"\x89PNG fake"


def test_items_and_items_for(tmp_path):
    store = EvidenceStore(tmp_path)
    store.add_text("A", "a1", "x")
    store.add_text("A", "a2", "y")
    store.add_text("B", "b1", "z")
    assert len(store.items()) == 3
    assert len(store.items_for("A")) == 2


def test_verify_detects_tampering(tmp_path):
    store = EvidenceStore(tmp_path)
    item = store.add_text("A", "a1", "original")
    assert store.verify() is True
    # Tamper the artifact on disk without updating the manifest hash.
    (tmp_path / item.rel_path).write_text("tampered", encoding="utf-8")
    assert store.verify() is False


def test_manifest_survives_new_instance(tmp_path):
    EvidenceStore(tmp_path).add_text("A", "a1", "x")
    assert len(EvidenceStore(tmp_path).items()) == 1


def test_render_appendix_groups_by_finding(tmp_path):
    store = EvidenceStore(tmp_path)
    store.add_text("FGT-1.1", "config.txt", "x", captured_utc="2026-06-10")
    store.add_text("FGT-1.1", "log.txt", "y")
    md = render_appendix_markdown(store)
    assert "Appendix — Evidence" in md
    assert "### FGT-1.1" in md
    assert "config.txt" in md and "log.txt" in md


def test_render_appendix_empty(tmp_path):
    assert render_appendix_markdown(EvidenceStore(tmp_path)) == ""
