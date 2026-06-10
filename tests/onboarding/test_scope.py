"""Tests for formal engagement scope (F2.3)."""

from __future__ import annotations

from kryon.onboarding.scope import (
    create_scope,
    is_in_scope,
    load_scope,
    save_scope,
    verify_scope,
)


def test_create_scope_has_stable_hash_independent_of_timestamp():
    a = create_scope("banco_x", ["10.0.0.0/24"], exclude=["10.0.0.5"], created_utc="2026-01-01")
    b = create_scope("banco_x", ["10.0.0.0/24"], exclude=["10.0.0.5"], created_utc="2026-12-31")
    assert a.scope_hash == b.scope_hash  # timestamp not part of the integrity hash


def test_in_scope_cidr_and_exclude():
    scope = create_scope("c", ["10.0.0.0/24"], exclude=["10.0.0.5"])
    assert is_in_scope(scope, "10.0.0.10") is True
    assert is_in_scope(scope, "10.0.0.5") is False  # explicitly excluded
    assert is_in_scope(scope, "192.168.1.1") is False  # outside ranges


def test_single_ip_range():
    scope = create_scope("c", ["172.16.4.9"])
    assert is_in_scope(scope, "172.16.4.9") is True
    assert is_in_scope(scope, "172.16.4.10") is False


def test_hostname_entries_exact_match():
    scope = create_scope("c", ["app.bank.test"])
    assert is_in_scope(scope, "app.bank.test") is True
    assert is_in_scope(scope, "other.bank.test") is False


def test_save_load_roundtrip(tmp_path):
    scope = create_scope("banco_x", ["10.0.0.0/24"], exclude=["10.0.0.1"], systems="PCI: CDE", authorized_by="CISO")
    path = save_scope(scope, tmp_path / "scope.json")
    loaded = load_scope(path)
    assert loaded.client == "banco_x"
    assert loaded.ip_ranges == ("10.0.0.0/24",)
    assert loaded.systems == "PCI: CDE"
    assert verify_scope(loaded) is True


def test_verify_detects_tampering(tmp_path):
    scope = create_scope("banco_x", ["10.0.0.0/24"])
    path = save_scope(scope, tmp_path / "scope.json")
    # Tamper: widen the scope on disk without recomputing the hash.
    text = path.read_text(encoding="utf-8").replace("10.0.0.0/24", "0.0.0.0/0")
    path.write_text(text, encoding="utf-8")
    assert verify_scope(load_scope(path)) is False
