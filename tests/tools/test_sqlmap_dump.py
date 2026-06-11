"""Tests for the SQLi data-extraction tool (kryon.tools.sqlmap_dump)."""

import pytest

from kryon.tools import sqlmap_dump as mod


@pytest.mark.unit
def test_is_function_tool():
    assert mod.sqlmap_dump_database.name == "sqlmap_dump_database"
    assert hasattr(mod.sqlmap_dump_database, "params_json_schema")


@pytest.mark.unit
def test_mask_pans_masks_card_number():
    out = mod._mask_pans("found 4242424242424242 in dump")
    assert "************4242" in out
    assert "4242424242424242" not in out


@pytest.mark.unit
def test_mask_pans_leaves_short_numbers():
    text = "id=1 port=8080 count=12345"
    assert mod._mask_pans(text) == text


@pytest.mark.unit
def test_mask_pans_handles_separators():
    out = mod._mask_pans("4242 4242 4242 4242")
    assert out.endswith("4242")
    assert out.count("*") >= 12


@pytest.mark.unit
def test_dump_reuses_sqlmap_scan_with_flags(monkeypatch):
    captured: dict = {}

    class FakeScan:
        @staticmethod
        def _raw_fn(**kwargs):
            captured.update(kwargs)
            return "Database: appdb\nrow: 4242424242424242"

    monkeypatch.setattr(mod, "sqlmap_scan", FakeScan)
    out = mod.sqlmap_dump_database._raw_fn(url="http://t/p?id=1", dump=True, db="appdb", tbl="users")

    assert captured["url"] == "http://t/p?id=1"
    assert captured["dump"] is True
    assert captured["db"] == "appdb"
    assert captured["tbl"] == "users"
    assert captured["method"] == "GET"
    # output is PAN-masked
    assert "************4242" in out
    assert "4242424242424242" not in out


@pytest.mark.unit
def test_dump_uses_post_when_data_present(monkeypatch):
    captured: dict = {}

    class FakeScan:
        @staticmethod
        def _raw_fn(**kwargs):
            captured.update(kwargs)
            return ""

    monkeypatch.setattr(mod, "sqlmap_scan", FakeScan)
    mod.sqlmap_dump_database._raw_fn(url="http://t/login", data="user=a&pass=b", dump=True)
    assert captured["method"] == "POST"
    assert captured["data"] == "user=a&pass=b"


@pytest.mark.unit
def test_dump_defaults_to_dbs_enumeration(monkeypatch):
    captured: dict = {}

    class FakeScan:
        @staticmethod
        def _raw_fn(**kwargs):
            captured.update(kwargs)
            return ""

    monkeypatch.setattr(mod, "sqlmap_scan", FakeScan)
    # no extraction flag set -> safe default of listing databases
    mod.sqlmap_dump_database._raw_fn(url="http://t/p?id=1")
    assert captured["dbs"] is True
    assert captured["dump"] is False
