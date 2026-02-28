"""Tests for credentials.credential_dataset — SecLists search, wordlists, hash ID."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.credentials.credential_dataset import (
    search_credential_dataset,
    generate_targeted_wordlist,
    identify_hash_type,
)


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# search_credential_dataset
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_seclists(monkeypatch):
    """SecLists search runs grep against standard paths."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return "admin:password123"

    monkeypatch.setattr("kryon.tools.credentials.credential_dataset.run_command", fake_run)

    result = await _invoke(search_credential_dataset, {
        "query": "admin",
        "dataset": "seclists",
    })
    assert "admin:password123" in result
    assert len(calls) == 3  # 3 seclists paths


@pytest.mark.asyncio
async def test_search_unknown_dataset(monkeypatch):
    """Unknown dataset returns error."""
    result = await _invoke(search_credential_dataset, {
        "query": "admin",
        "dataset": "unknown_db",
    })
    assert "Error" in result
    assert "Unknown dataset" in result


# ---------------------------------------------------------------------------
# generate_targeted_wordlist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_wordlist_basic():
    """Basic wordlist generation produces passwords based on target name."""
    result = await _invoke(generate_targeted_wordlist, {
        "target_name": "Acme",
    })
    passwords = result.strip().split("\n")
    assert len(passwords) > 0
    # Should contain variations of "Acme"
    assert any("Acme" in p or "acme" in p or "ACME" in p for p in passwords)


@pytest.mark.asyncio
async def test_generate_wordlist_with_keywords():
    """Keywords are incorporated into the wordlist."""
    result = await _invoke(generate_targeted_wordlist, {
        "target_name": "Corp",
        "keywords": "summer,beach",
    })
    passwords = result.strip().split("\n")
    assert any("summer" in p.lower() for p in passwords)
    assert any("beach" in p.lower() for p in passwords)


@pytest.mark.asyncio
async def test_generate_wordlist_with_leet():
    """Leet speak variations are generated."""
    result = await _invoke(generate_targeted_wordlist, {
        "target_name": "test",
        "include_leet": True,
    })
    passwords = result.strip().split("\n")
    # "test" -> "7357" or "73$7" etc.
    assert any("7" in p or "$" in p or "3" in p for p in passwords)


@pytest.mark.asyncio
async def test_generate_wordlist_min_length_filter():
    """Passwords shorter than min_length are filtered out."""
    result = await _invoke(generate_targeted_wordlist, {
        "target_name": "ab",
        "min_length": 10,
        "include_leet": False,
        "include_dates": True,
    })
    passwords = [p for p in result.strip().split("\n") if p]
    # All passwords should be >= 10 chars
    for pw in passwords:
        assert len(pw) >= 10, f"Password '{pw}' is shorter than min_length=10"


# ---------------------------------------------------------------------------
# identify_hash_type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_identify_hash_md5():
    """MD5 hash is correctly identified."""
    result = await _invoke(identify_hash_type, {
        "hash_value": "d41d8cd98f00b204e9800998ecf8427e",
    })
    assert "MD5" in result


@pytest.mark.asyncio
async def test_identify_hash_sha256():
    """SHA-256 hash is correctly identified."""
    result = await _invoke(identify_hash_type, {
        "hash_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    })
    assert "SHA-256" in result


@pytest.mark.asyncio
async def test_identify_hash_bcrypt():
    """bcrypt hash is correctly identified."""
    result = await _invoke(identify_hash_type, {
        "hash_value": "$2b$12$LJ3m4ys3Rr42fXMwKbhsx.HxEb3rBFvTq7wQbXvpZx4.RlVGwvJfS",
    })
    assert "bcrypt" in result


@pytest.mark.asyncio
async def test_identify_hash_unknown():
    """Unknown hash returns unknown with length info."""
    result = await _invoke(identify_hash_type, {
        "hash_value": "not-a-real-hash",
    })
    assert "Unknown" in result or "length" in result.lower()
