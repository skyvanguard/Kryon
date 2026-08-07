"""The REPL Magic Doc must persist credentials/loot (the foothold) and must not go
mute after 5 updates when new material appears.

Regression: session_memory never wrote creds/hashes, and a hard injection cap of 5
returned "" forever — so a cred cracked 10 turns ago vanished from the only memory
that survives auto-compaction."""

from __future__ import annotations

import pytest

from kryon.services.session_memory import SessionMemory


@pytest.fixture
def mem(tmp_path):
    return SessionMemory(filepath=str(tmp_path / "session.md"))


def _msg(text: str):
    return [{"role": "assistant", "content": text}]


def test_persists_comma_form_cred(mem):
    mem.update(_msg("wpscan: Valid Combinations Found: Username: admin, Password: my2boys"))
    assert "admin:my2boys" in mem._creds
    doc = mem._path.read_text(encoding="utf-8")
    assert "Credentials & Loot" in doc
    assert "admin:my2boys" in doc


def test_persists_ntlm_hash(mem):
    mem.update(_msg("Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"))
    assert any("31d6cfe0" in loot for loot in mem._loot)
    assert "loot:" in mem._path.read_text(encoding="utf-8")


def test_new_material_resets_injection_cap(mem):
    # Simulate an exhausted cap, then a fresh credential appears. update() consumes
    # the cumulative append-only history (T4-M1 delta), so the second call grows it.
    hist = _msg("nmap scan: 22/tcp open ssh")
    mem.update(hist)
    mem._injection_count = 5  # cap reached — get_context would return ""
    mem._last_injected_hash = "stale"
    hist = hist + _msg("cracked: Username: bob, Password: hunter2")
    mem.update(hist)
    assert mem._injection_count == 0  # material progress reset the cap
    ctx = mem.get_context()
    assert "hunter2" in ctx


def test_benign_update_does_not_reset_cap(mem):
    hist = _msg("22/tcp open ssh")
    mem.update(hist)
    mem._injection_count = 5
    hist = hist + _msg("just some more banner text, no creds")
    mem.update(hist)
    assert mem._injection_count == 5  # no material progress → cap stays
