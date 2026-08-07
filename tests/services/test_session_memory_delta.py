"""T4-M1: SessionMemory.update() must scan only the messages added since the last
call, not the whole history every turn (that was O(n²) over a session)."""

from __future__ import annotations

import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.services.session_memory import SessionMemory


def _msg(text: str) -> dict:
    return {"role": "assistant", "content": text}


def test_update_scans_only_the_delta(tmp_path):
    sm = SessionMemory(filepath=str(tmp_path / "mem.md"))
    seen_sizes: list[int] = []
    orig = SessionMemory._collect_text

    def spy(messages):
        seen_sizes.append(len(messages))
        return orig(messages)

    sm._collect_text = staticmethod(spy).__func__  # bind spy

    history = [_msg("target http://box.htb"), _msg("open port 22")]
    sm.update(history)
    history.append(_msg("Username: bob, Password: hunter2"))
    sm.update(history)
    history.append(_msg("nothing new here"))
    sm.update(history)

    # First call sees 2 (all new), then only the 1-message deltas — never re-scans.
    assert seen_sizes == [2, 1, 1]
    assert sm._processed_count == 4


def test_accumulated_facts_match_full_scan(tmp_path):
    # Delta-processing must reach the same state as scanning everything at once.
    history = [
        _msg("Nmap scan report for box.htb (10.10.10.5)"),
        _msg("Username: alice, Password: secret1"),
        _msg("uid=0(root)"),
    ]
    incremental = SessionMemory(filepath=str(tmp_path / "a.md"))
    for i in range(1, len(history) + 1):
        incremental.update(history[:i])

    whole = SessionMemory(filepath=str(tmp_path / "b.md"))
    whole.update(history)

    assert incremental._resolved_ip == whole._resolved_ip == "10.10.10.5"
    assert "alice:secret1" in incremental._creds
    assert incremental._creds == whole._creds
    assert incremental._shell_gained == whole._shell_gained is True


def test_shrunk_history_reprocesses_from_start(tmp_path):
    sm = SessionMemory(filepath=str(tmp_path / "mem.md"))
    sm.update([_msg("a"), _msg("b"), _msg("c")])
    assert sm._processed_count == 3
    # Compaction replaced history with a shorter list → offset must reset.
    sm.update([_msg("Username: eve, Password: pw")])
    assert sm._processed_count == 1
    assert "eve:pw" in sm._creds
