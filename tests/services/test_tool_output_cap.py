"""cap_tool_output must preserve high-value lines (hash/flag/cred) that fall in the
truncated middle.

Regression (#7): it kept only head 500 + tail 200, so a hash/flag/credential in the
middle of a big dump (linpeas, hashdump, loot) vanished — fatal for a THM pwn."""

from __future__ import annotations

from kryon.services.tool_output_cap import (
    _DEFAULT_TOOL_RESULT_CHARS,
    _LARGE_WINDOW_TOOL_RESULT_CHARS,
    cap_tool_output,
    resolve_tool_result_cap,
)


def test_small_output_unchanged():
    assert cap_tool_output("short output", "x") == "short output"


def test_resolve_tool_result_cap_window_relative():
    assert resolve_tool_result_cap(32_768) == _DEFAULT_TOOL_RESULT_CHARS
    assert resolve_tool_result_cap(128_000) == _DEFAULT_TOOL_RESULT_CHARS
    assert resolve_tool_result_cap(1_000_000) == _LARGE_WINDOW_TOOL_RESULT_CHARS
    assert resolve_tool_result_cap(500_000) == _LARGE_WINDOW_TOOL_RESULT_CHARS


def test_resolve_tool_result_cap_override_wins():
    assert resolve_tool_result_cap(1_000_000, override="5000") == 5000
    assert resolve_tool_result_cap(1_000_000, override="bad") == _LARGE_WINDOW_TOOL_RESULT_CHARS
    assert resolve_tool_result_cap(1_000_000, override="-1") == _LARGE_WINDOW_TOOL_RESULT_CHARS


def test_large_window_keeps_medium_output_whole(monkeypatch):
    # On a 1M window, a 20KB nmap/nuclei output must NOT be truncated (the 4B-era
    # 5k cap threw away the raw evidence a capable model chains from).
    monkeypatch.setenv("KRYON_MODEL_MAX_TOKENS", "1000000")
    monkeypatch.delenv("KRYON_MAX_TOOL_RESULT", raising=False)
    from kryon.config import settings

    settings(refresh=True)
    try:
        content = "x" * 20_000  # under the 50k large-window cap
        assert cap_tool_output(content, "nmap") == content
    finally:
        monkeypatch.delenv("KRYON_MODEL_MAX_TOKENS", raising=False)
        settings(refresh=True)


def test_env_override_forces_small_cap_even_on_large_window(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_TOOL_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("KRYON_MODEL_MAX_TOKENS", "1000000")
    monkeypatch.setenv("KRYON_MAX_TOOL_RESULT", "5000")
    from kryon.config import settings

    settings(refresh=True)
    try:
        content = "x" * 20_000
        out = cap_tool_output(content, "nmap")
        assert len(out) < len(content)  # override wins → still capped
    finally:
        for v in ("KRYON_MODEL_MAX_TOKENS", "KRYON_MAX_TOOL_RESULT"):
            monkeypatch.delenv(v, raising=False)
        settings(refresh=True)


def test_layers_1_and_2_large_window_caps_agree():
    # Layer-2 (micro_compact) must never re-trim what layer-1 preserved.
    from kryon.services.micro_compact import _LARGE_WINDOW_BUDGET

    assert _LARGE_WINDOW_TOOL_RESULT_CHARS == _LARGE_WINDOW_BUDGET


def test_shadow_hash_in_middle_is_preserved(tmp_path, monkeypatch):
    monkeypatch.setenv("KRYON_TOOL_OUTPUT_DIR", str(tmp_path))
    filler = "noise noise noise line of linpeas output\n" * 500  # ~20KB
    secret = "root:$6$abcd$deadbeefhashvalue:19000:0:99999:7:::"
    content = filler[:8000] + "\n" + secret + "\n" + filler[8000:]
    out = cap_tool_output(content, "linpeas")
    assert len(out) < len(content)  # capped
    assert "$6$abcd$deadbeefhashvalue" in out  # secret survived the cap


def test_flag_in_middle_is_preserved(tmp_path, monkeypatch):
    monkeypatch.setenv("KRYON_TOOL_OUTPUT_DIR", str(tmp_path))
    content = ("x" * 300 + "\n") * 30 + "flag{buried_treasure_123}\n" + ("y" * 300 + "\n") * 30
    out = cap_tool_output(content, "cat")
    assert "flag{buried_treasure_123}" in out


def test_nopasswd_line_preserved(tmp_path, monkeypatch):
    monkeypatch.setenv("KRYON_TOOL_OUTPUT_DIR", str(tmp_path))
    content = ("env_keep line\n" * 800) + "(ALL) NOPASSWD: /usr/bin/find\n" + ("more\n" * 800)
    out = cap_tool_output(content, "run_command")
    assert "NOPASSWD: /usr/bin/find" in out
