"""Tests for the run-scoped command dedup that breaks the repeated-curl loop."""

from __future__ import annotations

from kryon.tools.common.command_dedup import check_repeat, reset


def test_suppresses_third_identical_run():
    reset()
    cmd = "curl -s 'http://t/rest/products/search?q=1'"
    assert check_repeat(cmd) is None  # 1st runs
    assert check_repeat(cmd) is None  # 2nd runs (grace)
    third = check_repeat(cmd)
    assert third is not None and "DUPLICATE" in third  # 3rd suppressed
    assert check_repeat(cmd) is not None  # 4th+ suppressed


def test_whitespace_normalized():
    reset()
    check_repeat("curl  -s   http://t")
    check_repeat("curl -s http://t")
    # Same command modulo whitespace -> this is the 3rd -> suppressed.
    assert check_repeat("curl -s  http://t ") is not None


def test_distinct_commands_not_suppressed():
    reset()
    assert check_repeat("curl a") is None
    assert check_repeat("curl b") is None
    assert check_repeat("curl c") is None


def test_empty_is_ignored():
    reset()
    assert check_repeat("") is None
    assert check_repeat("   ") is None


def test_lru_evicts_old():
    reset()
    for i in range(100):
        check_repeat(f"cmd {i}")
    # 'cmd 0' was evicted long ago -> counts as fresh (1) -> not suppressed.
    assert check_repeat("cmd 0") is None
