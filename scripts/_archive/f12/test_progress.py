"""Unit tests for F12.2 progress parsers + live_progress."""
from __future__ import annotations

import io

from rich.console import Console

from kryon.repl.ui.live_progress import run_with_progress
from kryon.repl.ui.progress import (
    AmassProgressParser,
    MasscanProgressParser,
    ProgressState,
    RustscanProgressParser,
    format_progress_bar,
    get_parser_for_command,
)


def test_masscan_parser_percentage_and_rate() -> None:
    p = MasscanProgressParser()
    s = ProgressState()
    s = p.parse_line(
        "rate:  0.61-kpps, 12.34% done, 0:01:23 remaining, found=42", s,
    )
    assert s.percentage == 12.34
    assert "0.61-kpps" in s.current_step
    assert "42 found" in s.current_step
    print("  ok: masscan percentage + rate + found")


def test_rustscan_parser_open_ports() -> None:
    p = RustscanProgressParser()
    s = ProgressState()
    s = p.parse_line("Open 192.168.1.10:22", s)
    assert "192.168.1.10:22" in s.current_step
    print("  ok: rustscan open-port detection")


def test_amass_parser_found_count() -> None:
    p = AmassProgressParser()
    s = ProgressState()
    s = p.parse_line("Discovered: 15", s)
    assert "15 subdomains" in s.current_step
    print("  ok: amass subdomain count")


def test_parser_dispatch_by_command() -> None:
    assert get_parser_for_command("nmap -sV 10.0.0.1").name == "nmap"
    assert get_parser_for_command("masscan -p80 0.0.0.0/0").name == "masscan"
    assert get_parser_for_command("rustscan -a 10.0.0.1").name == "rustscan"
    assert get_parser_for_command("amass enum -d example.com").name == "amass"
    assert get_parser_for_command("some-random-binary").name == "generic"
    print("  ok: parser dispatch covers new tools")


def test_format_progress_bar_with_percentage() -> None:
    s = ProgressState(percentage=37.5, current_step="Scanning", total_lines=100)
    out = format_progress_bar(s, width=20)
    assert "37.5%" in out
    assert "Scanning" in out
    assert "100 lines" in out
    print("  ok: progress bar renders percentage + step + lines")


def test_run_with_progress_captures_stdout() -> None:
    """Smoke test with `echo`-based synthetic command that emits parseable
    progress-like output."""
    buf = io.StringIO()
    con = Console(file=buf, width=100, force_terminal=False, color_system=None)
    # A cheap command that emits a few lines quickly.
    r = run_with_progress(
        "for i in 1 2 3; do echo line $i; done",
        console=con, tail_size=3, timeout_s=10,
    )
    assert r.returncode == 0, r
    assert "line 1" in r.stdout
    assert "line 3" in r.stdout
    assert r.lines_emitted >= 3
    print(f"  ok: run_with_progress captured {r.lines_emitted} lines "
          f"in {r.duration_s:.2f}s")


def test_run_with_progress_nonzero_exit() -> None:
    buf = io.StringIO()
    con = Console(file=buf, width=100, force_terminal=False, color_system=None)
    r = run_with_progress("false", console=con, timeout_s=5)
    assert r.returncode != 0
    print(f"  ok: non-zero exit propagated (rc={r.returncode})")


def test_run_with_progress_calls_on_line_hook() -> None:
    buf = io.StringIO()
    con = Console(file=buf, width=100, force_terminal=False, color_system=None)
    seen: list[str] = []
    r = run_with_progress(
        "echo hello; echo world",
        console=con,
        on_line=lambda ln: seen.append(ln.rstrip("\n")),
    )
    assert r.returncode == 0
    assert "hello" in seen
    assert "world" in seen
    print("  ok: on_line callback invoked per stdout line")


if __name__ == "__main__":
    print("F12.2 progress parser + live_progress unit tests")
    test_masscan_parser_percentage_and_rate()
    test_rustscan_parser_open_ports()
    test_amass_parser_found_count()
    test_parser_dispatch_by_command()
    test_format_progress_bar_with_percentage()
    test_run_with_progress_captures_stdout()
    test_run_with_progress_nonzero_exit()
    test_run_with_progress_calls_on_line_hook()
    print("\nALL PASS")
