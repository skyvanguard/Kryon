"""Tests for progress bar parsers."""

import pytest

from kryon.repl.ui.progress import (
    GenericProgressParser,
    GobusterProgressParser,
    HashcatProgressParser,
    NmapProgressParser,
    ProgressState,
    format_progress_bar,
    get_parser_for_command,
)


class TestNmapProgressParser:
    def test_parses_percentage(self):
        parser = NmapProgressParser()
        state = ProgressState()
        state = parser.parse_line("About 45.50% done; ETC: 12:34", state)
        assert state.percentage == pytest.approx(45.5)
        assert state.total_lines == 1

    def test_parses_phase(self):
        parser = NmapProgressParser()
        state = ProgressState()
        state = parser.parse_line("Initiating SYN Stealth Scan at 12:00", state)
        assert state.current_step == "Initiating"

    def test_parses_nse_phase(self):
        parser = NmapProgressParser()
        state = ProgressState()
        state = parser.parse_line("NSE: Starting runlevel 1", state)
        assert state.current_step == "NSE"


class TestHashcatProgressParser:
    def test_parses_progress(self):
        parser = HashcatProgressParser()
        state = ProgressState()
        state = parser.parse_line("Progress.........: 1024/4096 (25.00%)", state)
        assert state.percentage == pytest.approx(25.0)

    def test_parses_status(self):
        parser = HashcatProgressParser()
        state = ProgressState()
        state = parser.parse_line("Status...........: Running", state)
        assert state.current_step == "Running"


class TestGobusterProgressParser:
    def test_parses_progress(self):
        parser = GobusterProgressParser()
        state = ProgressState()
        state = parser.parse_line("Progress: 500 / 2000 (25.00%)", state)
        assert state.percentage == pytest.approx(25.0)

    def test_no_match(self):
        parser = GobusterProgressParser()
        state = ProgressState()
        state = parser.parse_line("/admin (Status: 200)", state)
        assert state.percentage is None
        assert state.total_lines == 1


class TestGenericProgressParser:
    def test_counts_lines(self):
        parser = GenericProgressParser()
        state = ProgressState()
        for _ in range(5):
            state = parser.parse_line("some output", state)
        assert state.total_lines == 5
        assert state.percentage is None


class TestGetParserForCommand:
    def test_nmap(self):
        parser = get_parser_for_command("nmap -sV 10.0.0.1")
        assert isinstance(parser, NmapProgressParser)

    def test_hashcat(self):
        parser = get_parser_for_command("hashcat -m 0 hash.txt wordlist.txt")
        assert isinstance(parser, HashcatProgressParser)

    def test_gobuster(self):
        parser = get_parser_for_command("gobuster dir -u http://target -w wordlist")
        assert isinstance(parser, GobusterProgressParser)

    def test_ffuf(self):
        parser = get_parser_for_command("ffuf -u http://target/FUZZ -w wordlist")
        assert isinstance(parser, GobusterProgressParser)

    def test_feroxbuster(self):
        parser = get_parser_for_command("feroxbuster -u http://target")
        assert isinstance(parser, GobusterProgressParser)

    def test_unknown_returns_generic(self):
        parser = get_parser_for_command("ls -la")
        assert isinstance(parser, GenericProgressParser)

    def test_empty_command(self):
        parser = get_parser_for_command("")
        assert isinstance(parser, GenericProgressParser)


class TestFormatProgressBar:
    def test_with_percentage(self):
        state = ProgressState(total_lines=100, percentage=50.0, current_step="Scanning")
        bar = format_progress_bar(state, width=20)
        assert "50.0%" in bar
        assert "Scanning" in bar
        assert "100 lines" in bar

    def test_without_percentage(self):
        state = ProgressState(total_lines=42)
        bar = format_progress_bar(state, width=20)
        assert "42 lines processed" in bar

    def test_zero_percentage(self):
        state = ProgressState(percentage=0.0, total_lines=0)
        bar = format_progress_bar(state, width=10)
        assert "0.0%" in bar
