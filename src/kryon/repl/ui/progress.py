"""
Progress bar parsers for long-running tool output.

Provides pluggable parsers that extract progress information from
tool stdout (nmap, hashcat, gobuster, etc.) and a generic fallback.
"""

import re
from dataclasses import dataclass, field


@dataclass
class ProgressState:
    """Current progress of a running tool."""

    total_lines: int = 0
    percentage: float | None = None
    current_step: str = ""
    tool_name: str = ""


class ProgressParser:
    """Base class for progress parsers."""

    name: str = "generic"
    patterns: list[str] = []

    @classmethod
    def matches_command(cls, command: str) -> bool:
        """Check if this parser handles the given command."""
        cmd_lower = command.lower()
        return any(p in cmd_lower for p in cls.patterns)

    def parse_line(self, line: str, state: ProgressState) -> ProgressState:
        """Parse a line of output and update state."""
        state.total_lines += 1
        return state


class NmapProgressParser(ProgressParser):
    """Parse nmap progress output."""

    name = "nmap"
    patterns = ["nmap"]

    _pct_re = re.compile(r"About\s+([\d.]+)%\s+done")
    _phase_re = re.compile(
        r"(Initiating|Completed|Scanning|NSE|Host discovery|"
        r"SYN Stealth Scan|Service detection|OS detection)"
    )

    def parse_line(self, line: str, state: ProgressState) -> ProgressState:
        state.total_lines += 1
        m = self._pct_re.search(line)
        if m:
            state.percentage = float(m.group(1))
        m2 = self._phase_re.search(line)
        if m2:
            state.current_step = m2.group(1)
        return state


class HashcatProgressParser(ProgressParser):
    """Parse hashcat progress output."""

    name = "hashcat"
    patterns = ["hashcat"]

    _progress_re = re.compile(r"Progress[.\s]*:\s*(\d+)/(\d+)")
    _status_re = re.compile(r"Status[.\s]*:\s*(\w+)")

    def parse_line(self, line: str, state: ProgressState) -> ProgressState:
        state.total_lines += 1
        m = self._progress_re.search(line)
        if m:
            current = int(m.group(1))
            total = int(m.group(2))
            if total > 0:
                state.percentage = (current / total) * 100
        m2 = self._status_re.search(line)
        if m2:
            state.current_step = m2.group(1)
        return state


class GobusterProgressParser(ProgressParser):
    """Parse gobuster/ffuf/feroxbuster progress output."""

    name = "gobuster"
    patterns = ["gobuster", "ffuf", "feroxbuster"]

    _progress_re = re.compile(r"Progress:\s*(\d+)\s*/\s*(\d+)")

    def parse_line(self, line: str, state: ProgressState) -> ProgressState:
        state.total_lines += 1
        m = self._progress_re.search(line)
        if m:
            current = int(m.group(1))
            total = int(m.group(2))
            if total > 0:
                state.percentage = (current / total) * 100
        return state


class GenericProgressParser(ProgressParser):
    """Fallback parser — counts lines, no percentage."""

    name = "generic"
    patterns = []

    @classmethod
    def matches_command(cls, command: str) -> bool:
        return True  # Always matches as fallback

    def parse_line(self, line: str, state: ProgressState) -> ProgressState:
        state.total_lines += 1
        return state


# Registry of parsers in priority order (specific first, generic last)
PROGRESS_PARSERS: list[type[ProgressParser]] = [
    NmapProgressParser,
    HashcatProgressParser,
    GobusterProgressParser,
    GenericProgressParser,
]

# Parser instance cache
_parser_cache: dict[str, ProgressParser] = {}


def get_parser_for_command(command: str) -> ProgressParser:
    """Return the appropriate progress parser for a command.

    Args:
        command: The command string being executed.

    Returns:
        A ProgressParser instance suitable for the command.
    """
    # Check cache first
    cmd_base = command.strip().split()[0] if command.strip() else ""
    if cmd_base in _parser_cache:
        return _parser_cache[cmd_base]

    for parser_cls in PROGRESS_PARSERS:
        if parser_cls.matches_command(command):
            parser = parser_cls()
            _parser_cache[cmd_base] = parser
            return parser

    # Should never reach here since GenericProgressParser always matches
    parser = GenericProgressParser()
    _parser_cache[cmd_base] = parser
    return parser


def format_progress_bar(state: ProgressState, width: int = 30) -> str:
    """Render a Unicode progress bar from a ProgressState.

    Args:
        state: Current progress state.
        width: Character width of the bar.

    Returns:
        Formatted progress string like:
        [████████████░░░░░░░░░░░░░░░░░░] 42.5% | Scanning | 847 lines
    """
    if state.percentage is not None:
        pct = max(0.0, min(100.0, state.percentage))
        filled = int(width * pct / 100)
        bar = "\u2588" * filled + "\u2591" * (width - filled)
        parts = [f"[{bar}] {pct:.1f}%"]
    else:
        parts = [f"[dim]{state.total_lines} lines processed[/dim]"]

    if state.current_step:
        parts.append(state.current_step)

    if state.percentage is not None:
        parts.append(f"{state.total_lines} lines")

    return " | ".join(parts)
