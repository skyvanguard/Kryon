"""Kryon REPL theme — palette B (cybersec modern: cyan + magenta).

Centralizes the Rich color tags used across the REPL UI. Two layers:

  Chrome layer (cyan / magenta accents):
    - Status header, toolbar, banner, skill ticker, prompts, helpers.
    - These can change with future palette swaps.

  Severity layer (PCI/CIS-conventional):
    - CRITICAL → red, HIGH → orange, MEDIUM → yellow, LOW → blue,
      PASS → green, N/A → dim.
    - These DO NOT change with chrome palette — auditors expect them.

Usage:

    from kryon.repl.ui.theme import accent, ok, severity

    console.print(f"{accent('◆ skills:')} {skill_names}")
    console.print(f"  {ok('ollama')} healthy")
    console.print(severity("21 findings", "CRITICAL"))

Design notes:
  * Constants are Rich-tag *strings*, not Style objects. Easier to
    splice into f-strings; lower friction for the existing codebase
    that already uses inline tags.
  * Helpers wrap input text in `[<tag>]...[/]` (no closing-tag name
    required, Rich accepts the open-tag end form).
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Chrome palette (cyan + magenta — palette B "cybersec modern")
# ---------------------------------------------------------------------------

# Primary accent: section labels, prompt markers, "active" indicators.
ACCENT_PRIMARY = "bold cyan"

# Secondary accent: counters, badges, "needs attention" markers (drafts,
# experiences, alerts that aren't errors).
ACCENT_SECONDARY = "bold magenta"

# Soft accent for context lines that should NOT compete with primary.
ACCENT_DIM = "dim cyan"

# Default text color (override only when emphasizing).
TEXT_NORMAL = "white"

# Greyed-out text for timestamps, ids, "last X ago" hints.
TEXT_DIM = "dim"


# ---------------------------------------------------------------------------
# Status palette
# ---------------------------------------------------------------------------

STATUS_OK = "green"          # healthy / connected / passed
STATUS_WARN = "yellow"       # degraded / pending / soft warning
STATUS_ERR = "red"           # down / failed / hard error


# ---------------------------------------------------------------------------
# Severity palette (PCI-DSS / CIS / NIST convention — DO NOT customize)
# ---------------------------------------------------------------------------

SEVERITY_CRITICAL = "bold red"
SEVERITY_HIGH = "orange3"        # darker-than-yellow, lighter-than-red
SEVERITY_MEDIUM = "yellow"
SEVERITY_LOW = "blue"
SEVERITY_INFO = "cyan"
SEVERITY_PASS = "green"
SEVERITY_NA = "dim"


_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": SEVERITY_CRITICAL,
    "HIGH": SEVERITY_HIGH,
    "MEDIUM": SEVERITY_MEDIUM,
    "LOW": SEVERITY_LOW,
    "INFO": SEVERITY_INFO,
    "PASS": SEVERITY_PASS,
    "N/A": SEVERITY_NA,
    "NA": SEVERITY_NA,
}


# ---------------------------------------------------------------------------
# Helper builders — wrap text in the appropriate Rich tag
# ---------------------------------------------------------------------------


def accent(text: str) -> str:
    """Primary accent — section labels, prompt markers."""
    return f"[{ACCENT_PRIMARY}]{text}[/]"


def secondary(text: str) -> str:
    """Secondary accent — counters, badges, attention markers."""
    return f"[{ACCENT_SECONDARY}]{text}[/]"


def dim(text: str) -> str:
    """Soft / contextual text — timestamps, ids, hints."""
    return f"[{ACCENT_DIM}]{text}[/]"


def text(text_: str) -> str:
    """Plain emphasis (white) — for content that shouldn't compete."""
    return f"[{TEXT_NORMAL}]{text_}[/]"


def ok(text: str) -> str:
    """Healthy / passing status."""
    return f"[{STATUS_OK}]{text}[/]"


def warn(text: str) -> str:
    """Degraded / pending status."""
    return f"[{STATUS_WARN}]{text}[/]"


def err(text: str) -> str:
    """Failed / hard error status."""
    return f"[{STATUS_ERR}]{text}[/]"


def severity(text: str, level: str) -> str:
    """Wrap text in the severity color for `level`.

    Unknown levels degrade to dim instead of raising — keeps the UI
    rendering even if the agent emits a non-standard severity string.
    """
    style = _SEVERITY_MAP.get(level.upper(), TEXT_DIM)
    return f"[{style}]{text}[/]"
