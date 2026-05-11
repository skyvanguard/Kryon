"""TDD contract for kryon.repl.ui.theme — palette B (cybersec modern).

Theme module exposes:
  - Semantic constants (cyan + magenta accents, dims for context)
  - Severity colors (PCI/CIS-conventional, not configurable)
  - Helper builders that wrap text in the appropriate Rich tag
"""

from __future__ import annotations

import pytest

# ---------- Palette constants ----------


def test_palette_b_uses_cyan_and_magenta_accents() -> None:
    from kryon.repl.ui import theme

    # Two accents — primary (cyan) + secondary (magenta).
    assert "cyan" in theme.ACCENT_PRIMARY
    assert "magenta" in theme.ACCENT_SECONDARY


def test_palette_provides_text_normal_and_dim() -> None:
    from kryon.repl.ui import theme

    assert theme.TEXT_NORMAL  # non-empty
    assert "dim" in theme.TEXT_DIM


def test_palette_provides_status_ok_warn_err() -> None:
    from kryon.repl.ui import theme

    assert "green" in theme.STATUS_OK
    assert "yellow" in theme.STATUS_WARN
    assert "red" in theme.STATUS_ERR


# ---------- Severity colors are PCI/CIS-conventional ----------


def test_severity_critical_is_red() -> None:
    from kryon.repl.ui import theme

    assert "red" in theme.SEVERITY_CRITICAL


def test_severity_high_is_orange_or_red() -> None:
    """HIGH is conventionally orange/dark-red — never yellow (that's MEDIUM)."""
    from kryon.repl.ui import theme

    assert "orange" in theme.SEVERITY_HIGH or "red" in theme.SEVERITY_HIGH


def test_severity_medium_is_yellow() -> None:
    from kryon.repl.ui import theme

    assert "yellow" in theme.SEVERITY_MEDIUM


def test_severity_low_is_blue_or_cyan() -> None:
    from kryon.repl.ui import theme

    assert "blue" in theme.SEVERITY_LOW or "cyan" in theme.SEVERITY_LOW


def test_severity_pass_is_green() -> None:
    from kryon.repl.ui import theme

    assert "green" in theme.SEVERITY_PASS


def test_severity_na_is_dim() -> None:
    from kryon.repl.ui import theme

    assert "dim" in theme.SEVERITY_NA


# ---------- Helper builders ----------


def test_accent_wraps_text_with_primary_tag() -> None:
    from kryon.repl.ui.theme import accent

    out = accent("hello")
    assert out.startswith("[")
    assert out.endswith("[/]")
    assert "hello" in out


def test_dim_wraps_text() -> None:
    from kryon.repl.ui.theme import dim

    out = dim("context")
    assert "[dim" in out
    assert "context" in out
    assert "[/" in out


def test_ok_warn_err_distinct_styles() -> None:
    from kryon.repl.ui.theme import err, ok, warn

    a = ok("up")
    b = warn("hmm")
    c = err("down")
    # Three distinct strings
    assert a != b != c
    # All wrap the input text
    assert "up" in a and "hmm" in b and "down" in c


def test_severity_helper_for_known_level() -> None:
    from kryon.repl.ui.theme import severity

    out = severity("test", "CRITICAL")
    assert "test" in out
    # CRITICAL → red palette
    assert "red" in out


def test_severity_helper_falls_back_for_unknown_level() -> None:
    """Unknown severity strings get the dim treatment, not crash."""
    from kryon.repl.ui.theme import severity

    out = severity("test", "WHAT")
    assert "test" in out


def test_severity_helper_case_insensitive() -> None:
    from kryon.repl.ui.theme import severity

    a = severity("x", "critical")
    b = severity("x", "CRITICAL")
    assert a == b


# ---------- Composition guarantees ----------


def test_helpers_produce_strings_that_render_in_rich_console() -> None:
    """Smoke: build a styled string and ensure rich.Console.render
    doesn't raise on it. Catches mismatched [/] closures etc."""
    from io import StringIO

    from rich.console import Console

    from kryon.repl.ui.theme import accent, dim, err, ok, severity, warn

    buf = StringIO()
    c = Console(file=buf, force_terminal=False, width=120)
    line = " ".join(
        [
            accent("◆ skills:"),
            "fortigate-audit",
            dim("(14 tools)"),
            ok("ollama ✓"),
            warn("2 drafts"),
            err("1 failure"),
            severity("CRITICAL", "CRITICAL"),
        ]
    )
    c.print(line)
    text = buf.getvalue()
    # Rich strips tags when rendering to plain stream — just ensure
    # the words survive.
    assert "skills:" in text
    assert "ollama" in text
    assert "CRITICAL" in text
