"""Contract for the REPL smalltalk gate — greetings must not launch the agent."""

from __future__ import annotations

import pytest

from kryon.repl.smalltalk import is_smalltalk


@pytest.mark.parametrize(
    "text",
    [
        "hola",
        "Hola!",
        "hola kryon",
        "buenas",
        "buenos dias",
        "hey",
        "hi",
        "hello",
        "gracias",
        "muchas gracias",
        "ok",
        "dale",
        "listo",
        "  hola  ",
        "que tal",
    ],
)
def test_greetings_are_smalltalk(text: str) -> None:
    assert is_smalltalk(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "audita https://miapp.com",
        "escanea 10.0.0.5",
        "active sqli pentest contra http://localhost:3003",
        "qué CVEs aplican a nginx 1.18",
        "hola, audita example.com",  # greeting + real task → task wins
        "nmap 192.168.1.1",
        "revisa el compliance PCI de este segmento",
        "analiza este binario",
        "busca vulnerabilidades en target.com",
        "enumerá los usuarios del dominio",
    ],
)
def test_real_tasks_are_not_smalltalk(text: str) -> None:
    assert is_smalltalk(text) is False


def test_empty_is_not_smalltalk() -> None:
    assert is_smalltalk("") is False
    assert is_smalltalk("   ") is False


def test_long_non_greeting_is_not_smalltalk() -> None:
    # No greeting opener, no target, but a real question → let the agent handle.
    assert is_smalltalk("explicame como funciona el modo pasivo") is False
