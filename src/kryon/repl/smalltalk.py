"""Smalltalk / greeting gate for the REPL.

A bare "hola" must NOT launch the autonomous agent — the small local model,
given no target, invents a placeholder host ("https://HOST") and loops recon
tools against it until the stuck-detector aborts. This gate catches clear
greetings / acknowledgements and answers conversationally, waiting for a real
task instead.

Deliberately conservative: anything that looks like a target (URL / IP / host)
or carries a task verb (audit / scan / pentest / …) is NOT smalltalk and flows
through to the agent untouched. False negatives (a greeting slips through) are
tolerable; false positives (a real task treated as smalltalk) are not.
"""

from __future__ import annotations

import re

# A target reference — URL, bare IPv4, or a dotted hostname. Its presence means
# the user is pointing at something, so it's a task, not smalltalk.
_TARGET_HINT = re.compile(
    r"https?://|www\.|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9-]+\.[a-z]{2,}\b",
    re.IGNORECASE,
)

# Task intent verbs (es/en). Presence → route to the agent.
_TASK_VERB = re.compile(
    r"\b(audit\w*|audita\w*|scan\w*|escane\w*|pentest\w*|exploit\w*|enumera\w*|"
    r"recon\w*|analiz\w*|hack\w*|busc\w*|find|nmap|nuclei|sqli|xss|cve|vuln\w*|"
    r"compliance|informe|report\w*|revis\w*|check|target|objetivo)\b",
    re.IGNORECASE,
)

# Pure greetings / acknowledgements (normalized, punctuation stripped).
_GREETINGS = {
    "hola",
    "holas",
    "holis",
    "ola",
    "buenas",
    "buenos dias",
    "buenas tardes",
    "buenas noches",
    "que tal",
    "qué tal",
    "como estas",
    "cómo estás",
    "como va",
    "que hace",
    "saludos",
    "hey",
    "hey kryon",
    "hola kryon",
    "hi",
    "hello",
    "yo",
    "gracias",
    "muchas gracias",
    "thanks",
    "thank you",
    "ok",
    "oka",
    "okay",
    "dale",
    "listo",
    "perfecto",
    "genial",
    "buenas kryon",
}

# First-word triggers that, in a short message, count as a greeting opener.
_OPENERS = {"hola", "hey", "hi", "hello", "buenas", "gracias", "ola", "saludos", "holis"}


def is_smalltalk(text: str) -> bool:
    """True for clear greetings / acknowledgements with no target or task."""
    t = (text or "").strip().lower()
    if not t:
        return False
    if _TARGET_HINT.search(t) or _TASK_VERB.search(t):
        return False
    core = t.strip(" \t!?.¡¿,;:")
    if core in _GREETINGS:
        return True
    words = core.split()
    return len(words) <= 3 and bool(words) and words[0] in _OPENERS


def print_smalltalk_reply(console) -> None:
    """Answer a greeting on-brand, nudging toward a real task."""
    console.print(
        "[bold #45e0ef]◆ Kryon en línea.[/] [#5f8bb0]Decime un objetivo — una URL, IP o host — o qué querés auditar.[/]"
    )
    console.print(
        '  [dim #45e0ef]ej:[/] [dim]"audita https://miapp.com"  ·  '
        '"active sqli pentest contra http://localhost:3003"  ·  /help[/]'
    )
