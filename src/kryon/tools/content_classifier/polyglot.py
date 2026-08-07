"""F116 — Polyglot detection.

Detects files that present as MULTIPLE format types simultaneously.
Classic bypass: serve a JPEG with embedded PHP. The file is a valid
JPEG (passes type-strict upload filters) AND executes as PHP when
the path is requested with `.php` extension or via a misconfigured
handler.

Heuristic: scan for known magic-byte signatures + known textual
markers anywhere in the body. If more than one DISTINCT format is
present, flag as polyglot."""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "PolyglotIndicator",
    "detect_polyglot",
]


@dataclass(frozen=True)
class PolyglotIndicator:
    signature: str  # short label
    offset: int


# (signature_label, magic-bytes-prefix-OR-pattern, kind)
# kind: "binary-magic" or "text-pattern"
_SIGNATURES: tuple[tuple[str, bytes, str], ...] = (
    # Binary magic bytes (matched at offset 0 OR later in file)
    ("jpeg", b"\xff\xd8\xff", "binary-magic"),
    ("png", b"\x89PNG\r\n\x1a\n", "binary-magic"),
    ("gif87", b"GIF87a", "binary-magic"),
    ("gif89", b"GIF89a", "binary-magic"),
    ("zip", b"PK\x03\x04", "binary-magic"),
    ("pdf", b"%PDF-", "binary-magic"),
    ("elf", b"\x7fELF", "binary-magic"),
    ("pe", b"MZ", "binary-magic"),
    ("class-file", b"\xca\xfe\xba\xbe", "binary-magic"),
    ("gzip", b"\x1f\x8b", "binary-magic"),
    ("wasm", b"\x00asm", "binary-magic"),
    ("rtf", b"{\\rtf", "binary-magic"),
)


# Text-based markers (scanned via regex)
_TEXT_MARKERS: tuple[tuple[str, re.Pattern], ...] = (
    ("php-open-tag", re.compile(rb"<\?(?:php|=)", re.IGNORECASE)),
    ("jsp-scriptlet", re.compile(rb"<%[!@=]?[\s\S]{0,200}%>")),
    ("asp-scriptlet", re.compile(rb"<%[\s\S]{0,200}%>")),
    ("html-doctype", re.compile(rb"(?i)<!DOCTYPE\s+html")),
    ("xml-decl", re.compile(rb"<\?xml\s")),
    ("js-script", re.compile(rb"(?i)<script[\s>]")),
    ("python-marker", re.compile(rb"^#!.*python", re.MULTILINE)),
    ("shell-shebang", re.compile(rb"^#!/.*?/(?:sh|bash|zsh|dash)", re.MULTILINE)),
    ("perl-shebang", re.compile(rb"^#!.*perl", re.MULTILINE)),
)


# Map signatures to FORMAT FAMILIES — two signatures of the same
# family don't count as polyglot.
_FAMILY: dict[str, str] = {
    "jpeg": "image",
    "png": "image",
    "gif87": "image",
    "gif89": "image",
    "zip": "archive",
    "gzip": "archive",
    "pdf": "document",
    "rtf": "document",
    "elf": "executable",
    "pe": "executable",
    "class-file": "executable",
    "wasm": "executable",
    "php-open-tag": "script",
    "jsp-scriptlet": "script",
    "asp-scriptlet": "script",
    "python-marker": "script",
    "shell-shebang": "script",
    "perl-shebang": "script",
    "js-script": "script",
    "html-doctype": "markup",
    "xml-decl": "markup",
}


# Sample window for scanning — capped to avoid catastrophic cost
_SCAN_WINDOW = 256_000


def detect_polyglot(content: bytes) -> tuple[PolyglotIndicator, ...]:
    """Return all detected signatures. The caller decides if more
    than one DISTINCT FAMILY constitutes a polyglot."""
    if not content:
        return ()
    window = content[:_SCAN_WINDOW]
    out: list[PolyglotIndicator] = []
    seen_signatures: set[str] = set()
    # Binary magic bytes — search anywhere
    for label, magic, _kind in _SIGNATURES:
        idx = window.find(magic)
        if idx != -1 and label not in seen_signatures:
            seen_signatures.add(label)
            out.append(PolyglotIndicator(signature=label, offset=idx))
    # Text-pattern markers
    for label, pat in _TEXT_MARKERS:
        m = pat.search(window)
        if m and label not in seen_signatures:
            seen_signatures.add(label)
            out.append(PolyglotIndicator(signature=label, offset=m.start()))
    return tuple(out)


def is_polyglot(indicators: tuple[PolyglotIndicator, ...]) -> bool:
    """True if ≥ 2 DIFFERENT format families are present."""
    families = {_FAMILY.get(i.signature, "") for i in indicators if _FAMILY.get(i.signature)}
    return len(families) >= 2
