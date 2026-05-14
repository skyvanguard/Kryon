"""F119 — Sensitive-data redactor (PCI-DSS 3.3 baseline).

Single entry point ``redact_sensitive(text)`` returns a
``RedactionResult`` with the masked text and per-category counts so
the caller can log how many sensitive elements were stripped (without
seeing what they were).

Detected categories (banca-safe defaults, all on unless env disables):

  - ``pan``    : 13-19 digit sequences passing the Luhn check. Cards
                 detected with or without space/dash separators.
  - ``cvv``    : 3-4 digit numbers in CVV-tagged context. We only
                 redact CVV when it sits near the keyword ``cvv``,
                 ``cvc`` or ``code`` so we don't shred random small
                 integers.
  - ``track``  : magnetic stripe Track 2 dumps (``;PAN=YYMM...?``).
  - ``py_ci``  : Paraguayan cédula de identidad (1.234.567-X or bare
                 6-8 digit sequences in a CI context).
  - ``py_ruc`` : Paraguayan RUC (``d-ddddddd-d``).
  - ``iban``   : IBAN (any country, length 15-34).

The function is pure — no logging, no I/O, no global state. The env
toggle ``KRYON_REDACT_PAN`` lets tests force passthrough.

PAN handling notes
------------------
We refuse to redact a 16-digit run unless it passes Luhn. This keeps
the function from clobbering log IDs, hashes, IPv6 (which has its own
shape), and timestamps. The downside is that an obfuscated PAN (e.g.
``42424242 42424242``) won't trip detection — but obfuscated PANs are
also out of scope for PCI-DSS 3.3, which targets cleartext storage.

Mask styles
-----------
``mask_style='full'`` (default) replaces the whole match with the
category placeholder ``[PAN-REDACTED]``. ``mask_style='last4'`` keeps
the trailing 4 digits visible (``************4242``), the disclosure
permitted by PCI-DSS 3.3 for display purposes.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Luhn check
# ---------------------------------------------------------------------------


def is_luhn_valid(digits: str) -> bool:
    """Return True iff ``digits`` is a numeric string of length 12-19
    passing the Luhn mod-10 check used by PAN issuers. Sequences with
    all identical digits (``0000...``, ``1111...``) are rejected even
    when they happen to pass Luhn arithmetically — no real issuer
    emits those and treating them as PANs hits log IDs and pad-bytes."""
    if not digits or not digits.isdigit():
        return False
    n = len(digits)
    if n < 12 or n > 19:
        return False
    # Reject homogeneous-digit sequences (Luhn-valid for all-zero etc).
    if len(set(digits)) == 1:
        return False
    total = 0
    # Process from the rightmost digit. Double every second digit.
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------


# 13-19 digit sequences, optionally split into groups of 3-6 by spaces
# or dashes. The regex is intentionally loose — we run Luhn on every
# candidate to filter false positives.
_PAN_CANDIDATE_RE = re.compile(r"(?<!\d)(\d{4}[\s\-]?\d{4}[\s\-]?\d{2,6}(?:[\s\-]?\d{1,5})?)(?!\d)")

# Track 2: ;PAN=...? (also ';PAN=YYMMservice...?')
_TRACK2_RE = re.compile(r";\d{13,19}=[\d?]+", re.IGNORECASE)

# CVV in CVV-context: cvv 123, cvc=123, code 1234
_CVV_RE = re.compile(r"\b(cvv|cvc|cvc2|cv2|code)\b\s*[:=]?\s*(\d{3,4})\b", re.IGNORECASE)

# Paraguayan cédula: 1.234.567-8 or 1234567 in CI context.
# Strict form ddd.ddd-d covers most. Bare 6-8 digit form requires the
# token "cedula"/"ci" nearby (handled at function level).
_PY_CI_DOTTED_RE = re.compile(r"\b\d{1,3}\.\d{3}\.\d{3}-\d\b")
_PY_CI_BARE_RE = re.compile(r"(?<!\d)(\d{6,8})(?!\d)")

# RUC: 8 digits + check digit, written d-ddddddd-d
_PY_RUC_RE = re.compile(r"\b\d{1,2}-?\d{5,7}-\d\b")

# IBAN: ISO 3166-1 alpha-2 + 2 check digits + 11-30 alphanumeric.
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

_PLACEHOLDERS = {
    "pan": "[PAN-REDACTED]",
    "cvv": "[CVV-REDACTED]",
    "track": "[TRACK-REDACTED]",
    "py_ci": "[PY-CI-REDACTED]",
    "py_ruc": "[PY-RUC-REDACTED]",
    "iban": "[IBAN-REDACTED]",
}


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class RedactionResult:
    """Outcome of a single redaction pass. ``counts`` is keyed by
    category (pan/cvv/track/py_ci/py_ruc/iban)."""

    text: str
    counts: dict[str, int] = field(default_factory=dict)

    def total(self) -> int:
        return sum(self.counts.values())


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def _is_disabled() -> bool:
    return os.environ.get("KRYON_REDACT_PAN", "true").strip().lower() in {"0", "false", "no", "off"}


def _mask_pan(pan_digits: str, original_match: str, mask_style: str) -> str:
    if mask_style == "last4":
        last4 = pan_digits[-4:]
        return f"************{last4}"
    return _PLACEHOLDERS["pan"]


def redact_sensitive(text: str | None, *, mask_style: str = "full") -> RedactionResult:
    """Redact sensitive elements in ``text``. Pure function.

    Args:
        text:        the input string. ``None`` is treated as empty.
        mask_style:  ``"full"`` (default) replaces with category
                     placeholder; ``"last4"`` keeps the last 4 PAN
                     digits visible (PCI-DSS 3.3 allowance).

    Returns:
        ``RedactionResult`` with masked ``text`` and per-category
        ``counts`` so callers can log how many items were stripped.
    """
    if not text:
        return RedactionResult(text="")

    if _is_disabled():
        return RedactionResult(text=text, counts={})

    counts: dict[str, int] = {}
    result = text

    # 1) Track 2 first — they contain a PAN that the PAN pass would also
    # catch, but we want a single 'track' replacement instead of a stray
    # ';' + '[PAN-REDACTED]' + '=...?' artefact.
    def _track_sub(match: re.Match[str]) -> str:
        counts["track"] = counts.get("track", 0) + 1
        return _PLACEHOLDERS["track"]

    result = _TRACK2_RE.sub(_track_sub, result)

    # 2) PAN candidates: Luhn-filter every match.
    def _pan_sub(match: re.Match[str]) -> str:
        raw = match.group(1)
        digits = re.sub(r"[\s\-]", "", raw)
        if not is_luhn_valid(digits):
            return raw
        counts["pan"] = counts.get("pan", 0) + 1
        return _mask_pan(digits, raw, mask_style)

    result = _PAN_CANDIDATE_RE.sub(_pan_sub, result)

    # 3) CVV in CVV-context. Keep the keyword, redact the digits.
    def _cvv_sub(match: re.Match[str]) -> str:
        keyword = match.group(1)
        counts["cvv"] = counts.get("cvv", 0) + 1
        return f"{keyword} {_PLACEHOLDERS['cvv']}"

    result = _CVV_RE.sub(_cvv_sub, result)

    # 4) IBAN before PY CI to avoid digit-stretches inside the IBAN
    #    being mis-classified as a bare cédula.
    def _iban_sub(match: re.Match[str]) -> str:
        counts["iban"] = counts.get("iban", 0) + 1
        return _PLACEHOLDERS["iban"]

    result = _IBAN_RE.sub(_iban_sub, result)

    # 5) RUC before bare CI to avoid the d-ddddddd-d run being matched
    #    as two bare CIs.
    def _ruc_sub(match: re.Match[str]) -> str:
        counts["py_ruc"] = counts.get("py_ruc", 0) + 1
        return _PLACEHOLDERS["py_ruc"]

    result = _PY_RUC_RE.sub(_ruc_sub, result)

    # 6) PY CI dotted form (unambiguous).
    def _ci_dotted_sub(match: re.Match[str]) -> str:
        counts["py_ci"] = counts.get("py_ci", 0) + 1
        return _PLACEHOLDERS["py_ci"]

    result = _PY_CI_DOTTED_RE.sub(_ci_dotted_sub, result)

    # 7) Bare CI — only when the token "ci" or "cedula" sits before the
    #    digit run. Otherwise a 6-8 digit number is too ambiguous to
    #    redact safely (port numbers, build IDs, etc).
    ci_context_re = re.compile(r"\b(cedula|cédula|c[ií]|ci)[\s:=]+(\d{6,8})\b", re.IGNORECASE)

    def _ci_context_sub(match: re.Match[str]) -> str:
        keyword = match.group(1)
        counts["py_ci"] = counts.get("py_ci", 0) + 1
        return f"{keyword} {_PLACEHOLDERS['py_ci']}"

    result = ci_context_re.sub(_ci_context_sub, result)

    return RedactionResult(text=result, counts=counts)
