"""
Intent-shift detector — decides when `recall_similar_experiences` should
fire mid-engagement.

Fix R5 from ZERO_DAY_ROADMAP. In the baseline session (britimp.com.py),
the learning loop only recalled at turn 1. When the user pivoted
("quiero ver si /uploads se puede explotar", "hay otro vector?"),
recall never fired again — the model lost access to relevant prior
engagements for the new sub-objective.

No LLM calls. Pure regex + simple lexical diff against the last
user prompt.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Verbs/keywords that signal a clear attack objective — changing these
# mid-session almost always means a new retrieval would help.
_ATTACK_VERBS = {
    "exploit",
    "explotar",
    "bypass",
    "bypassear",
    "escalate",
    "escalar",
    "pivot",
    "pivotear",
    "dump",
    "extract",
    "extraer",
    "read",
    "leer",
    "upload",
    "subir",
    "inject",
    "inyectar",
    "brute",
    "crack",
    "crackear",
    "fuzz",
    "enumerate",
    "enumerar",
    "audit",
    "auditar",
    "hardening",
    "forensic",
    "forense",
    "triage",
    "deobfuscate",
    "deobfuscar",
    "exfil",
    "persist",
    "persistir",
}

# Attack-surface / vector nouns. Switching between these is an intent shift.
_VECTOR_NOUNS = {
    "sql",
    "sqli",
    "xss",
    "ssrf",
    "rce",
    "lfi",
    "rfi",
    "xxe",
    "ssti",
    "idor",
    "csrf",
    "deserialization",
    "deserializacion",
    "auth",
    "login",
    "jwt",
    "oauth",
    "session",
    "cookie",
    "upload",
    "uploads",
    "file",
    "directory",
    "path",
    "api",
    "graphql",
    "rest",
    "ssh",
    "ftp",
    "smb",
    "rdp",
    "ldap",
    "kerberos",
    "wordpress",
    "joomla",
    "drupal",
    "docker",
    "kubernetes",
    "k8s",
    "aws",
    "azure",
    "gcp",
    "windows",
    "ad",
    "active directory",
    "memory",
    "heap",
    "stack",
    "overflow",
    "crypto",
    "tls",
    "ssl",
    "certificate",
}

# Verbs / phrases that are NOT real shifts — continuation, not pivot.
_CONTINUATION_MARKERS = {
    "continua",
    "continue",
    "sigue",
    "keep going",
    "avanza",
    "proceed",
    "ok",
    "dale",
    "vale",
    "perfecto",
}

# Things that look like targets (host, URL, path)
_TARGET_RE = re.compile(
    r"(?:https?://)?([a-z0-9][a-z0-9.\-]*\.[a-z]{2,}(?:/\S*)?)|"
    r"(/[A-Za-z0-9._\-/]+)",
    re.I,
)


@dataclass
class IntentSignature:
    """Lexical fingerprint of a user prompt's intent."""

    verbs: set[str] = field(default_factory=set)
    vectors: set[str] = field(default_factory=set)
    targets: set[str] = field(default_factory=set)
    raw: str = ""

    def is_continuation(self) -> bool:
        """Pure-continuation prompts (like 'continua') don't change intent."""
        if not self.verbs and not self.vectors and not self.targets:
            low = self.raw.strip().lower()
            return any(m in low for m in _CONTINUATION_MARKERS)
        return False


class IntentShiftDetector:
    """Tracks consecutive user prompts and flags objective changes."""

    def __init__(self) -> None:
        self._last: IntentSignature | None = None
        self._recall_fired_count = 0

    def extract(self, text: str) -> IntentSignature:
        low = text.lower()
        verbs = {v for v in _ATTACK_VERBS if _word_in(v, low)}
        vectors = {n for n in _VECTOR_NOUNS if _word_in(n, low)}
        targets: set[str] = set()
        for m in _TARGET_RE.finditer(text):
            t = m.group(1) or m.group(2) or ""
            t = t.strip(".,;:)(!?").lower()
            if t and len(t) > 2:
                targets.add(t)
        return IntentSignature(verbs=verbs, vectors=vectors, targets=targets, raw=text)

    def should_recall(self, user_msg: str) -> tuple[bool, str]:
        """Return (fire_recall, reason). reason empty if no shift."""
        sig = self.extract(user_msg)

        # First turn — always recall
        if self._last is None:
            self._last = sig
            self._recall_fired_count += 1
            return True, "first-turn recall"

        # Pure continuation — skip
        if sig.is_continuation():
            return False, "continuation prompt"

        # Compute deltas
        new_verbs = sig.verbs - self._last.verbs
        new_vectors = sig.vectors - self._last.vectors
        new_targets = sig.targets - self._last.targets

        shifted = bool(new_verbs or new_vectors or new_targets)

        if shifted:
            reasons: list[str] = []
            if new_verbs:
                reasons.append(f"new verbs: {sorted(new_verbs)}")
            if new_vectors:
                reasons.append(f"new vectors: {sorted(new_vectors)}")
            if new_targets:
                reasons.append(f"new targets: {sorted(new_targets)}")
            self._last = sig
            self._recall_fired_count += 1
            return True, "; ".join(reasons)

        self._last = sig
        return False, "no shift"

    def recall_count(self) -> int:
        return self._recall_fired_count

    def reset(self) -> None:
        self._last = None
        self._recall_fired_count = 0


def _word_in(term: str, text: str) -> bool:
    """True if term appears as a standalone token (not a substring match)."""
    # For multi-word terms allow phrase match; for single words require boundaries.
    if " " in term:
        return term in text
    return re.search(rf"\b{re.escape(term)}\b", text) is not None


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: IntentShiftDetector | None = None


def get_intent_detector() -> IntentShiftDetector:
    global _instance
    if _instance is None:
        _instance = IntentShiftDetector()
    return _instance


def reset_intent_detector() -> None:
    global _instance
    _instance = IntentShiftDetector()
