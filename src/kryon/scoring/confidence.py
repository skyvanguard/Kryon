"""F134 — Confidence scoring + cross-tool validation for findings.

Every finding emitted in an engagement carries a confidence score in
``[0.0, 1.0]`` plus a ``needs_verification`` flag. The score reflects
how much trust the report should put on the finding:

  - **1.0** — Emitted by a deterministic check (Phase 2 ``_check_http``,
    the compliance runner, the Phase 2b' device-family audits).
    Re-running gives the same result; no LLM hallucination risk.
  - **0.5 (base for LLM)** — Emitted by an LLM phase via
    ``_parse_agent_findings``. The LLM may have invented the rule_id
    or echoed a tool output it didn't actually run.
  - **0.85 (LLM + corroboration)** — An LLM finding whose ``rule_id``
    prefix or text overlaps with a deterministic finding gets a boost
    because there's independent evidence.

Findings with ``confidence < 0.7`` carry ``needs_verification=True``;
the reporting layer can render those in a separate "needs review"
section so the operator knows what to confirm before client handoff.

This module is intentionally pure: it consumes a list of finding-like
objects (anything with ``rule_id``, ``host``, ``message``, optionally
``confidence`` / ``needs_verification``) and returns a list of
``ConfidenceAnnotation`` records or mutates the inputs in place,
caller's choice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# F134 — Rule_id prefix → "this finding came from a deterministic
# emitter, not the LLM". Anything that starts with one of these is
# treated as ground truth (confidence=1.0). New deterministic emitters
# should be registered here.
DETERMINISTIC_RULE_PREFIXES: tuple[str, ...] = (
    # Engage Phase 2 _check_http / _check_ssh / _check_db
    "http-",
    "ssh-",
    "db-",
    "tls-",
    # F77/F85.E compliance runner
    "PCI-DSS-",
    "BCP-",
    "PVE-",
    "FGT-",
    "UNF-",
    "CIS-",
    "HIPAA-",
    "SOC2-",
    "NIST-",
    "ISO-",
    # F210 — native deterministic check families that were emitting as
    # "llm" here because this list drifted from finding_dedup._NATIVE_PREFIXES.
    # These are all reproducible on-box/remote checks, not model output.
    "MTK-",
    "IOS-",
    "PG-",
    "MYSQL-",
    "NGX-",
    "APACHE-",
    "HAP-",
    "LNX-",
    "ESX-",
    "KVM-",
    "HV-",
    "XEN-",
    "WIN-",
    "TOMCAT-",
    "VOIP-",
    "IIS-",
    "CADDY-",
    "SWIFT-",
    "ASTERISK-",
    # F100/F101/F102/F103/F104/F105/F106/F107 static analyzers
    "INFO-",
    "VJS-",
    "OR-",
    "SMG-",
    "DOM-",
    "CC-",
    # F87 API security
    "API-",
    "BOLA-",
    "GQL-",
    "JWT-",
    "CORS-",
    "FAPI-",
)

# Confidence thresholds.
_BASE_LLM_CONFIDENCE = 0.5
_BOOST_WITH_CORROBORATION = 0.85
_DETERMINISTIC_CONFIDENCE = 1.0
_VERIFICATION_THRESHOLD = 0.7

# F210 — deterministic ≠ infallible. A deterministic emitter (compliance
# check, pre_hook, version→CVE mapper) can still emit a false positive when
# its verdict is *inferred* rather than *directly probed*. Each finding may
# carry a ``verification_level`` describing how directly the condition was
# observed; this maps it to a confidence band. Anything below the
# verification threshold gets ``needs_verification=True`` and is routed to
# the report's "requiere verificación" section instead of the confirmed set.
# Missing/unknown level → "confirmed" (backwards compatible: every existing
# check keeps confidence 1.0).
_VERIFICATION_BANDS: dict[str, float] = {
    "confirmed": 1.0,
    "heuristic": 0.6,
    "inferred": 0.4,
}


def _verification_level(finding: Any) -> str:
    """Read a finding's ``verification_level``, defaulting to ``confirmed``
    for objects that don't carry the field (or carry an unknown value)."""
    val = str(getattr(finding, "verification_level", "") or "").strip().lower()
    return val if val in _VERIFICATION_BANDS else "confirmed"


@dataclass
class ConfidenceAnnotation:
    """Result of scoring one finding. Indexed by ``(rule_id, host)``."""

    rule_id: str
    host: str
    confidence: float
    needs_verification: bool
    source: str = "unknown"  # "deterministic" | "llm" | "llm_corroborated"
    reasoning: str = ""


def _is_deterministic(rule_id: str) -> bool:
    if not rule_id:
        return False
    rule_lower = rule_id.lower()
    rule_upper = rule_id.upper()
    for prefix in DETERMINISTIC_RULE_PREFIXES:
        if prefix.isupper():
            if rule_upper.startswith(prefix):
                return True
        else:
            if rule_lower.startswith(prefix.lower()):
                return True
    return False


def _normalised_text(finding: Any) -> str:
    parts: list[str] = []
    for attr in ("message", "title", "description", "evidence"):
        val = getattr(finding, attr, "")
        if val:
            parts.append(str(val))
    return " ".join(parts).lower()


def _share_significant_words(text_a: str, text_b: str, *, min_overlap: int = 2) -> bool:
    """Cheap textual corroboration: do the two finding bodies share at
    least ``min_overlap`` words longer than 4 characters? Stopword-free
    because rule_id prefixes already catch the structured signal."""
    if not text_a or not text_b:
        return False
    words_a = {w for w in text_a.split() if len(w) > 4}
    words_b = {w for w in text_b.split() if len(w) > 4}
    return len(words_a & words_b) >= min_overlap


def _rule_prefix(rule_id: str) -> str:
    """Pull the leading alphabetic prefix from a rule_id so
    ``http-plaintext`` and ``http-server-token`` count as the same
    family for corroboration purposes."""
    if not rule_id:
        return ""
    s = rule_id.split("-")[0] if "-" in rule_id else rule_id
    return s.lower()


def compute_confidence(findings: list[Any]) -> list[ConfidenceAnnotation]:
    """Score every finding. Pure: returns ``ConfidenceAnnotation`` list
    in the same order as input.

    Algorithm:
        1. Tag each finding as deterministic / llm by ``rule_id`` prefix.
        2. Deterministic findings get confidence 1.0.
        3. LLM findings: base 0.5. Then check for corroboration:
           - rule_id prefix matches a deterministic finding for the
             same host → boost to 0.85.
           - text overlap (≥2 words >4 chars) with any deterministic
             finding for the same host → boost to 0.7.
        4. ``needs_verification = confidence < 0.7``.
    """
    annotations: list[ConfidenceAnnotation] = []
    if not findings:
        return annotations

    # Build a deterministic lookup: (host, rule_prefix) and per-host text bag.
    det_prefixes: set[tuple[str, str]] = set()
    det_text_by_host: dict[str, str] = {}
    for f in findings:
        rule_id = str(getattr(f, "rule_id", "") or "")
        host = str(getattr(f, "host", "") or "")
        if _is_deterministic(rule_id):
            det_prefixes.add((host, _rule_prefix(rule_id)))
            det_text_by_host[host] = det_text_by_host.get(host, "") + " " + _normalised_text(f)

    for f in findings:
        rule_id = str(getattr(f, "rule_id", "") or "")
        host = str(getattr(f, "host", "") or "")

        # 1. Base score from emitter class (deterministic vs LLM ± corroboration).
        if _is_deterministic(rule_id):
            confidence = _DETERMINISTIC_CONFIDENCE
            source = "deterministic"
            reasons = ["rule_id prefix matches a deterministic emitter"]
        else:
            confidence = _BASE_LLM_CONFIDENCE
            source = "llm"
            reasons = []
            prefix = _rule_prefix(rule_id)
            if prefix and (host, prefix) in det_prefixes:
                confidence = _BOOST_WITH_CORROBORATION
                source = "llm_corroborated"
                reasons.append(f"prefix '{prefix}' overlaps a deterministic finding on same host")
            elif det_text_by_host.get(host) and _share_significant_words(_normalised_text(f), det_text_by_host[host]):
                confidence = max(confidence, 0.7)
                source = "llm_corroborated"
                reasons.append("text overlap with deterministic finding on same host")
            else:
                reasons.append("no deterministic corroboration — needs verification")

        # 2. F210 — apply the verification_level cap. An explicit
        # ``heuristic``/``inferred`` self-declaration can only LOWER the
        # score (a banner-inferred CVE is never ground truth even if its
        # rule_id looks deterministic). ``confirmed`` (the default) is a
        # no-op, so LLM findings keep their base score.
        level = _verification_level(f)
        band = _VERIFICATION_BANDS[level]
        if band < confidence:
            confidence = band
            source = f"{source}_{level}" if not source.endswith(level) else source
            reasons.append(f"verification_level={level} — not directly probed, capped at {band}")

        annotations.append(
            ConfidenceAnnotation(
                rule_id=rule_id,
                host=host,
                confidence=confidence,
                needs_verification=confidence < _VERIFICATION_THRESHOLD,
                source=source,
                reasoning="; ".join(reasons),
            )
        )

    return annotations


def annotate_confidence(findings: list[Any]) -> None:
    """Convenience: mutate each finding in place with ``confidence``
    and ``needs_verification`` attributes set by ``compute_confidence``.
    No-op if the finding object doesn't accept attribute assignment.
    """
    annotations = compute_confidence(findings)
    for finding, ann in zip(findings, annotations, strict=False):
        try:
            finding.confidence = ann.confidence
            finding.needs_verification = ann.needs_verification
        except (AttributeError, TypeError):
            continue
