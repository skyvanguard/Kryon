"""F116 — Main Content Classifier.

Composes magika delegation + disguise + secrets + polyglot + threat
scoring into a single ContentClassification per body.

Soft-fails when Magika is unavailable: degrades to magic-byte
heuristic classification (less accurate but still emits findings)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from kryon.tools.content_classifier.disguise import (
    DisguiseAssessment,
    detect_disguise,
)
from kryon.tools.content_classifier.polyglot import (
    PolyglotIndicator,
    detect_polyglot,
    is_polyglot,
)
from kryon.tools.content_classifier.secrets import (
    EmbeddedSecret,
    scan_for_secrets,
    shannon_entropy,
)
from kryon.tools.content_classifier.threat_scorer import (
    ThreatScoreResult,
    score_threat,
)

__all__ = [
    "ALL_CC_RULES",
    "ContentClassification",
    "ContentClassifier",
    "ContentInput",
    "ContentFinding",
    "classify_content",
    "is_magika_available",
]


ALL_CC_RULES: frozenset[str] = frozenset(
    {"CC-001", "CC-002", "CC-003", "CC-004", "CC-005", "CC-006", "CC-007", "CC-008"}
)


@dataclass(frozen=True)
class ContentInput:
    """Operator-supplied input to the classifier."""

    content: bytes
    source_url: str = ""
    content_type_header: str = ""
    content_length: int = 0  # informational; if 0, len(content) used


@dataclass(frozen=True)
class ContentFinding:
    """One actionable finding from content classification."""

    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    source_url: str = ""
    extra: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ContentClassification:
    magika_label: str = ""
    magika_available: bool = False
    heuristic_label: str = ""  # used when magika unavailable
    disguise: DisguiseAssessment = field(default_factory=DisguiseAssessment)
    polyglot_indicators: tuple[PolyglotIndicator, ...] = ()
    polyglot: bool = False
    embedded_secrets: tuple[EmbeddedSecret, ...] = ()
    threat: ThreatScoreResult = field(
        default_factory=lambda: ThreatScoreResult(score=0, factors=())
    )
    content_sha256: str = ""
    content_entropy: float = 0.0
    content_length: int = 0
    findings: tuple[ContentFinding, ...] = ()


# ---- Magika availability + invocation -------------------------------------


_MAGIKA_INSTANCE = None


def is_magika_available() -> bool:
    try:
        import magika  # noqa: F401
        return True
    except Exception:
        return False


def _magika_classify(content: bytes) -> str:
    global _MAGIKA_INSTANCE
    try:
        if _MAGIKA_INSTANCE is None:
            from magika import Magika  # type: ignore
            _MAGIKA_INSTANCE = Magika()
        result = _MAGIKA_INSTANCE.identify_bytes(content)
        # Magika API: result.output.label
        label = getattr(getattr(result, "output", None), "label", "")
        return str(label or "")
    except Exception:
        return ""


# ---- Heuristic fallback ----------------------------------------------------


_HEURISTIC_MAGIC: tuple[tuple[str, bytes], ...] = (
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("gif", b"GIF8"),
    ("pdf", b"%PDF-"),
    ("zip", b"PK\x03\x04"),
    ("elf", b"\x7fELF"),
    ("pe", b"MZ"),
    ("class-file", b"\xca\xfe\xba\xbe"),
    ("gzip", b"\x1f\x8b"),
    ("wasm", b"\x00asm"),
)


def _heuristic_label(content: bytes, content_type_header: str = "") -> str:
    """Magic-byte based fallback when Magika is absent."""
    if not content:
        return ""
    head = content[:512]
    for label, magic in _HEURISTIC_MAGIC:
        if head.startswith(magic):
            return label
    # Text heuristics
    try:
        text = head.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "binary"
    low = text.lower().lstrip()
    if low.startswith("<?php"):
        return "phpsource"
    if low.startswith("<!doctype html") or low.startswith("<html"):
        return "html"
    if low.startswith("{") and ("\":" in text or "\":\n" in text):
        return "json"
    if low.startswith("<?xml"):
        return "xml"
    if low.startswith("#!/"):
        if "python" in low.split("\n", 1)[0]:
            return "python"
        if "node" in low.split("\n", 1)[0]:
            return "javascript"
        return "shell"
    if "function" in low and ("{" in low or "=>" in low):
        return "javascript"
    if low.startswith("body {") or "body{" in low:
        return "css"
    return "txt"


# ---- Finding emission rules ------------------------------------------------


_SECRET_KIND_TO_RULE: dict[str, str] = {
    # All secrets emit CC-006; severity is taken from the secret's own.
}


def _build_findings(
    classif: ContentClassification, source_url: str
) -> tuple[ContentFinding, ...]:
    out: list[ContentFinding] = []

    # CC-001 / CC-002 — disguise findings
    if classif.disguise.mime_disguise:
        out.append(
            ContentFinding(
                rule_id="CC-001",
                severity=classif.disguise.severity or "HIGH",
                title="MIME disguise: server Content-Type differs from actual content",
                detail=classif.disguise.mime_detail,
                remediation=(
                    "Set the Content-Type header from the actual file type. "
                    "Reject uploads whose declared MIME doesn't match the "
                    "magika-detected type."
                ),
                source_url=source_url,
                extra=(
                    ("detected_label", classif.magika_label or classif.heuristic_label),
                ),
            )
        )
    if classif.disguise.extension_disguise:
        out.append(
            ContentFinding(
                rule_id="CC-002",
                severity=classif.disguise.severity or "MEDIUM",
                title="Extension disguise: URL extension doesn't match actual content",
                detail=classif.disguise.extension_detail,
                remediation=(
                    "Normalize file extensions on upload. Reject or rename "
                    "files whose content disagrees with their extension."
                ),
                source_url=source_url,
                extra=(
                    ("detected_label", classif.magika_label or classif.heuristic_label),
                ),
            )
        )

    # CC-003 — polyglot
    if classif.polyglot:
        sigs = ", ".join(p.signature for p in classif.polyglot_indicators)
        out.append(
            ContentFinding(
                rule_id="CC-003",
                severity="HIGH",
                title="Polyglot file detected (multiple format signatures)",
                detail=(
                    f"Content contains signatures for multiple distinct formats: "
                    f"{sigs}. Classic file-upload bypass pattern."
                ),
                remediation=(
                    "Re-encode uploaded files via a trusted library (Pillow for "
                    "images, etc.) instead of accepting the upload as-is. Validate "
                    "that the file contains ONLY the declared format."
                ),
                source_url=source_url,
                extra=(("polyglot_signatures", sigs),),
            )
        )

    # CC-004 — executable in web path
    label = (classif.magika_label or classif.heuristic_label or "").lower()
    if label in {"elf", "pe", "macho", "wasm"} and classif.threat.score >= 60:
        out.append(
            ContentFinding(
                rule_id="CC-004",
                severity="CRITICAL" if classif.threat.score >= 80 else "HIGH",
                title=f"Executable ({label}) served from web endpoint",
                detail=(
                    f"Body content is a {label!r} executable. Threat score: "
                    f"{classif.threat.score}/100. Factors: "
                    + "; ".join(classif.threat.factors)
                ),
                remediation=(
                    "Restrict file types served. If this endpoint should not "
                    "return binaries, audit how the response got here."
                ),
                source_url=source_url,
            )
        )

    # CC-005 — source code leak
    if label in {"phpsource", "php", "python", "ruby", "go", "java", "rust"}:
        if classif.threat.score >= 60:
            out.append(
                ContentFinding(
                    rule_id="CC-005",
                    severity="CRITICAL" if classif.threat.score >= 75 else "HIGH",
                    title=f"Source code ({label}) leaked in response body",
                    detail=(
                        f"Body content is recognized as {label!r} source code "
                        "but was returned from a production endpoint."
                    ),
                    remediation=(
                        "Verify the application interpreter is configured. PHP "
                        "files served as source = interpreter not running. Audit "
                        "deploy + web-server config."
                    ),
                    source_url=source_url,
                )
            )

    # CC-006 — embedded secrets
    for secret in classif.embedded_secrets:
        out.append(
            ContentFinding(
                rule_id="CC-006",
                severity=secret.severity,
                title=f"Embedded secret detected: {secret.kind}",
                detail=(
                    f"Body contains a {secret.kind} (redacted preview: "
                    f"{secret.redacted_preview}). SHA-256 fingerprint: "
                    f"{secret.value_sha256[:16]}…"
                ),
                remediation=(
                    "Rotate the secret immediately. Remove it from this "
                    "response. Audit how it ended up in client-visible "
                    "content (often: server-side config dumped into HTML, "
                    "or .env served by mistake)."
                ),
                source_url=source_url,
                extra=(
                    ("secret_kind", secret.kind),
                    ("secret_sha256", secret.value_sha256),
                    ("redacted_preview", secret.redacted_preview),
                ),
            )
        )

    # CC-007 — high entropy in unexpected place
    if (
        classif.content_entropy >= 7.0
        and classif.content_length >= 256
        and label in {"txt", "html", ""}
    ):
        out.append(
            ContentFinding(
                rule_id="CC-007",
                severity="LOW",
                title="High-entropy content in non-binary response",
                detail=(
                    f"Body looks like a text response but has Shannon entropy "
                    f"{classif.content_entropy:.2f} (~random). Could indicate "
                    "embedded encrypted/encoded data or a leaked secret blob."
                ),
                remediation=(
                    "Inspect manually. If intentional (e.g. base64 payload), no "
                    "action needed; if not, investigate."
                ),
                source_url=source_url,
            )
        )

    return tuple(out)


# ---- Public API ------------------------------------------------------------


class ContentClassifier:
    """Composes magika + heuristics + scoring into a single output."""

    def __init__(self, prefer_magika: bool = True) -> None:
        self.prefer_magika = prefer_magika
        self._magika_available = is_magika_available()

    def classify(self, input: ContentInput) -> ContentClassification:
        content = input.content or b""
        clen = input.content_length or len(content)

        magika_label = ""
        heuristic_label = ""
        magika_ok = self._magika_available and self.prefer_magika
        if magika_ok and content:
            magika_label = _magika_classify(content)
        if not magika_label:
            heuristic_label = _heuristic_label(content, input.content_type_header)
        chosen_label = magika_label or heuristic_label

        disguise = detect_disguise(
            chosen_label, input.content_type_header, input.source_url
        )
        polyglot_inds = detect_polyglot(content)
        polyglot_flag = is_polyglot(polyglot_inds)
        secrets = scan_for_secrets(content)
        entropy = shannon_entropy(content)

        threat = score_threat(
            detected_label=chosen_label,
            source_url=input.source_url,
            content_length=clen,
            secret_count=len(secrets),
            polyglot_present=polyglot_flag,
            mime_disguise=disguise.mime_disguise,
        )

        sha = hashlib.sha256(content).hexdigest() if content else ""

        classification = ContentClassification(
            magika_label=magika_label,
            magika_available=self._magika_available,
            heuristic_label=heuristic_label,
            disguise=disguise,
            polyglot_indicators=polyglot_inds,
            polyglot=polyglot_flag,
            embedded_secrets=secrets,
            threat=threat,
            content_sha256=sha,
            content_entropy=entropy,
            content_length=clen,
        )
        findings = _build_findings(classification, input.source_url)
        return ContentClassification(
            **{**classification.__dict__, "findings": findings}
        )


def classify_content(
    content: bytes,
    source_url: str = "",
    content_type_header: str = "",
) -> ContentClassification:
    """Functional shortcut."""
    return ContentClassifier().classify(
        ContentInput(
            content=content,
            source_url=source_url,
            content_type_header=content_type_header,
            content_length=len(content),
        )
    )
