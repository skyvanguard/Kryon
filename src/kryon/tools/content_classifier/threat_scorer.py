"""F116 — Contextual threat scoring.

Given (detected_label, source_url, content_length, headers), assign
a 0-100 threat score. The scorer encodes operational risk:

  * Same content in /static/foo.css and /uploads/foo.css have wildly
    different risk profiles. /uploads/+executable = takeover; /static/
    +executable = probably a misnamed asset.
  * Source-code labels (phpsource, python) from a /api/ endpoint are
    critical (live source leak); from /docs/ they may be intentional.

Scoring is heuristic but reproducible. The output feeds into rule
selection (CC-004 / CC-005 / etc.)."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

__all__ = ["ThreatScoreResult", "score_threat"]


@dataclass(frozen=True)
class ThreatScoreResult:
    score: int  # 0..100
    factors: tuple[str, ...]  # human-readable contributors
    primary_rule: str = ""  # the most-specific CC-NNN rule to emit


# Source-code labels that are NEVER expected from production endpoints
_SOURCE_LABELS: frozenset[str] = frozenset(
    {"phpsource", "php", "python", "ruby", "go", "java", "rust"}
)

# Executable labels — almost never legit from web responses
_EXECUTABLE_LABELS: frozenset[str] = frozenset(
    {"elf", "pe", "macho", "wasm", "dosbinary"}
)

# Archive labels — sometimes legit (downloads) but risky in some paths
_ARCHIVE_LABELS: frozenset[str] = frozenset(
    {"zip", "gzip", "tar", "7zip", "rar"}
)

# Path heuristics: bonus / penalty multipliers
_UPLOAD_PATH_HINTS: tuple[str, ...] = (
    "/upload", "/uploads", "/userfiles", "/files/user", "/avatar",
    "/profile/photo", "/attachments",
)
_STATIC_PATH_HINTS: tuple[str, ...] = (
    "/static/", "/assets/", "/public/", "/dist/", "/build/",
    "/_next/", "/_nuxt/", "/wp-content/uploads/themes/",
)
_API_PATH_HINTS: tuple[str, ...] = ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")
_ADMIN_PATH_HINTS: tuple[str, ...] = ("/admin", "/manage", "/dashboard", "/wp-admin/")
_DOCS_PATH_HINTS: tuple[str, ...] = ("/docs/", "/documentation/", "/swagger", "/api-docs")
_BACKUP_PATH_HINTS: tuple[str, ...] = (".bak", ".old", ".backup", ".swp", ".save", ".orig")


def _path_lower(url: str) -> str:
    return (urlparse(url).path or "").lower()


def score_threat(
    detected_label: str,
    source_url: str = "",
    content_length: int = 0,
    secret_count: int = 0,
    polyglot_present: bool = False,
    mime_disguise: bool = False,
) -> ThreatScoreResult:
    """Compute the contextual threat score + best CC rule to emit."""
    label = (detected_label or "").lower().strip()
    path = _path_lower(source_url)
    factors: list[str] = []
    score = 0
    primary_rule = ""

    # ---- Source code from any web response = bad ----
    if label in _SOURCE_LABELS:
        if any(h in path for h in _DOCS_PATH_HINTS):
            score += 25
            factors.append("source-code in /docs path (-25 vs critical)")
            primary_rule = primary_rule or "CC-005"
        else:
            score += 80
            factors.append("source-code leaked from production endpoint")
            primary_rule = "CC-005"

    # ---- Executables ----
    if label in _EXECUTABLE_LABELS:
        if any(h in path for h in _UPLOAD_PATH_HINTS):
            score += 90
            factors.append("executable in /uploads — web-shell pattern")
            primary_rule = primary_rule or "CC-004"
        elif any(h in path for h in _STATIC_PATH_HINTS):
            score += 30
            factors.append("executable in /static — likely misnamed asset")
            primary_rule = primary_rule or "CC-004"
        else:
            score += 70
            factors.append("executable served from generic web path")
            primary_rule = primary_rule or "CC-004"

    # ---- Polyglot ----
    if polyglot_present:
        # Polyglot in /uploads + image MIME would be the worst —
        # the file is an image that ALSO contains script content
        if any(h in path for h in _UPLOAD_PATH_HINTS):
            score += 80
            factors.append("polyglot in /uploads — bypass-pattern")
            primary_rule = primary_rule or "CC-003"
        else:
            score += 50
            factors.append("polyglot file")
            primary_rule = primary_rule or "CC-003"

    # ---- MIME disguise ----
    if mime_disguise:
        # Already weighted by the disguise module's severity; add a
        # context bump if it lands in a sensitive path.
        if any(h in path for h in _UPLOAD_PATH_HINTS):
            score += 50
            factors.append("MIME disguise in /uploads")
        elif any(h in path for h in _ADMIN_PATH_HINTS):
            score += 40
            factors.append("MIME disguise in /admin")
        else:
            score += 30
            factors.append("MIME disguise")
        primary_rule = primary_rule or "CC-001"

    # ---- Embedded secrets ----
    if secret_count > 0:
        if any(h in path for h in _API_PATH_HINTS):
            score += min(60, 30 * secret_count)
            factors.append(f"{secret_count} secret(s) in API response")
        else:
            score += min(50, 25 * secret_count)
            factors.append(f"{secret_count} secret(s) in response body")
        primary_rule = primary_rule or "CC-006"

    # ---- Backup / dotfile path penalties ----
    if any(path.endswith(b) for b in _BACKUP_PATH_HINTS):
        score += 20
        factors.append("backup-style file extension")

    # ---- Archive in sensitive places ----
    if label in _ARCHIVE_LABELS:
        if any(h in path for h in _ADMIN_PATH_HINTS + _API_PATH_HINTS):
            score += 30
            factors.append("archive served from API/admin")
            primary_rule = primary_rule or "CC-008"

    score = max(0, min(100, score))
    return ThreatScoreResult(
        score=score,
        factors=tuple(factors),
        primary_rule=primary_rule,
    )
