"""F2.2 — Baseline CVSS v3.1 scores derived from severity.

Compliance checks classify by severity, not CVSS. CISOs prioritize by CVSS, so
we map each severity tier to a representative CVSS v3.1 base score + vector. This
is a deterministic baseline for prioritization — a finding that carries its own
measured CVSS (e.g. an intelligence Finding with cvss_score) should use that
instead. The mapping is intentionally conservative and documented, not invented
per finding.
"""

from __future__ import annotations

# severity → (base_score, representative v3.1 vector)
_BASELINE: dict[str, tuple[float, str]] = {
    "CRITICAL": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "HIGH": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "MEDIUM": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "LOW": (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "INFO": (0.0, ""),
}


def cvss_for_severity(severity: str) -> tuple[float, str]:
    """Return ``(base_score, vector)`` for a severity label (case-insensitive).

    Unknown severities fall back to MEDIUM so a finding is never silently
    dropped from prioritization.
    """
    return _BASELINE.get((severity or "").upper(), _BASELINE["MEDIUM"])


def cvss_score_for_severity(severity: str) -> float:
    return cvss_for_severity(severity)[0]
