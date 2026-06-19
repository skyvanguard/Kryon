"""Deterministic secret extraction. The probe layer detects that a ``.env`` /
``.git`` / config file is *exposed*; this turns that exposure into a concrete,
demonstrable finding by extracting and classifying the actual credentials in the
body (gitleaks/trufflehog-style: curated FP-safe regexes + an entropy fallback).

Pure + offline: ``scan_secrets(text, source)`` returns ``SecretMatch`` objects;
``to_findings(matches, host)`` converts them to engage ``Finding`` records. The
matched secret is always REDACTED in evidence — we never store the full value.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from kryon.cli.engage import Finding, make_finding


@dataclass(frozen=True)
class SecretMatch:
    kind: str  # human label, e.g. "AWS Access Key ID"
    rule_id: str
    severity: str
    redacted: str  # safe-to-log preview (first/last chars only)
    line: int  # 1-based line where it was found


def _redact(value: str) -> str:
    v = value.strip()
    if len(v) <= 10:
        return v[0] + "***" + v[-1] if len(v) > 2 else "***"
    return f"{v[:4]}…{v[-4:]} ({len(v)} chars)"


# (rule_id, label, severity, compiled regex). Prefixes/structure make these
# specific enough that ordinary prose/HTML won't false-trigger.
_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    ("secret-aws-akid", "AWS Access Key ID", "HIGH", re.compile(r"\b((?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16})\b")),
    ("secret-aws-secret", "AWS Secret Access Key", "CRITICAL",
     re.compile(r"(?i)aws_?secret_?access_?key[\"'\s:=]+([A-Za-z0-9/+]{40})")),
    ("secret-private-key", "Private Key (PEM)", "CRITICAL",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("secret-github-pat", "GitHub Token", "HIGH", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b")),
    ("secret-gitlab-pat", "GitLab Token", "HIGH", re.compile(r"\b(glpat-[A-Za-z0-9_-]{20})\b")),
    ("secret-slack-token", "Slack Token", "HIGH", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b")),
    ("secret-google-api", "Google API Key", "HIGH", re.compile(r"\b(AIza[A-Za-z0-9_-]{35})\b")),
    ("secret-stripe", "Stripe Secret Key", "CRITICAL", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{24,99})\b")),
    ("secret-jwt", "JSON Web Token", "MEDIUM", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("secret-slack-webhook", "Slack Webhook", "MEDIUM", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("secret-db-uri", "Database Connection URI", "HIGH",
     re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@[^\s/]+)")),
    ("secret-twilio", "Twilio API Key", "HIGH", re.compile(r"\b(SK[a-f0-9]{32})\b")),
    ("secret-npm-token", "npm Token", "HIGH", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
    ("secret-generic-password", "Hardcoded Password/Secret", "MEDIUM",
     re.compile(r"(?im)^\s*(?:DB_PASSWORD|APP_KEY|SECRET_KEY|API_SECRET|PRIVATE_TOKEN|DATABASE_PASSWORD)\s*[:=]\s*[\"']?([^\s\"'#]{6,})")),
)

# Keys whose value we entropy-check (generic high-entropy credential).
_ENTROPY_ASSIGN = re.compile(r"(?i)\b(\w*(?:secret|token|apikey|api_key|passwd|password|access_key)\w*)\s*[:=]\s*[\"']?([A-Za-z0-9/+_\-]{20,})")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan_secrets(text: str, source: str = "") -> list[SecretMatch]:
    """Extract + classify secrets from a blob of text. Pure, deterministic.
    ``source`` is a label (path/url) kept for the caller's evidence string."""
    if not text:
        return []
    out: list[SecretMatch] = []
    seen: set[tuple[str, str]] = set()

    def _line_of(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    for rule_id, label, sev, rx in _PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            key = (rule_id, val)
            if key in seen:
                continue
            seen.add(key)
            out.append(SecretMatch(label, rule_id, sev, _redact(val), _line_of(m.start())))

    # Entropy fallback: high-entropy value assigned to a secret-looking key,
    # not already caught by a structural pattern above.
    for m in _ENTROPY_ASSIGN.finditer(text):
        val = m.group(2)
        if any(val in s.redacted or val[:4] in s.redacted for s in out):
            continue
        if _shannon_entropy(val) >= 3.5:
            key = ("secret-high-entropy", val)
            if key in seen:
                continue
            seen.add(key)
            out.append(SecretMatch(f"High-entropy secret ({m.group(1)})", "secret-high-entropy", "MEDIUM",
                                   _redact(val), _line_of(m.start())))
    return out


def to_findings(matches: list[SecretMatch], host: str, source: str) -> list[Finding]:
    """Convert SecretMatch records into engage Findings (one per match)."""
    return [
        make_finding(
            "CWE-798", mt.severity, host, mt.rule_id,
            f"Secreto expuesto en {source}: {mt.kind} (host {host}).",
            evidence=f"{mt.kind} en {source}:{mt.line} → {mt.redacted}",
            remediation="Rotar el secreto YA; removerlo del recurso expuesto; usar un secret manager / "
                        "variables de entorno fuera del docroot.",
        )
        for mt in matches
    ]
