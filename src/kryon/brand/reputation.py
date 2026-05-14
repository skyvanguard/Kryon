"""F90.3 — Brand reputation aggregator.

Closes F90 by combining the F90.1 typosquat scan + F90.2 CT monitor
signals (and an optional WHOIS age lookup) into a unified per-domain
risk score the brand-protection team acts on.

Scoring philosophy: additive evidence with a legitimate-override.
Each signal contributes a point delta toward `score` (0..100 capped).
The legitimate-whitelist signal applies a hard floor — a domain
covered by the bank's whitelist scores low regardless of how
suspicious the other signals look (banks legitimately issue weird-
looking certs all the time).

Signals + deltas:

  registered          +20  domain resolves in DNS (typosquat hit)
  brand_keyword       +20  brand keyword in the domain itself
  ssl_cert            +15  ≥1 CT cert matches the domain
  ssl_cert_recent     +15  one of those certs is fresh
  ssl_cert_high       +20  one of those certs classified high-risk
  suspicious_tld      +20  on F90.2's SUSPICIOUS_TLDS list
  whois_new           +30  WHOIS age < 30 days (when available)
  whois_unknown        0   no WHOIS data (don't penalize unknown)
  legitimate         -100  on the bank's whitelist — HARD overridem
                            (effectively forces score to 0)

Tiers:
  >= 70  → high
  >= 40  → medium
  >= 20  → low
  <  20  → info

These thresholds are deliberately conservative for banking: a single
strong signal (recent cert on suspicious TLD = 35) lands the domain
in `medium`, not `high`. Operators usually want a manual review
before they escalate — false positives in a takedown request burn
political capital with registrars.

Banca-safety:
  - Aggregator itself is a PURE function. No I/O. Inputs are the
    structured results from F90.1 + F90.2 + optional WHOIS dict.
  - `lookup_whois_age` is gated (KRYON_BRAND_FIRE=true env + arg)
    and uses subprocess to the system `whois` binary when available.
    Falls back to None gracefully — never crashes the aggregator.
  - Read-only. No takedown requests, no registrar notifications —
    those are downstream operator decisions.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from kryon.brand.ct_monitor import (
    SUSPICIOUS_TLDS,
    CTRiskAssessment,
)
from kryon.brand.typosquat import TyposquatScanResult

logger = logging.getLogger(__name__)


__all__ = [
    "BrandSignal",
    "DomainRisk",
    "ReputationReport",
    "aggregate_reputation",
    "lookup_whois_age",
    "DEFAULT_TIER_THRESHOLDS",
    "SIGNAL_DELTAS",
]


# Signal name → point delta. Tweakable but pinned by tests so a
# tuning change is intentional.
SIGNAL_DELTAS: dict[str, int] = {
    "registered": 20,
    "brand_keyword": 20,
    "ssl_cert": 15,
    "ssl_cert_recent": 15,
    "ssl_cert_high": 20,
    "suspicious_tld": 20,
    "whois_new": 30,
    "legitimate": -100,  # hard override
}

# Tier thresholds (lower bounds, inclusive).
DEFAULT_TIER_THRESHOLDS: dict[str, int] = {
    "high": 70,
    "medium": 40,
    "low": 20,
}

_WHOIS_NEW_THRESHOLD_DAYS = 30


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BrandSignal:
    """One evidence point contributing to a domain's score."""

    name: str  # matches SIGNAL_DELTAS keys
    delta: int
    detail: str = ""  # human-readable explanation


@dataclass(frozen=True)
class DomainRisk:
    """Per-domain aggregated assessment."""

    domain: str
    score: int  # 0..100, capped
    tier: str  # high / medium / low / info
    signals: tuple[BrandSignal, ...] = field(default_factory=tuple)
    strategies_observed: tuple[str, ...] = field(default_factory=tuple)
    ip_addresses: tuple[str, ...] = field(default_factory=tuple)
    matching_cert_count: int = 0


@dataclass(frozen=True)
class ReputationReport:
    """Aggregated outcome across all evaluated domains."""

    brand_keyword: str
    total_domains: int
    by_tier: dict[str, int] = field(default_factory=dict)
    high_risk: tuple[DomainRisk, ...] = field(default_factory=tuple)
    medium_risk: tuple[DomainRisk, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# WHOIS lookup (gated, optional)
# ---------------------------------------------------------------------------


def _fire_enabled(fire: bool) -> bool:
    if not fire:
        return False
    return os.environ.get("KRYON_BRAND_FIRE", "").strip().lower() in ("1", "true", "yes")


# Match "Creation Date: 2026-04-15T12:34:56Z" or "Created: 2026-04-15"
# across the variants different registrar WHOIS servers return.
_CREATION_PATTERNS = (
    re.compile(r"^\s*creation\s*date\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*created\s*on\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*created\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*registered\s*on\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*domain\s*registration\s*date\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
)


def _parse_creation_date(whois_text: str) -> datetime | None:
    """Extract the creation date from raw WHOIS text. Tries several
    common registrar formats. Returns None when no pattern matches —
    the caller treats that as 'unknown', not 'old'."""
    for pattern in _CREATION_PATTERNS:
        match = pattern.search(whois_text)
        if not match:
            continue
        raw = match.group(1).strip()
        # Trim everything after the first space; some registrars
        # append `(ICANN)` etc.
        raw = raw.split()[0] if raw else ""
        if not raw:
            continue
        # Strip trailing 'Z' for fromisoformat compatibility on older
        # Pythons. Sub-second fractions are tolerated.
        cleaned = raw.rstrip("Z").rstrip("z")
        # Strip sub-second fraction if present.
        cleaned = re.sub(r"\.\d+$", "", cleaned)
        try:
            return datetime.fromisoformat(cleaned).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def lookup_whois_age(
    domain: str,
    *,
    fire: bool = False,
    timeout: int = 15,
) -> int | None:
    """Shell out to the system `whois` binary and parse the creation
    date. Returns age in days, or None when unavailable.

    Gated: KRYON_BRAND_FIRE=true env + fire=True kwarg required.

    None is returned for:
      - dry-run (gates not satisfied)
      - `whois` binary missing from PATH
      - timeout / network failure
      - registrar response without a recognizable creation date

    The aggregator treats None as "unknown — don't penalize". Better
    to under-flag than over-flag on missing metadata.
    """
    if not _fire_enabled(fire):
        return None
    if not domain.strip():
        return None

    try:
        result = subprocess.run(
            ["whois", domain.strip()],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        logger.debug("whois binary not in PATH; skipping age lookup for %s", domain)
        return None
    except subprocess.TimeoutExpired:
        logger.debug("whois lookup timed out for %s", domain)
        return None
    except Exception as e:  # noqa: BLE001
        logger.debug("whois lookup failed for %s: %s", domain, e)
        return None

    creation = _parse_creation_date(result.stdout)
    if creation is None:
        return None
    age = datetime.now(timezone.utc) - creation
    return max(0, int(age.total_seconds() // 86400))


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


def _tier_for_score(score: int, thresholds: dict[str, int] | None = None) -> str:
    """Map an integer score to a tier label. Thresholds inclusive."""
    t = thresholds or DEFAULT_TIER_THRESHOLDS
    if score >= t.get("high", 70):
        return "high"
    if score >= t.get("medium", 40):
        return "medium"
    if score >= t.get("low", 20):
        return "low"
    return "info"


def _is_legitimate(domain: str, legitimate_domains: tuple[str, ...]) -> bool:
    if not legitimate_domains:
        return False
    d = domain.strip().lower()
    legit = {x.strip().lower() for x in legitimate_domains}
    if d in legit:
        return True
    return any(d.endswith("." + x) for x in legit)


def _has_suspicious_tld(domain: str) -> bool:
    if "." not in domain:
        return False
    return domain.rsplit(".", 1)[-1].lower() in SUSPICIOUS_TLDS


def _ct_signals_for_domain(
    domain: str,
    ct_assessments: list[CTRiskAssessment],
) -> tuple[int, int, bool, bool, bool]:
    """Compute the CT-derived per-domain numbers.

    Returns (matching_count, max_score_offset, has_any_cert,
    has_recent_cert, has_high_risk_cert). The score offset is
    derived from the per-cert flags, not returned directly — the
    caller assembles BrandSignal entries from the booleans.
    """
    d = domain.strip().lower()
    matching = 0
    has_recent = False
    has_high = False
    for a in ct_assessments:
        cn = a.cert.common_name or ""
        sans = a.cert.san_names
        # Match: domain is exactly a cert identifier OR domain is a
        # subdomain of one (covers wildcard certs too).
        identifiers = [cn] + list(sans)
        if not any(
            i == d or (i.startswith("*.") and d.endswith("." + i[2:])) or d.endswith("." + i) for i in identifiers if i
        ):
            continue
        matching += 1
        if a.matched_recent:
            has_recent = True
        if a.risk == "high":
            has_high = True
    return matching, 0, matching > 0, has_recent, has_high


def aggregate_reputation(
    *,
    brand_keyword: str,
    typosquat_results: list[TyposquatScanResult] | None = None,
    ct_assessments: list[CTRiskAssessment] | None = None,
    whois_ages: dict[str, int | None] | None = None,
    legitimate_domains: tuple[str, ...] = (),
    tier_thresholds: dict[str, int] | None = None,
) -> ReputationReport:
    """Aggregate F90.1 + F90.2 + optional WHOIS into a per-domain
    risk report.

    Args:
        brand_keyword: the brand being protected (e.g. "bcp").
        typosquat_results: output of F90.1 resolve_candidate (list
            of TyposquatScanResult). Default: empty list.
        ct_assessments: output of F90.2 classify_cert (list of
            CTRiskAssessment). Default: empty list.
        whois_ages: optional dict domain → age_days (None when
            unknown). The aggregator treats missing entries as
            unknown (no signal contribution).
        legitimate_domains: bank's whitelist. Matching domains get
            the -100 override.
        tier_thresholds: override the default tier cutoffs.

    Returns:
        ReputationReport with per-tier counts and the high+medium
        DomainRisk entries surfaced separately for the report.
    """
    typosquat_results = typosquat_results or []
    ct_assessments = ct_assessments or []
    whois_ages = whois_ages or {}

    # Build the universe of domains: every registered typosquat + every
    # domain referenced in a CT assessment whose brand-keyword fired.
    # Resolves are the strongest "this domain exists" signal; CT
    # assessments add domains seen only in certs.
    domains: dict[str, dict[str, Any]] = {}

    def _record(domain: str) -> dict[str, Any]:
        d = domain.strip().lower()
        if not d:
            return {}
        entry = domains.setdefault(
            d,
            {
                "signals": [],
                "strategies": set(),
                "ips": set(),
                "matching_certs": 0,
            },
        )
        return entry

    # F90.1 typosquat → registered + strategy + IPs.
    for r in typosquat_results:
        if r.verdict != "registered":
            continue
        entry = _record(r.candidate.variant)
        if not entry:
            continue
        entry["signals"].append(
            BrandSignal(
                name="registered",
                delta=SIGNAL_DELTAS["registered"],
                detail=f"DNS resolves to {len(r.ip_addresses)} address(es)",
            )
        )
        entry["strategies"].add(r.candidate.strategy)
        entry["ips"].update(r.ip_addresses)

    # F90.2 CT assessments → cert presence + freshness + risk tier.
    # We index per identifier (CN + SANs) so domains that appeared in
    # CT but not in the typosquat output still surface.
    for a in ct_assessments:
        if not a.matched_brand:
            continue
        # Each cert touches one or more domains.
        identifiers: list[str] = []
        if a.cert.common_name:
            identifiers.append(a.cert.common_name)
        identifiers.extend(a.cert.san_names)
        for i in identifiers:
            # Skip wildcard markers in the per-domain accounting; the
            # wildcard signal is applied to the base domain.
            if i.startswith("*."):
                i = i[2:]
            entry = _record(i)
            if not entry:
                continue
            entry["matching_certs"] += 1

    # Now decorate each domain with the cumulative CT signals.
    for domain, entry in domains.items():
        matching, _, has_cert, has_recent, has_high = _ct_signals_for_domain(domain, ct_assessments)
        entry["matching_certs"] = matching
        if has_cert:
            entry["signals"].append(
                BrandSignal(
                    name="ssl_cert",
                    delta=SIGNAL_DELTAS["ssl_cert"],
                    detail=f"{matching} SSL cert(s) cover this domain",
                )
            )
        if has_recent:
            entry["signals"].append(
                BrandSignal(
                    name="ssl_cert_recent",
                    delta=SIGNAL_DELTAS["ssl_cert_recent"],
                    detail="at least one cert was issued recently",
                )
            )
        if has_high:
            entry["signals"].append(
                BrandSignal(
                    name="ssl_cert_high",
                    delta=SIGNAL_DELTAS["ssl_cert_high"],
                    detail="at least one cert classified as high-risk",
                )
            )

    # Brand keyword + suspicious TLD + WHOIS age + legitimate.
    kw = brand_keyword.strip().lower()
    for domain, entry in domains.items():
        if kw and kw in domain:
            entry["signals"].append(
                BrandSignal(
                    name="brand_keyword",
                    delta=SIGNAL_DELTAS["brand_keyword"],
                    detail=f"brand keyword {kw!r} present in domain",
                )
            )
        if _has_suspicious_tld(domain):
            entry["signals"].append(
                BrandSignal(
                    name="suspicious_tld",
                    delta=SIGNAL_DELTAS["suspicious_tld"],
                    detail="TLD on the abuse-prone list",
                )
            )
        age = whois_ages.get(domain)
        if age is not None and age < _WHOIS_NEW_THRESHOLD_DAYS:
            entry["signals"].append(
                BrandSignal(
                    name="whois_new",
                    delta=SIGNAL_DELTAS["whois_new"],
                    detail=f"WHOIS creation only {age} days ago",
                )
            )
        if _is_legitimate(domain, legitimate_domains):
            entry["signals"].append(
                BrandSignal(
                    name="legitimate",
                    delta=SIGNAL_DELTAS["legitimate"],
                    detail="domain covered by the bank's legitimate whitelist",
                )
            )

    # Build DomainRisk entries, sort by score descending.
    risks: list[DomainRisk] = []
    for domain, entry in domains.items():
        signals = tuple(entry["signals"])
        raw_score = sum(s.delta for s in signals)
        # Capped 0..100. The legitimate override drives below zero;
        # cap to zero so the tier classifier sees a clean number.
        capped = max(0, min(100, raw_score))
        tier = _tier_for_score(capped, tier_thresholds)
        risks.append(
            DomainRisk(
                domain=domain,
                score=capped,
                tier=tier,
                signals=signals,
                strategies_observed=tuple(sorted(entry["strategies"])),
                ip_addresses=tuple(sorted(entry["ips"])),
                matching_cert_count=int(entry["matching_certs"]),
            )
        )
    risks.sort(key=lambda r: (-r.score, r.domain))

    by_tier: dict[str, int] = {}
    for r in risks:
        by_tier[r.tier] = by_tier.get(r.tier, 0) + 1

    return ReputationReport(
        brand_keyword=brand_keyword,
        total_domains=len(risks),
        by_tier=by_tier,
        high_risk=tuple(r for r in risks if r.tier == "high"),
        medium_risk=tuple(r for r in risks if r.tier == "medium"),
    )
