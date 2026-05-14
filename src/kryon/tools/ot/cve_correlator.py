"""F84.6 — Correlate OT banner detections with CISA ICS advisories.

Each `tools/ot/<protocol>_*` module extracts a vendor/product banner
(Modbus device ID, S7 SZL module ID, DNP3 outstation banner, etc.).
This module takes that banner triple — (vendor, product, version) —
and returns any advisories whose `products_affected` field plausibly
covers it.

Heuristic (precision-over-recall, banking-safe):

  1. Vendor match (case-insensitive substring either direction).
  2. Product token overlap: at least one token of `product` (length ≥3)
     must appear in the advisory's `products_affected` string, OR the
     advisory's `product` field must contain the queried product as a
     substring.
  3. Optional version match: if the caller supplied a version AND the
     advisory's `products_affected` contains an explicit version range
     like "5.8.x" or "V4.4", the version must be inside that range.
     When version parsing is ambiguous, we **include** the advisory
     and let the human auditor decide — false-positive bias is
     acceptable for an advisory dataset (auditor reviews each hit).

We don't try to parse arbitrary semver ranges — operator banners in OT
gear use vendor-specific schemes (Siemens V4.4.3, Modicon UMAS 2.3,
DNP3 outstation revision 1.0a). Keeping the matcher conservative
prevents the loader from emitting wildly off-target CVEs.
"""

from __future__ import annotations

import re
from pathlib import Path

from kryon.knowledge.datasets import Advisory, advisories_by_vendor

__all__ = ["correlate_banner_to_cves"]

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
_VERSION_RE = re.compile(r"\bV?(\d+(?:\.\d+){1,3})\b")


def _tokens(text: str, min_length: int = 3) -> set[str]:
    """Tokenize a banner string into lower-case alphanumeric tokens.
    Tokens shorter than `min_length` are dropped — they cause spurious
    matches ("V4" matches everything Siemens-shaped)."""
    return {t.lower() for t in _TOKEN_RE.findall(text) if len(t) >= min_length}


def _version_tuple(raw: str) -> tuple[int, ...] | None:
    """Extract the leading dotted-int version. "V4.4.3" → (4, 4, 3).
    Returns None when no version is present."""
    match = _VERSION_RE.search(raw)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def _product_relates(product: str, advisory: Advisory) -> bool:
    """Stage 2 of the heuristic — token overlap or substring."""
    product_lower = product.strip().lower()
    if not product_lower:
        return False
    haystack = f"{advisory.product} {advisory.products_affected}".lower()
    if product_lower in haystack or advisory.product.lower() in product_lower:
        return True
    query_tokens = _tokens(product)
    if not query_tokens:
        return False
    advisory_tokens = _tokens(advisory.products_affected) | _tokens(advisory.product)
    return bool(query_tokens & advisory_tokens)


def _version_compatible(version: str | None, advisory: Advisory) -> bool:
    """Stage 3 of the heuristic — version inclusion when both sides
    provide one. When either side is ambiguous, return True so the
    auditor sees the hit and can dismiss it manually."""
    if not version:
        return True
    queried = _version_tuple(version)
    if queried is None:
        return True
    advisory_versions = [
        tuple(int(p) for p in m.group(1).split(".")) for m in _VERSION_RE.finditer(advisory.products_affected)
    ]
    if not advisory_versions:
        return True
    # If ANY explicit version in the advisory matches the queried one
    # at the major.minor level, include. Stricter exact-match would
    # miss patch-level dot-releases that share the same CVE.
    queried_majmin = queried[:2]
    return any(v[:2] == queried_majmin for v in advisory_versions)


def correlate_banner_to_cves(
    vendor: str,
    product: str,
    version: str | None = None,
    *,
    dataset_path: Path | None = None,
) -> tuple[Advisory, ...]:
    """Given a banner triple, return matching CISA advisories.

    Empty tuple when nothing matches. Callers should sort by
    `cvss_v3` if they want the highest-impact advisory first.

    Banking-safe note: this function is read-only on the dataset and
    performs no network I/O. Refresh of the underlying CSV is a
    separate operator workflow (scripts/update_cisa_advisories.sh).
    """
    if not vendor.strip():
        return ()

    candidates = advisories_by_vendor(vendor, path=dataset_path)
    if not candidates:
        return ()

    return tuple(adv for adv in candidates if _product_relates(product, adv) and _version_compatible(version, adv))
