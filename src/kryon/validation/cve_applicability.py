"""F173 — Tech-stack vs CVE applicability filter.

This module sits between F151 (CVE format gate) / F171 (existence gate)
and the finding output. F151 catches malformed CVE IDs; F171 catches
plausible fabrications that were never published. What still leaks
through: a **real, published CVE that simply doesn't apply** to the
target stack.

The F170 bench surfaced the canonical example. gpt-oss-20b emitted
``CVE-2013-6235`` (JAMon JSP cross-site scripting) as a finding for
OWASP Juice Shop. CVE-2013-6235 is real and lives in the NVD cache so
F171 doesn't drop it. But Juice Shop is a Node.js/Express app — JAMon
is a Java profiling tool. The CVE does not apply.

This filter loads the CVE's affected-product metadata (NVD ``cpe``
strings + description) and checks whether **any** of those products
match the technology stack observed on the target. Stack is built
from prior tool outputs: WhatWeb plugins, HTTP ``Server`` and
``X-Powered-By`` headers, banner grabs. Matching is substring +
case-insensitive — a CVE that names ``nginx`` will match a stack
token ``nginx/1.20.0``.

**Conservative by design**: when either side of the comparison is
empty (no recon yet, or NVD has no structured product data for this
CVE), the filter passes the finding. We don't penalize the operator
for missing data.

Env:
  - ``KRYON_CVE_APPLICABILITY``  default ``true``. Set to ``false`` to
    skip the gate entirely (research / testing).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CVEApplicability:
    """Subset of NVD metadata used by the filter."""

    cve_id: str
    products: tuple[str, ...] = ()
    description: str = ""


# ---------------------------------------------------------------------------
# Tech-stack extraction
# ---------------------------------------------------------------------------


# WhatWeb plugin keys appear as JSON object keys: ``"PluginName":{...}``.
# We grab the key directly off the JSON-shaped output so we don't have to
# fully parse the file (whatweb returns valid JSON but the regex is
# resilient to truncation).
_WHATWEB_PLUGIN_RE = re.compile(r'"([A-Za-z0-9_.\-/]+)"\s*:\s*\{')

# WhatWeb often emits human-readable product strings inside ``"string":["..."]``.
_WHATWEB_STRING_RE = re.compile(r'"string"\s*:\s*\[\s*"([^"]+)"')

# Server / X-Powered-By header tokens — capture the product, ignore the
# version suffix; downstream matching uses substring so the version
# stays in the stack token too.
_SERVER_HEADER_RE = re.compile(
    r"(?im)^(?:Server|X-Powered-By)\s*:\s*([A-Za-z0-9_.\-/ ]+)"
)


def extract_target_tech_stack(text: str | None) -> set[str]:
    """Pull a normalized set of technology tokens from arbitrary recon
    output (whatweb JSON, HTTP headers, banner grabs, etc.).

    Returns a set of lowercase tokens. Empty input → empty set.
    """
    if not text or not isinstance(text, str):
        return set()

    tokens: set[str] = set()

    # WhatWeb JSON plugins.
    for plugin in _WHATWEB_PLUGIN_RE.findall(text):
        norm = plugin.strip().lower()
        if norm and norm not in {"plugins", "string", "module", "target", "request_config"}:
            tokens.add(norm)

    # WhatWeb plugin string values (Title, X-Powered-By, etc.).
    for value in _WHATWEB_STRING_RE.findall(text):
        norm = value.strip().lower()
        if norm:
            tokens.add(norm)

    # HTTP headers.
    for value in _SERVER_HEADER_RE.findall(text):
        norm = value.strip().lower()
        if norm:
            tokens.add(norm)
            # Also add the bare product name (left of the version slash).
            bare = norm.split("/", 1)[0].strip()
            if bare and bare != norm:
                tokens.add(bare)

    return tokens


# ---------------------------------------------------------------------------
# Applicability check
# ---------------------------------------------------------------------------


def _normalize(token: str) -> str:
    """Lowercase, collapse separators (``-`` / ``_`` / spaces / dots)."""
    t = token.lower().strip()
    for ch in ("-", "_", "."):
        t = t.replace(ch, " ")
    return " ".join(t.split())


def _tokens_overlap(left: str, right: str) -> bool:
    """True iff the normalized forms share a substring at the product
    level. ``apache log4j core`` overlaps ``log4j``, but ``apache`` alone
    doesn't overlap ``log4j`` — we require the shared substring to be
    something a reasonable product name (≥4 chars), not a generic
    prefix like ``apache``."""
    a = _normalize(left)
    b = _normalize(right)
    if not a or not b:
        return False

    # Split into words and look for a meaningful shared word.
    a_words = {w for w in a.split() if len(w) >= 4}
    b_words = {w for w in b.split() if len(w) >= 4}
    if a_words & b_words:
        return True

    # Substring fallback for compound product names without spaces.
    if len(a) >= 4 and a in b:
        return True
    if len(b) >= 4 and b in a:
        return True
    return False


def _env_true(name: str, default: str = "true") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def is_cve_applicable(
    cve: CVEApplicability, tech_stack: set[str]
) -> tuple[bool, str]:
    """Decide whether ``cve`` plausibly applies to a target whose
    detected technology stack is ``tech_stack``.

    Returns ``(applicable, reason)``. Conservative defaults — when
    either side is empty, returns ``(True, ...)`` so the finding
    survives.
    """
    if not _env_true("KRYON_CVE_APPLICABILITY"):
        return True, "applicability filter disabled via KRYON_CVE_APPLICABILITY=false"

    if not tech_stack:
        return True, "no tech stack info — passing conservatively"

    if not cve.products and not cve.description:
        return True, "no CVE metadata — passing conservatively"

    # Try structured product list first.
    for product in cve.products:
        for token in tech_stack:
            if _tokens_overlap(product, token):
                return True, f"CVE product '{product}' matches stack token '{token}'"

    # Description fallback: split description into candidate words and
    # check for an explicit tech token match. Only counts when the CVE
    # provides no structured product list (description is noisy).
    if not cve.products and cve.description:
        desc_norm = _normalize(cve.description)
        for token in tech_stack:
            t_norm = _normalize(token)
            if len(t_norm) >= 4 and t_norm in desc_norm:
                return True, f"description mentions '{token}'"

    products_str = ", ".join(cve.products) if cve.products else "(no products listed)"
    return (
        False,
        f"no match between CVE products [{products_str}] and detected stack "
        f"[{', '.join(sorted(tech_stack))}]",
    )


# ---------------------------------------------------------------------------
# Finding-level entry point
# ---------------------------------------------------------------------------


def _lookup_cve_metadata(cve_id: str) -> CVEApplicability:
    """Stub: in this commit we only expose the lookup hook so tests can
    inject metadata. A real NVD-backed lookup (loading from a JSON
    sibling of ``cves.txt``) lands in a follow-up commit; until then
    the lookup returns empty metadata and the filter passes the
    finding (conservative default).

    Tests monkeypatch this symbol directly.
    """
    return CVEApplicability(cve_id=cve_id, products=(), description="")


def is_cve_applicable_for_finding(
    finding: dict | object, *, tech_stack: set[str]
) -> tuple[bool, str]:
    """Run the applicability gate over a finding-shaped object.

    Non-CVE rule_ids (``Missing-CSP``, ``Exposed-htpasswd``, etc.) pass
    unconditionally — this gate is CVE-specific.
    """
    if isinstance(finding, dict):
        rule_id = str(finding.get("rule_id", "") or "")
    else:
        rule_id = str(getattr(finding, "rule_id", "") or "")
    rule_id = rule_id.strip().upper()

    if not rule_id.startswith("CVE-"):
        return True, "rule_id is not CVE-shaped; gate does not apply"

    cve_meta = _lookup_cve_metadata(rule_id)
    return is_cve_applicable(cve_meta, tech_stack)
