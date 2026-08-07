"""F183 — Generalized finding applicability filter.

F173/F180 catch FPs whose ``rule_id`` is CVE-shaped (e.g.
``CVE-2013-6235``). F182 surfaced an evasion: the model emits the same
JAMon-on-Node-target FP with ``rule_id="WEB-XSS-001"`` (non-CVE shape),
which bypasses the CVE-specific filter even though the
``message``/``evidence`` still cite the wrong-stack product.

This module generalizes the check: scan the finding's text fields
(``message`` + ``evidence``) for known product keywords; if any
product mentioned doesn't apply to the target tech stack, drop the
finding regardless of ``rule_id`` shape.

Conservative defaults preserved:
* No product mention → pass (most legit findings name no products)
* Empty stack → pass
* Match wins on multi-product findings (one matching product saves
  the rest)

Env:
  - ``KRYON_FINDING_APPLICABILITY``  default ``true``. Set ``false``
    to disable the gate entirely.
"""

from __future__ import annotations

import logging
import os
import re

from kryon.validation.cve_applicability import (
    CVEApplicability,
    _target_tech_hint,
    extract_target_tech_stack,
    is_cve_applicable,
)

logger = logging.getLogger(__name__)


# Per-product regex patterns. Mapping: ``keyword_root → (regex_pattern,
# canonical_product_tuple)``. Patterns use a start word-boundary but
# allow some products to match as prefixes of compound names — JAMon
# appears as ``JAMonAdmin.jsp``, Struts as ``struts2``, Log4j as
# ``log4j-core``. Other products like ``jsp`` keep strict boundaries
# because they're short and generic.
#
# F183 deliberately keeps this list narrow to known FP-prone products
# we've seen in benches. Adding a generic keyword like ``apache`` would
# false-positive on every legit Apache-related finding. The list grows
# as new FPs surface.
_PRODUCT_KEYWORDS: dict[str, tuple[str, tuple[str, ...]]] = {
    # Allow JAMon to match JAMonAdmin / JAMonbean (prefix-only).
    "jamon": (r"\bjamon", ("jamon", "jamonadmin")),
    # struts, struts2, struts-rest
    "struts": (r"\bstruts", ("apache struts", "struts2", "struts")),
    # log4j, log4j-core, log4j2
    "log4j": (r"\blog4j", ("log4j", "log4j-core", "apache log4j")),
    "wordpress": (r"\bwordpress\b", ("wordpress",)),
    "drupal": (r"\bdrupal\b", ("drupal",)),
    "joomla": (r"\bjoomla\b", ("joomla",)),
    "tomcat": (r"\btomcat\b", ("tomcat", "apache tomcat")),
    "jsp": (r"\bjsp\b", ("jsp",)),
    "weblogic": (r"\bweblogic\b", ("weblogic", "oracle weblogic")),
    "jboss": (r"\bjboss\b", ("jboss", "wildfly")),
    "exchange server": (
        r"\bexchange\s+server\b",
        ("microsoft exchange", "exchange server"),
    ),
    "spring boot": (r"\bspring\s+boot\b", ("spring framework", "spring boot")),
}


# One combined regex with named groups so we can recover the keyword
# root from each match. Each product's pattern keeps its own boundary
# rules (prefix-only vs full word).
_PRODUCT_RE = re.compile(
    "(?i)(" + "|".join(f"(?P<_{i}>{pat})" for i, (pat, _products) in enumerate(_PRODUCT_KEYWORDS.values())) + ")"
)

# Mapping group-name → keyword root for post-match resolution.
_GROUP_TO_ROOT: dict[str, str] = {f"_{i}": root for i, root in enumerate(_PRODUCT_KEYWORDS.keys())}


def extract_product_mentions(text: str | None) -> set[str]:
    """Return the set of product-keyword roots mentioned in ``text``.

    Empty/None input → empty set. Each product's regex pattern decides
    its own boundary rules (jamon matches JAMonAdmin, jsp requires
    full-word match).
    """
    if not text or not isinstance(text, str):
        return set()
    found: set[str] = set()
    for m in _PRODUCT_RE.finditer(text):
        for group_name, root in _GROUP_TO_ROOT.items():
            if m.group(group_name) is not None:
                found.add(root)
                break
    return found


def _env_true(name: str, default: str = "true") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _finding_text(finding: dict | object) -> str:
    """Concatenate the message + evidence + remediation fields so the
    keyword scanner sees the full context."""
    if isinstance(finding, dict):
        parts = [
            str(finding.get("message", "") or ""),
            str(finding.get("evidence", "") or ""),
            str(finding.get("remediation", "") or ""),
        ]
    else:
        parts = [
            str(getattr(finding, "message", "") or ""),
            str(getattr(finding, "evidence", "") or ""),
            str(getattr(finding, "remediation", "") or ""),
        ]
    return " ".join(parts)


def _finding_host(finding: dict | object) -> str:
    if isinstance(finding, dict):
        return str(finding.get("host", "") or "")
    return str(getattr(finding, "host", "") or "")


def is_finding_applicable_general(finding: dict | object, *, tech_stack: set[str]) -> tuple[bool, str]:
    """Decide whether the finding's mentioned products apply to the
    target's tech stack. Works for ANY rule_id shape, not just CVE-XXXX.

    Returns ``(applicable, reason)``. Conservative defaults: empty
    stack or no product mention → pass.
    """
    if not _env_true("KRYON_FINDING_APPLICABILITY"):
        return True, "filter disabled via KRYON_FINDING_APPLICABILITY=false"

    text = _finding_text(finding)
    mentions = extract_product_mentions(text)
    if not mentions:
        return True, "no product mention in finding text — gate does not apply"

    # Authoritative host-hint when target is in the known-lab map.
    host = _finding_host(finding)
    host_hint = _target_tech_hint(host)
    effective_stack = host_hint if host_hint else set(tech_stack)
    if not effective_stack:
        return True, "no tech stack info — passing conservatively"

    # F183.B — match-wins on TECH keywords too. If the finding text
    # mentions tech that IS in the stack (e.g. "Express middleware
    # misconfig"), the finding belongs to the target even if it also
    # cites a wrong-stack product as the source. This protects legit
    # findings that name multiple things from over-aggressive drops.
    tech_in_text = extract_target_tech_stack(text)
    if tech_in_text & effective_stack:
        return True, (f"finding text mentions stack-compatible tech {sorted(tech_in_text & effective_stack)}")

    # Flatten keyword mentions to the canonical product names they map to.
    flat_products: list[str] = []
    for keyword in mentions:
        entry = _PRODUCT_KEYWORDS.get(keyword)
        if entry is None:
            flat_products.append(keyword)
        else:
            flat_products.extend(entry[1])

    # Match-wins: if ANY mentioned product overlaps the stack, pass.
    pseudo = CVEApplicability(cve_id="(implicit)", products=tuple(flat_products), description=text)
    ok, reason = is_cve_applicable(pseudo, effective_stack)
    if ok:
        return True, f"product match found: {reason}"
    return False, (
        f"finding mentions products {sorted(set(flat_products))} that don't "
        f"apply to detected stack {sorted(effective_stack)}"
    )
