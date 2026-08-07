"""Finding aggregation / dedup — the layer that turns N scanners into one
prioritized findings set.

Multiple engines (OpenVAS, Cinc, Lynis, Nuclei, Kryon's own checks) report
overlapping findings: the same CVE on the same host from two tools, or the same
control re-run. This module collapses **exact** duplicates and rewards
cross-engine corroboration with higher confidence — without fuzzy-merging
*distinct* weaknesses (that would hide findings).

Dedup key (deliberately strong / conservative):
* If a CVE id is present (rule_id or message) → ``("cve", host, CVE-ID)``.
* Otherwise → ``("rule", host, rule_id)``.

Same-CWE / same-topic clustering across engines is intentionally NOT a merge
key — it's left for a presentation-layer grouping so nothing is destroyed.

Corroboration: when a group is confirmed by ≥2 raw detections, the merged
finding's confidence is bumped and needs_verification is cleared — independent
engines agreeing is real signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from kryon.cli.engage import Finding, make_finding

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)

# rule_id prefix → source engine (for provenance display).
_SOURCE_PREFIXES = {
    "LYNIS-": "lynis",
    "CINC-": "cinc",
    "OPENVAS-": "openvas",
}
# Kryon's own deterministic check families.
_NATIVE_PREFIXES = (
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
    "FGT-",
    "UNF-",
    "PVE-",
    "TOMCAT-",
    "VOIP-",
    "IIS-",
    "CADDY-",
)

_EVIDENCE_CAP = 2400


@dataclass(frozen=True)
class AggregatedFinding:
    """A merged finding plus its provenance across engines."""

    finding: Finding
    sources: tuple[str, ...]
    corroboration: int  # how many raw findings collapsed into this one
    raw_rule_ids: tuple[str, ...]


def source_of(finding: Finding) -> str:
    """Engine attribution. Prefers the finding's explicit ``source`` (set by the
    integration normalizers), falling back to rule_id-prefix inference.

    The explicit source is what makes CVE corroboration accurate — two engines
    reporting the same CVE have identical rule_ids, so only the carried source
    tells them apart.
    """
    explicit = getattr(finding, "source", "") or ""
    if explicit.strip():
        return explicit.strip()
    rid = (finding.rule_id or "").upper()
    for pfx, name in _SOURCE_PREFIXES.items():
        if rid.startswith(pfx):
            return name
    if rid.startswith(_NATIVE_PREFIXES):
        return "kryon-native"
    if _CVE_RE.match(rid):
        return "cve-scan"
    return "kryon"


def dedup_key(finding: Finding) -> tuple:
    """Strong, conservative dedup key. Same CVE on a host, or same rule_id (+url)."""
    host = finding.host or ""
    m = _CVE_RE.search(finding.rule_id or "") or _CVE_RE.search(finding.message or "")
    if m:
        return ("cve", host, m.group(0).upper())
    # T3-A13: include the url/param for non-CVE web findings. Web probe ids are static
    # per vuln class (probe_lfi, probe_xss_reflected…), so without the url N distinct
    # instances (3 XSS in 3 different forms) collapsed into 1 and the others were
    # destroyed. Host-level compliance findings have no url → key is unchanged.
    url = getattr(finding, "url", "") or ""
    if url:
        return ("rule", host, finding.rule_id or "", url)
    rid = finding.rule_id or ""
    # A generic LLM rule_id ("agent-finding" default / empty) on the same host would
    # collapse DISTINCT findings (an IDOR and a stored-XSS both default-tagged) into one,
    # destroying N-1. Discriminate by the (truncated) message so distinct LLM findings
    # survive; a specific real rule_id (a check id) still dedups by rule_id as before.
    if not rid or rid == "agent-finding":
        return ("rule", host, rid, (finding.message or "")[:120])
    return ("rule", host, rid)


def _merge(group: list[Finding], *, sources: tuple[str, ...] | None = None) -> AggregatedFinding:
    rep = min(group, key=lambda f: f.severity_rank)  # highest-severity representative
    srcs = sources if sources is not None else tuple(sorted({source_of(f) for f in group}))
    corroboration = len(group)

    confidence = max((f.confidence for f in group), default=rep.confidence)
    # Corroboration = agreement across DISTINCT engines (not merely N raw hits —
    # one engine emitting a dup must not fake corroboration).
    corroborated = len(srcs) >= 2
    if corroborated:
        confidence = min(1.0, confidence + 0.15)
    # Trust it without verification when independent engines corroborate it.
    needs_verification = all(f.needs_verification for f in group) and not corroborated

    # F210 — preserve the verification_level across the merge (make_finding would
    # otherwise reset it to the "confirmed" default, silently flattening every
    # inferred/heuristic finding to ground truth and defeating the anti-FP layer).
    # The merged level is the MOST CONFIDENT band present (best evidence wins:
    # a real probe corroborating a banner → confirmed). Corroboration boosts the
    # numeric confidence but does NOT promote the cap — two spoofable banners must
    # not become "confirmed". A finding below confirmed always needs verification.
    from kryon.scoring.confidence import _VERIFICATION_BANDS  # noqa: PLC0415

    levels = [getattr(f, "verification_level", "confirmed") or "confirmed" for f in group]
    merged_level = max(levels, key=lambda lv: _VERIFICATION_BANDS.get(lv, 1.0))
    if merged_level != "confirmed":
        needs_verification = True
        # The level caps confidence — the corroboration bonus must not push a
        # banner-only finding above its inferred/heuristic ceiling.
        confidence = min(confidence, _VERIFICATION_BANDS.get(merged_level, 1.0))

    evidence = " | ".join(dict.fromkeys(f.evidence for f in group if f.evidence))[:_EVIDENCE_CAP]
    remediation = next((f.remediation for f in group if f.remediation), "")
    suffix = f" [corroborado por {len(srcs)} fuentes: {', '.join(srcs)}]" if len(srcs) > 1 else ""

    merged = make_finding(
        cwe=rep.cwe,
        severity=rep.severity,
        host=rep.host,
        rule_id=rep.rule_id,
        message=(rep.message or rep.rule_id) + suffix,
        evidence=evidence or rep.evidence,
        remediation=remediation,
        remediation_command=rep.remediation_command,
        target_host=rep.target_host,
        confidence=confidence,
        needs_verification=needs_verification,
        verification_level=merged_level,
    )
    return AggregatedFinding(
        finding=merged,
        sources=srcs,
        corroboration=corroboration,
        raw_rule_ids=tuple(sorted({f.rule_id for f in group})),
    )


def _sorted(aggs: list[AggregatedFinding]) -> list[AggregatedFinding]:
    return sorted(aggs, key=lambda a: (a.finding.severity_rank, a.finding.host, a.finding.rule_id))


def aggregate(findings: list[Finding]) -> list[AggregatedFinding]:
    """Dedup a flat finding list (source derived from rule_id prefix)."""
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        groups.setdefault(dedup_key(f), []).append(f)
    return _sorted([_merge(g) for g in groups.values()])


def aggregate_sources(labeled: list[tuple[str, list[Finding]]]) -> list[AggregatedFinding]:
    """Dedup across source-labeled groups — accurate provenance even for CVEs."""
    tagged: dict[tuple, list[tuple[str, Finding]]] = {}
    for src, fs in labeled:
        for f in fs:
            tagged.setdefault(dedup_key(f), []).append((src, f))
    out: list[AggregatedFinding] = []
    for grp in tagged.values():
        srcs = tuple(sorted({s for s, _f in grp}))
        out.append(_merge([f for _s, f in grp], sources=srcs))
    return _sorted(out)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drop-in for a Finding list → deduped Finding list (provenance in message)."""
    return [a.finding for a in aggregate(findings)]
