"""Skill evaluator — gate auto-synthesized drafts against historical findings.

The question we answer: "If this auto-skill had existed during the last
N engagements, would it have surfaced the findings we already know
about?"

This is a heuristic check, not a real re-run. We ask:
  1. Filter the findings corpus to those whose tech overlaps the cluster.
  2. For each relevant finding, check whether the draft's chain contains
     at least one tool known to detect that CWE.
  3. Pass rate = detected / relevant. >= threshold → "passed".

Stance: precision over recall. We'd rather skip an inconclusive eval
than rubber-stamp a bad skill. If the relevant corpus is too small
(< `min_findings_evaluated`), we return `skipped` — the operator
reviews manually instead.

Why heuristic? Re-running the actual tools against historical hosts
isn't safe (some are external, some don't exist anymore, some auth
expired). The CWE→tools map is the cheap proxy.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Default mapping of CWE → tool names known to detect that class.
#
# IMPORTANT: tool names here MUST match Kryon's actual `@function_tool`
# registrations (the `name` attribute of the FunctionTool object). The
# evaluator compares these against the draft's `required_tools` list,
# which in turn comes from the cluster's chain of real tool calls.
#
# Conservative posture (precision > recall): leaving a CWE OFF the map
# makes findings of that class "skipped from denominator" instead of
# counted as failures. So the map errs toward listing only well-known
# detectors; CWEs we can't reliably detect with current tooling are
# intentionally absent.
#
# Override at runtime via:
#   - `cwe_to_tools=` kwarg on `evaluate_draft_against_corpus`
#   - Yaml file at `~/.kryon/cwe_map.yaml` (or path in `KRYON_CWE_MAP` env)
#     loaded by `load_cwe_map_override()`. The yaml shape is:
#         CWE-XXX:
#           - tool_name_a
#           - tool_name_b
#     File entries OVERRIDE defaults for the same CWE (no merging within
#     a CWE). New CWEs in the file extend the default map.
_DEFAULT_CWE_TO_TOOLS: dict[str, set[str]] = {
    # ---- OWASP Top 10 / web app ----
    "CWE-89": {  # SQL injection
        "sqlmap_scan",
        "sqlmap_request",
        "sqlmap_crawl",
        "validate_sqli",
        "nuclei_scan",
        "burp_active_scan",
        "zap_full_scan",
        "zap_baseline_scan",
    },
    "CWE-79": {  # XSS (reflected/stored)
        "validate_xss",
        "browser_test_xss",
        "nuclei_scan",
        "burp_active_scan",
        "zap_full_scan",
        "zap_baseline_scan",
    },
    "CWE-22": {  # path traversal / LFI
        "nuclei_scan",
        "feroxbuster_scan",
        "wfuzz",
        "burp_active_scan",
        "zap_full_scan",
    },
    "CWE-78": {  # OS command injection
        "nuclei_scan",
        "burp_active_scan",
        "zap_full_scan",
        "generate_injection_payloads",
    },
    "CWE-94": {  # generic code injection
        "nuclei_scan",
        "semgrep_scan",
        "joern_scan",
        "burp_active_scan",
        "generate_injection_payloads",
    },
    "CWE-918": {  # SSRF
        "nuclei_scan",
        "burp_active_scan",
        "fuzz_api_endpoint",
    },
    "CWE-352": {  # CSRF
        "burp_active_scan",
        "zap_full_scan",
        "nuclei_scan",
    },
    "CWE-611": {  # XXE
        "nuclei_scan",
        "burp_active_scan",
        "fuzz_api_endpoint",
        "zap_full_scan",
    },
    "CWE-434": {  # unrestricted upload
        "nuclei_scan",
        "burp_active_scan",
        "zap_full_scan",
        "fuzz_api_endpoint",
    },
    "CWE-502": {  # insecure deserialization
        "nuclei_scan",
        "burp_active_scan",
        "joern_scan",
        "semgrep_scan",
    },
    "CWE-200": {  # information exposure
        "whatweb_scan",
        "nuclei_scan",
        "crawl_web_target",
        "nmap",
        "feroxbuster_scan",
    },
    "CWE-693": {  # protection-mechanism failure (security headers etc)
        "nuclei_scan",
        "burp_active_scan",
        "zap_baseline_scan",
        "run_compliance_audit",
    },
    # CWE-1004 (missing HttpOnly / Secure on cookies) is intentionally NOT
    # in the default map — banking ops team should opt in via override
    # if they care, otherwise findings of that class skip the denominator.
    # ---- AuthN / AuthZ ----
    "CWE-287": {  # improper authentication / brute-forceable
        "hydra_attack",
        "medusa_attack",
        "credential_spray",
        "nuclei_scan",
        "burp_active_scan",
    },
    "CWE-307": {  # missing rate-limit / lockout
        "hydra_attack",
        "medusa_attack",
        "credential_spray",
        "burp_active_scan",
    },
    "CWE-639": {  # IDOR / BOLA — API authorization
        "discover_api_endpoints",
        "api_security_scan",
        "owasp_api_top",
        "fuzz_api_endpoint",
        "burp_active_scan",
    },
    "CWE-915": {  # mass-assignment (unsafe object property modification)
        "api_security_scan",
        "owasp_api_top",
        "fuzz_api_endpoint",
        "burp_active_scan",
    },
    "CWE-345": {  # JWT / token verification (insufficient signing checks)
        "jwt_decode",
        "jwt_forge",
        "jwt_crack",
        "nuclei_scan",
    },
    # ---- Network / TLS / config ----
    "CWE-319": {  # cleartext transmission
        "nmap",
        "nuclei_scan",
        "frida_intercept_ssl",
        "run_compliance_audit",
    },
    "CWE-326": {  # weak/inadequate crypto
        "nuclei_scan",
        "nmap",
        "run_compliance_audit",
    },
    "CWE-327": {  # broken / risky cryptographic algorithm
        "nuclei_scan",
        "nmap",
        "semgrep_scan",
        "joern_scan",
    },
    "CWE-295": {  # improper certificate validation
        "nmap",
        "nuclei_scan",
        "frida_intercept_ssl",
    },
    "CWE-732": {  # incorrect permission assignment
        "run_compliance_audit",
        "semgrep_scan",
    },
    # ---- Active Directory / lateral movement ----
    # Note: Kryon's AD playbooks expose dedicated tools — map AD-class
    # CWEs to those rather than to generic web scanners.
    "CWE-1390": {  # weak authentication in AD context (umbrella)
        "bloodhound_collect",
        "bas_ad_reconnaissance",
        "kerberoast",
        "asreproast",
        "dcsync_attack",
    },
    "CWE-264": {  # generic permission/privilege issues (AD ACLs etc)
        "bloodhound_collect",
        "bas_ad_reconnaissance",
        "dcsync_attack",
        "smb_lateral_movement",
        "rdp_lateral_movement",
    },
    # ---- Credentials / secrets ----
    "CWE-798": {  # use of hard-coded credentials
        "semgrep_scan",
        "joern_scan",
        "search_credential_dataset",
    },
    "CWE-256": {  # plaintext storage of credentials
        "semgrep_scan",
        "joern_scan",
        "search_credential_dataset",
    },
    "CWE-916": {  # password hashing without salt / weak hashing
        "semgrep_scan",
        "crack_ntlm_hash",
    },
    # ---- Supply chain / SBOM ----
    "CWE-1357": {  # reliance on insufficiently trustworthy component
        "scan_sbom_vulns",
        "check_typosquatting",
        "detect_dependency_confusion",
    },
    "CWE-829": {  # inclusion of functionality from untrusted control sphere
        "scan_sbom_vulns",
        "check_typosquatting",
        "detect_dependency_confusion",
        "semgrep_scan",
    },
    # ---- Wireless / 802.11 (Unifi audits) ----
    "CWE-1391": {  # use of weak credentials (covers WPA2 weak PSKs)
        "aircrack_capture",
        "aircrack_crack",
        "credential_spray",
        "hydra_attack",
    },
    # ---- API security (OWASP API Top 10) ----
    "CWE-285": {  # improper authorization
        "api_security_scan",
        "owasp_api_top",
        "discover_api_endpoints",
        "fuzz_api_endpoint",
        "burp_active_scan",
    },
    "CWE-862": {  # missing authorization
        "api_security_scan",
        "owasp_api_top",
        "discover_api_endpoints",
        "fuzz_api_endpoint",
    },
}


# Resolution order for the override file: explicit arg > env var > home dir.
_CWE_MAP_ENV = "KRYON_CWE_MAP"
_DEFAULT_CWE_MAP_FILENAME = "cwe_map.yaml"


def _resolve_override_path(explicit: str | Path | None) -> Path | None:
    """Pick the override file path, in this priority order:
       1. `explicit` argument
       2. KRYON_CWE_MAP env var
       3. <home>/.kryon/cwe_map.yaml (only if it exists)
    Returns None when nothing usable is found.
    """
    if explicit is not None:
        return Path(explicit)
    env_path = os.environ.get(_CWE_MAP_ENV, "").strip()
    if env_path:
        return Path(env_path)
    default = Path.home() / ".kryon" / _DEFAULT_CWE_MAP_FILENAME
    return default if default.is_file() else None


def load_cwe_map_override(
    path: str | Path | None = None,
) -> dict[str, set[str]]:
    """Build the effective CWE → tools map by overlaying a yaml file
    (when present) on top of `_DEFAULT_CWE_TO_TOOLS`.

    Yaml shape:
        CWE-89:
          - sqlmap_scan
          - my_internal_tool
        CWE-CUSTOM-1:
          - banking_grade_scanner

    Semantics:
      * For each CWE in the yaml, the file's tool list REPLACES the
        default for that CWE (no within-CWE union — the operator's
        team is the authority on what they trust).
      * CWEs absent from the yaml keep their default entries.
      * New CWEs in the yaml extend the map.

    All failure modes (missing file, unreadable yaml, wrong shape) fall
    back to the unchanged default map. The caller never gets an
    exception — eval pipeline must keep running.
    """
    merged: dict[str, set[str]] = {cwe: set(tools) for cwe, tools in _DEFAULT_CWE_TO_TOOLS.items()}

    file_path = _resolve_override_path(path)
    if file_path is None or not file_path.is_file():
        return merged

    try:
        import yaml  # PyYAML is in the base deps via transitives

        raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        logger.warning("cwe_map override load failed (%s): %s", file_path, e)
        return merged

    if not isinstance(raw, dict):
        # Empty file (None) or wrong top-level shape — keep defaults.
        if raw is None:
            return merged
        logger.warning(
            "cwe_map override at %s has wrong shape (expected dict, got %s) — ignoring",
            file_path,
            type(raw).__name__,
        )
        return merged

    for cwe, tools in raw.items():
        if not isinstance(tools, list):
            logger.warning(
                "cwe_map override: %s value must be a list of tool names — skipping",
                cwe,
            )
            continue
        # Coerce to set of strings; drop non-string items defensively.
        merged[str(cwe)] = {str(t) for t in tools if isinstance(t, str)}

    logger.debug("cwe_map override loaded from %s: %d CWEs", file_path, len(merged))
    return merged


@dataclass(frozen=True)
class EvalReport:
    """Result of evaluating a draft against the findings corpus."""

    cluster_id: str
    eval_status: str  # "passed" | "rejected" | "skipped" | "rejected_by_guide"
    findings_evaluated: int = 0
    findings_passed: int = 0
    pass_rate: float = 0.0
    reason: str = ""
    matched_findings: tuple[str, ...] = field(default_factory=tuple)
    # F77.G.4 — Guide score (relevance + naturalness). Populated when the
    # caller requests `apply_guide_gate=True`. None when the gate didn't
    # run (off by default — banking-safe rollout).
    guide_score: dict[str, Any] | None = None


def _profile_tech(profile: dict[str, Any]) -> set[str]:
    return {t.lower() for t in (profile.get("tech") or [])}


def _finding_tech(finding: dict[str, Any]) -> set[str]:
    """Pull tech tokens from the finding's tech_fingerprint string."""
    raw = (finding.get("tech_fingerprint") or "").lower()
    if not raw:
        return set()
    # Tech_fingerprint is a free-form string like "php/laravel mysql".
    # Split on common delimiters and trim.
    tokens = set()
    for token in raw.replace(",", " ").replace("/", " ").split():
        tokens.add(token.strip())
    return {t for t in tokens if t}


def _profiles_overlap(cluster_tech: set[str], finding_tech: set[str]) -> bool:
    """Profile match rule — at least one shared tech token, OR cluster
    has no tech (matches everything). Empty finding tech also matches
    (we don't penalize fragmented historical data)."""
    if not cluster_tech:
        return True
    if not finding_tech:
        return True
    return bool(cluster_tech & finding_tech)


def _relevant_findings(findings: list[dict[str, Any]], cluster_profile: dict[str, Any]) -> list[dict[str, Any]]:
    """Filter to findings whose tech overlaps the cluster's profile."""
    cluster_tech = _profile_tech(cluster_profile)
    return [f for f in findings if _profiles_overlap(cluster_tech, _finding_tech(f))]


def _is_finding_detectable(
    finding: dict[str, Any],
    chain_tools: set[str],
    cwe_to_tools: dict[str, set[str]],
) -> bool | None:
    """Return True/False if we can decide, or None when CWE is unmapped.

    Unmapped CWEs are SKIPPED (not False). Mapping in only what we trust
    keeps the precision-over-recall posture: ambiguity becomes "don't
    count" rather than "fail".
    """
    cwe = (finding.get("cwe_id") or "").upper()
    if cwe not in cwe_to_tools:
        return None
    detecting = cwe_to_tools[cwe]
    return bool(detecting & chain_tools)


def _guide_gate_enabled() -> bool:
    """F77.G.4 — `KRYON_GUIDE_GATE=true` enables the Guide axis. Off by
    default during the banking-safe rollout (Fase 4 flips this once we
    have empirical false-positive numbers from real drafts)."""
    return os.environ.get("KRYON_GUIDE_GATE", "").lower() in ("1", "true", "yes")


def _guide_threshold() -> float:
    """`KRYON_GUIDE_THRESHOLD` overrides the default 0.6 cutoff."""
    raw = os.environ.get("KRYON_GUIDE_THRESHOLD", "")
    if not raw:
        from kryon.learning.guide_scorer import GUIDE_DEFAULT_THRESHOLD

        return GUIDE_DEFAULT_THRESHOLD
    try:
        return float(raw)
    except ValueError:
        logger.warning("Invalid KRYON_GUIDE_THRESHOLD=%r — falling back to default", raw)
        from kryon.learning.guide_scorer import GUIDE_DEFAULT_THRESHOLD

        return GUIDE_DEFAULT_THRESHOLD


def evaluate_draft_against_corpus(
    *,
    draft: Any,
    cluster: Any,
    findings: list[dict[str, Any]],
    min_pass_rate: float = 0.7,
    min_findings_evaluated: int = 3,
    cwe_to_tools: dict[str, set[str]] | None = None,
    apply_guide_gate: bool | None = None,
) -> EvalReport:
    """Heuristic evaluation of a draft against a findings corpus.

    Args:
        draft: SkillDraft (carries the chain via required_tools).
        cluster: ChainCluster (carries the profile to match findings against).
        findings: list of finding dicts (same shape `findings_library`
            stores). The caller supplies — we never read chromadb here.
        min_pass_rate: minimum detected/relevant ratio for `passed`.
        min_findings_evaluated: minimum relevant + decidable findings
            before we draw a conclusion. Below this → skipped.
        cwe_to_tools: optional override of the CWE → detection-tools
            map. When None, the default banking-conservative map applies.
        apply_guide_gate: When True, run the F77.G.4 Guide score
            (relevance + naturalness) BEFORE the technical eval. A draft
            that fails the Guide is rejected with status
            `rejected_by_guide` and the technical eval is skipped (cheap
            short-circuit). When None, falls back to the
            `KRYON_GUIDE_GATE` env flag.

    Returns:
        EvalReport with one of
        {passed, rejected, skipped, rejected_by_guide}.
    """
    # F77.G.4 — Guide gate runs FIRST. Cheap (stdlib heuristics, no I/O).
    # If a draft is textually broken, no point in walking findings.
    use_guide = apply_guide_gate if apply_guide_gate is not None else _guide_gate_enabled()
    if use_guide:
        from kryon.learning.guide_scorer import score_draft

        guide = score_draft(draft)
        guide_payload = {
            "relevance": guide.relevance,
            "naturalness": guide.naturalness,
            "combined": guide.combined,
            "reasons": list(guide.reasons),
        }
        if not guide.passes(_guide_threshold()):
            return EvalReport(
                cluster_id=cluster.cluster_id,
                eval_status="rejected_by_guide",
                reason=(
                    f"Guide score {guide.combined:.2f} below threshold "
                    f"{_guide_threshold():.2f} "
                    f"(relevance={guide.relevance:.2f}, "
                    f"naturalness={guide.naturalness:.2f}). "
                    "Fix the draft text before promoting."
                ),
                guide_score=guide_payload,
            )
    else:
        guide_payload = None

    if cwe_to_tools is not None:
        # Explicit caller intent — bypass any file override.
        eff_map = dict(cwe_to_tools)
    else:
        # Default + optional yaml override (~/.kryon/cwe_map.yaml or env).
        eff_map = load_cwe_map_override()
    chain_tools = {t.lower() for t in (draft.frontmatter.get("required_tools") or [])}

    relevant = _relevant_findings(findings, cluster.representative_profile)
    if not relevant:
        return EvalReport(
            cluster_id=cluster.cluster_id,
            eval_status="skipped",
            reason=(
                "Findings corpus empty or none match the cluster's tech "
                "profile. Insufficient signal to draw a conclusion."
            ),
            guide_score=guide_payload,
        )

    # Walk relevant findings, classify each.
    decided: list[tuple[dict, bool]] = []
    for f in relevant:
        ok = _is_finding_detectable(f, chain_tools, eff_map)
        if ok is None:
            continue  # unmapped CWE — skip from denominator
        decided.append((f, ok))

    if len(decided) < min_findings_evaluated:
        return EvalReport(
            cluster_id=cluster.cluster_id,
            eval_status="skipped",
            findings_evaluated=len(decided),
            reason=(
                f"Only {len(decided)} relevant + classifiable findings "
                f"(need >= {min_findings_evaluated}). Insufficient corpus."
            ),
            guide_score=guide_payload,
        )

    passed_count = sum(1 for _, ok in decided if ok)
    total = len(decided)
    rate = passed_count / total

    matched_ids = tuple(f.get("id", "") for f, ok in decided if ok)

    if rate >= min_pass_rate:
        return EvalReport(
            cluster_id=cluster.cluster_id,
            eval_status="passed",
            findings_evaluated=total,
            findings_passed=passed_count,
            pass_rate=rate,
            reason=(
                f"Chain detected {passed_count}/{total} relevant findings "
                f"({rate * 100:.1f}% >= {min_pass_rate * 100:.1f}% threshold)."
            ),
            matched_findings=matched_ids,
            guide_score=guide_payload,
        )

    return EvalReport(
        cluster_id=cluster.cluster_id,
        eval_status="rejected",
        findings_evaluated=total,
        findings_passed=passed_count,
        pass_rate=rate,
        reason=(
            f"Chain detected only {passed_count}/{total} relevant findings "
            f"({rate * 100:.1f}% < {min_pass_rate * 100:.1f}% threshold). "
            f"Add detection tools (sqlmap, burp, etc.) before promoting."
        ),
        matched_findings=matched_ids,
        guide_score=guide_payload,
    )
