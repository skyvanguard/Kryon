"""
semgrep_scan — @function_tool wrapper around the Semgrep CLI.

Semgrep is the industry-standard pattern scanner (Slack, Stripe, Firefox,
Mozilla, Snowflake, Snowflake use it in production). We clone the full
community ruleset (~2165 rules, MIT) to /workspace/.semgrep_rules/ and
run scans against that instead of the Semgrep Cloud registry — which is
auth-gated for most serious rules.

Returns JSON normalized to the Kryon planner's expectations:
  { count, rules_run, findings: [{path, start_line, end_line, check_id,
    severity, cwe, message, lines}] }
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)

# Defaults — overridable via env
_DEFAULT_RULES_ROOT = Path(os.environ.get(
    "KRYON_SEMGREP_RULES_DIR",
    "/workspace/.semgrep_rules/semgrep-rules",
))
# Kryon-curated rules (F6.1) tuned to Juliet BadSink templates.
# Loaded ALONGSIDE the upstream community ruleset, not instead of.
_KRYON_RULES_ROOT = Path(__file__).parent.parent.parent / "skills" / "patterns" / "semgrep"
_DEFAULT_SEMGREP_BIN = os.environ.get(
    "KRYON_SEMGREP_BIN",
    "/opt/venv/bin/semgrep",
)
_DEFAULT_TIMEOUT_S = int(os.environ.get("KRYON_SEMGREP_TIMEOUT_S", "300"))
_DEFAULT_MAX_FINDINGS = int(os.environ.get("KRYON_SEMGREP_MAX_FINDINGS", "200"))

# Preferred language-specific subdirs under semgrep-rules/ to load per-scan.
# Order matters — we try each and merge.
_LANG_DIRS = {
    "c": ["c", "trailofbits"],
    "cpp": ["c", "cpp", "trailofbits"],
    "python": ["python", "trailofbits"],
    "javascript": ["javascript", "typescript"],
    "go": ["go"],
    "java": ["java"],
    "php": ["php"],
    "ruby": ["ruby"],
    "rust": ["rust"],
    # "auto" scans everything relevant
    "auto": ["c", "cpp", "python", "javascript", "typescript", "go", "java",
             "generic", "trailofbits"],
}

# Rough file-extension → language map (for auto-detection on single-file scans)
_EXT_TO_LANG = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
}


def _detect_language(target: str) -> str:
    p = Path(target)
    if p.is_file():
        return _EXT_TO_LANG.get(p.suffix.lower(), "auto")
    return "auto"


def _rule_configs_for_lang(lang: str) -> list[str]:
    """Return --config flag values (absolute paths) for the language."""
    dirs = _LANG_DIRS.get(lang, _LANG_DIRS["auto"])
    configs: list[str] = []
    for d in dirs:
        p = _DEFAULT_RULES_ROOT / d
        if p.is_dir():
            configs.append(str(p))
    # Kryon custom rules (F6.1) — load FIRST so high-confidence rules
    # take precedence in any de-dup logic semgrep applies.
    kryon_dir = _KRYON_RULES_ROOT / lang
    if kryon_dir.is_dir():
        configs.insert(0, str(kryon_dir))
    return configs


def _extract_cwe(check_id: str, metadata: dict) -> str:
    """Pull the first CWE tag from the rule metadata, or empty string."""
    cwe_field = metadata.get("cwe") or metadata.get("cwe2022") or metadata.get("cwe2021")
    if isinstance(cwe_field, list) and cwe_field:
        return str(cwe_field[0]).split(":")[0].strip()
    if isinstance(cwe_field, str):
        return cwe_field.split(":")[0].strip()
    # Some rules embed CWE in the check_id itself
    if "cwe-" in check_id.lower():
        parts = [p for p in check_id.lower().split(".") if p.startswith("cwe-")]
        if parts:
            return parts[0].upper()
    return ""


def _extract_cwe_aliases(metadata: dict) -> list[str]:
    """Read `kryon_alias` from rule metadata — Kryon-curated rules declare
    which additional CWEs a finding should also count as (e.g. a rule
    flagging malloc(N*M) is primarily CWE-190 but also counts as CWE-122
    and CWE-787). Returns a normalised list of 'CWE-NNN' strings.

    Fix for the F8.0 plumbing bug: rule authors declared these aliases but
    the normalisation pipeline dropped them, causing bench recall@CWE to
    miss legitimate matches.
    """
    raw = metadata.get("kryon_alias") or metadata.get("kryon_aliases") or []
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for a in raw:
        s = str(a).split(":")[0].strip().upper()
        if s:
            out.append(s)
    return out


def _severity_to_confidence(severity: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
        (severity or "").upper(), "medium"
    )


def _normalize_finding(raw: dict) -> dict:
    """Emit a finding in the converged shape shared with joern_scan.

    `method` and `flow` are empty for pattern-based findings; they are
    populated by joern_scan for taint flows.
    """
    extra = raw.get("extra") or {}
    meta = extra.get("metadata") or {}
    severity = extra.get("severity", "")
    return {
        "path": raw.get("path", ""),
        "start_line": (raw.get("start") or {}).get("line", 0),
        "end_line": (raw.get("end") or {}).get("line", 0),
        "check_id": raw.get("check_id", ""),
        "rule_id": raw.get("check_id", "").split(".")[-1],
        "severity": severity,
        "confidence": _severity_to_confidence(severity),
        "cwe": _extract_cwe(raw.get("check_id", ""), meta),
        "cwe_aliases": _extract_cwe_aliases(meta),
        "message": (extra.get("message") or "").strip()[:500],
        "lines": (extra.get("lines") or "")[:1000],
        "method": "",
        "flow": [],
    }


def _semgrep_scan_impl(
    target_path: str,
    language: str = "",
    severity_min: str = "",
    max_findings: int = _DEFAULT_MAX_FINDINGS,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
) -> str:
    """Impl separated from the function_tool wrapper for tests."""
    target = Path(target_path)
    if not target.exists():
        return json.dumps({
            "status": "error",
            "reason": f"target not found: {target_path}",
            "count": 0, "findings": [],
        })
    if not Path(_DEFAULT_SEMGREP_BIN).is_file() and not shutil.which("semgrep"):
        return json.dumps({
            "status": "unavailable",
            "reason": f"semgrep binary not found at {_DEFAULT_SEMGREP_BIN}",
            "count": 0, "findings": [],
        })
    if not _DEFAULT_RULES_ROOT.is_dir():
        return json.dumps({
            "status": "unavailable",
            "reason": (
                f"semgrep rules dir missing: {_DEFAULT_RULES_ROOT}. "
                "Clone github.com/semgrep/semgrep-rules to that path."
            ),
            "count": 0, "findings": [],
        })

    lang = (language or _detect_language(target_path) or "auto").lower()
    configs = _rule_configs_for_lang(lang)
    if not configs:
        return json.dumps({
            "status": "error",
            "reason": f"no rule dirs resolved for language={lang!r}",
            "count": 0, "findings": [],
        })

    cmd: list[str] = [_DEFAULT_SEMGREP_BIN]
    for c in configs:
        cmd += ["--config", c]
    cmd += [
        "--no-git-ignore",
        "--json",
        "--quiet",
        "--timeout", str(timeout_s),
        "--disable-version-check",
        target_path,
    ]
    # Override HOME to a writable dir so the version-check cache doesn't fail
    env = {**os.environ, "HOME": "/tmp", "SEMGREP_VERSION_CHECK": "0"}

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_s + 30, check=False, env=env,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({
            "status": "timeout",
            "reason": f"semgrep timed out after {timeout_s}s",
            "count": 0, "findings": [],
        })

    if not r.stdout.strip():
        return json.dumps({
            "status": "error",
            "reason": "semgrep produced no output",
            "stderr": r.stderr[:500],
            "count": 0, "findings": [],
        })

    try:
        doc = json.loads(r.stdout)
    except json.JSONDecodeError:
        return json.dumps({
            "status": "error",
            "reason": "semgrep output was not JSON",
            "stderr": r.stderr[:500],
            "stdout_head": r.stdout[:300],
            "count": 0, "findings": [],
        })

    findings = [_normalize_finding(f) for f in (doc.get("results") or [])]

    # Severity filter
    sev_rank = {"INFO": 0, "WARNING": 1, "ERROR": 2}
    if severity_min:
        min_rank = sev_rank.get(severity_min.upper(), 0)
        findings = [
            f for f in findings if sev_rank.get(f["severity"].upper(), 0) >= min_rank
        ]

    # Cap
    findings = findings[:max_findings]

    return json.dumps({
        "status": "ok",
        "count": len(findings),
        "language": lang,
        "configs_used": configs,
        "target": target_path,
        "errors": len(doc.get("errors") or []),
        "findings": findings,
    }, indent=2)


@function_tool(strict_mode=False)
def semgrep_scan(
    target_path: str,
    language: str = "",
    severity_min: str = "",
    max_findings: int = 200,
    timeout_s: int = 300,
) -> str:
    """Run Semgrep against a file or directory, return structured findings.

    Semgrep uses industry-maintained CWE-labeled rules. Use this as the
    first pass in the hunter — it surfaces high-signal candidates quickly.
    Each finding includes path, line range, check_id, severity, CWE (if
    tagged), and the relevant source lines.

    Args:
        target_path: Absolute path to file or directory to scan.
        language: Optional ("c", "cpp", "python", "javascript", "go",
            "java", "php", "ruby", "rust", "auto"). Auto-detected from
            file extension when omitted.
        severity_min: "INFO" | "WARNING" | "ERROR" (empty = no filter).
        max_findings: Cap returned findings (default 200).
        timeout_s: Semgrep scan timeout (default 300).

    Returns JSON: {count, language, configs_used, findings:[...]}
    """
    return _semgrep_scan_impl(
        target_path=target_path,
        language=language,
        severity_min=severity_min,
        max_findings=max_findings,
        timeout_s=timeout_s,
    )
