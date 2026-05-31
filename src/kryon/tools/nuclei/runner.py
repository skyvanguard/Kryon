"""F110 — Nuclei CLI wrapper.

Detects `nuclei` on PATH, runs it with a banca-safe profile (subset
of tags by default, explicit timeout, rate-limit, retries), parses
its JSONL output, and returns NucleiFinding records that map cleanly
onto the UnifiedFinding shape used by the F109 pipeline.

**Banca-safety contract**:
  - Default tag allowlist: `tech,exposure,misconfig,cve,xss,sqli,rce`
    but with `-severity` capped at `medium,high,critical` by default
    (the info-level firehose is opt-in).
  - Default `-no-interactsh` (no out-of-band callback server).
  - Default rate limit 30 req/s and concurrency 25 (nuclei defaults
    are much higher).
  - Templates path is controlled by the `templates_path` option;
    operator can pin to a vetted directory.
  - **No** `-headless` (browser-based templates) by default.
  - **No** custom code templates (`-code`) — operator must opt in
    explicitly via `enable_code_templates=True`.

If `nuclei` binary isn't on PATH, `is_nuclei_available()` returns
False and `run_nuclei()` returns a result with `nuclei_missing=True`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field

__all__ = [
    "NuclieConfig",
    "NucleiFinding",
    "NucleiResult",
    "is_nuclei_available",
    "run_nuclei",
    "parse_nuclei_jsonl",
    "severity_normalize",
]


# Nuclei severity strings → our normalized scale.
_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informative": "INFO",
    "unknown": "INFO",
}


def severity_normalize(s: str) -> str:
    return _SEVERITY_MAP.get((s or "").strip().lower(), "INFO")


@dataclass(frozen=True)
class NuclieConfig:
    """Banca-safe Nuclei invocation profile."""

    targets: tuple[str, ...]
    nuclei_binary: str = "nuclei"
    templates_path: str = ""  # empty = use nuclei's default install
    tags: tuple[str, ...] = (
        "tech",
        "exposure",
        "misconfig",
        "cve",
        "xss",
        "sqli",
        "rce",
        "ssrf",
        "lfi",
        "xxe",
    )
    severities: tuple[str, ...] = ("medium", "high", "critical")
    rate_limit_per_second: int = 30
    bulk_size: int = 25
    concurrency: int = 25
    timeout_seconds: int = 5  # per-request timeout
    overall_timeout_seconds: int = 300  # whole-run wall-clock
    no_interactsh: bool = True
    enable_code_templates: bool = False
    enable_headless: bool = False
    silent: bool = True
    follow_redirects: bool = False
    auth_header: str = ""  # e.g. "Authorization: Bearer xxx"
    user_agent: str = "Kryon-Nuclei/1.0 (banca-safe)"
    extra_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class NucleiFinding:
    template_id: str
    name: str
    severity: str  # normalized (CRITICAL/HIGH/.../INFO)
    nuclei_severity: str  # original from nuclei
    matched_at: str  # the URL that triggered
    target: str
    description: str = ""
    reference: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    matcher_name: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    raw_event: str = ""  # JSON-encoded original (for forensics)


@dataclass(frozen=True)
class NucleiResult:
    findings: tuple[NucleiFinding, ...] = field(default_factory=tuple)
    elapsed_seconds: float = 0.0
    nuclei_missing: bool = False
    exit_code: int = 0
    stdout_truncated: bool = False
    stderr_excerpt: str = ""  # last ~1k of stderr, for debug
    command: str = ""


def is_nuclei_available(binary: str = "nuclei") -> bool:
    """True if the named binary is on PATH."""
    return shutil.which(binary) is not None


def _build_args(cfg: NuclieConfig, targets_file: str | None) -> list[str]:
    args: list[str] = [cfg.nuclei_binary, "-jsonl", "-disable-update-check"]
    if cfg.silent:
        args.append("-silent")
    if cfg.no_interactsh:
        args.append("-no-interactsh")
    if not cfg.enable_code_templates:
        # Nuclei flag to disable code-protocol templates is "-disable-clustering"?
        # The dedicated flag varies between versions; the safer path is to
        # restrict by tag/template path. We add `-exclude-tags=code` defensively.
        args.extend(["-exclude-tags", "code,headless,fuzz,unsafe,dos"])
    if cfg.enable_headless:
        args.append("-headless")
    if cfg.follow_redirects:
        args.append("-follow-redirects")
    if cfg.templates_path:
        args.extend(["-t", cfg.templates_path])
    if cfg.tags:
        args.extend(["-tags", ",".join(cfg.tags)])
    if cfg.severities:
        args.extend(["-severity", ",".join(cfg.severities)])
    args.extend(["-rate-limit", str(cfg.rate_limit_per_second)])
    args.extend(["-bulk-size", str(cfg.bulk_size)])
    args.extend(["-concurrency", str(cfg.concurrency)])
    args.extend(["-timeout", str(cfg.timeout_seconds)])
    if cfg.user_agent:
        args.extend(["-H", f"User-Agent: {cfg.user_agent}"])
    if cfg.auth_header:
        args.extend(["-H", cfg.auth_header])
    if targets_file:
        args.extend(["-l", targets_file])
    else:
        for t in cfg.targets:
            args.extend(["-u", t])
    args.extend(cfg.extra_args)
    return args


def parse_nuclei_jsonl(stdout: str) -> list[NucleiFinding]:
    """Parse Nuclei's `-jsonl` output (one JSON event per line) into
    NucleiFinding records. Skips malformed lines silently."""
    findings: list[NucleiFinding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(evt, dict):
            continue
        info = evt.get("info") or {}
        classification = info.get("classification") or {}

        template_id = str(evt.get("template-id") or evt.get("template_id") or "")
        name = str(info.get("name") or "")
        nuclei_sev = str(info.get("severity") or "info").lower()
        sev = severity_normalize(nuclei_sev)
        matched_at = str(evt.get("matched-at") or evt.get("matched_at") or "")
        host = str(evt.get("host") or "")
        # Tags can be a list OR a comma-separated string
        raw_tags = info.get("tags")
        if isinstance(raw_tags, str):
            tags = tuple(t.strip() for t in raw_tags.split(",") if t.strip())
        elif isinstance(raw_tags, list):
            tags = tuple(str(t) for t in raw_tags)
        else:
            tags = ()
        refs_raw = info.get("reference")
        if isinstance(refs_raw, str):
            references = (refs_raw,)
        elif isinstance(refs_raw, list):
            references = tuple(str(r) for r in refs_raw)
        else:
            references = ()
        cve_ids = classification.get("cve-id") or classification.get("cve_id")
        if isinstance(cve_ids, list) and cve_ids:
            cve = str(cve_ids[0])
        elif isinstance(cve_ids, str):
            cve = cve_ids
        else:
            cve = ""
        cvss = classification.get("cvss-score") or classification.get("cvss_score") or 0.0
        try:
            cvss_score = float(cvss) if cvss not in (None, "") else 0.0
        except (TypeError, ValueError):
            cvss_score = 0.0

        findings.append(
            NucleiFinding(
                template_id=template_id,
                name=name,
                severity=sev,
                nuclei_severity=nuclei_sev,
                matched_at=matched_at,
                target=host or matched_at,
                description=str(info.get("description") or ""),
                reference=references,
                tags=tags,
                matcher_name=str(evt.get("matcher-name") or evt.get("matcher_name") or ""),
                cve_id=cve,
                cvss_score=cvss_score,
                raw_event=line,
            )
        )
    return findings


def run_nuclei(config: NuclieConfig) -> NucleiResult:
    """Spawn nuclei, capture its JSONL stdout, return parsed findings.

    Never raises — every failure mode produces a NucleiResult with
    appropriate flags."""
    if not is_nuclei_available(config.nuclei_binary):
        return NucleiResult(nuclei_missing=True, exit_code=-1)
    if not config.targets:
        return NucleiResult(exit_code=-2, stderr_excerpt="no targets")

    args = _build_args(config, targets_file=None)
    cmd_str = " ".join(args)
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=config.overall_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return NucleiResult(
            elapsed_seconds=time.monotonic() - t0,
            exit_code=-3,
            stderr_excerpt=(e.stderr or "")[-1000:] if hasattr(e, "stderr") else "timeout",
            command=cmd_str,
        )
    except (FileNotFoundError, PermissionError) as e:
        return NucleiResult(
            nuclei_missing=True,
            exit_code=-4,
            stderr_excerpt=str(e),
            command=cmd_str,
        )
    findings = parse_nuclei_jsonl(proc.stdout or "")
    elapsed = time.monotonic() - t0
    from kryon.util.severity import SEVERITY_RANK as severity_order
    findings.sort(
        key=lambda f: (
            severity_order.get(f.severity, 99),
            f.template_id,
            f.target,
        )
    )
    return NucleiResult(
        findings=tuple(findings),
        elapsed_seconds=elapsed,
        exit_code=proc.returncode,
        stderr_excerpt=(proc.stderr or "")[-1000:],
        command=cmd_str,
    )
