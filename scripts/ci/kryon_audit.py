"""F89.2 / F89.3 — CI entrypoint: findings JSON → SARIF + gate.

Usage:
  python -m scripts.ci.kryon_audit \
      --findings findings.json \
      --sarif-out kryon.sarif \
      --fail-on high

Exit codes:
  0  — no findings at or above the gate threshold.
  1  — gate failed; at least one finding meets `--fail-on`.
  2  — input error (missing file, malformed JSON).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from kryon.reporting.sarif import write_sarif


__all__ = [
    "SEVERITY_ORDER",
    "severity_rank",
    "filter_failing",
    "summarize_findings",
    "write_github_outputs",
    "main",
]


# Ordered low → high. Index doubles as the rank for comparisons.
# Anything not in the list (e.g. "trivial", custom labels) ranks at
# -1 and never triggers the gate — defensive default.
SEVERITY_ORDER: list[str] = ["info", "low", "medium", "high", "critical"]


def severity_rank(severity: str) -> int:
    """Map a severity string to its ordinal rank. Case-insensitive,
    whitespace-tolerant. Unknown values return -1 (never gates)."""
    if not isinstance(severity, str):
        return -1
    cleaned = severity.strip().lower()
    try:
        return SEVERITY_ORDER.index(cleaned)
    except ValueError:
        return -1


def filter_failing(
    findings: list[dict[str, Any]],
    fail_on: str,
) -> list[dict[str, Any]]:
    """Return findings whose severity rank >= the gate threshold.

    `fail_on` is itself parsed with severity_rank — operators can
    pass "high", "HIGH", "  Medium  ", etc. An unparseable
    `fail_on` returns an empty list (the gate is effectively
    disabled — better than crashing the build with an obscure
    config error)."""
    threshold = severity_rank(fail_on)
    if threshold < 0:
        return []
    return [
        f
        for f in findings
        if severity_rank(str(f.get("severity") or "")) >= threshold
    ]


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Bucket findings by severity. Always returns the canonical five
    keys (info / low / medium / high / critical) so CI step output
    consumers don't have to guess which buckets are missing."""
    counts: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
    counts["unknown"] = 0
    for f in findings:
        severity = str(f.get("severity") or "").strip().lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["unknown"] += 1
    return counts


def _set_github_output(name: str, value: str, output_file: Path | None) -> None:
    """Write one `name=value` row to $GITHUB_OUTPUT if set, else fall
    back to the legacy `::set-output::` annotation for older runners."""
    if output_file is not None:
        with output_file.open("a", encoding="utf-8") as fh:
            # GitHub's official spec: name=value (or multiline with
            # delimiter); single-line is enough for our values.
            fh.write(f"{name}={value}\n")
    else:
        # Fallback for runners pre-2023-06-13. Still works on
        # self-hosted runners that haven't upgraded.
        print(f"::set-output name={name}::{value}", flush=True)


def write_github_outputs(
    *,
    sarif_path: Path,
    findings: list[dict[str, Any]],
    failing: list[dict[str, Any]],
    output_file_env: str = "GITHUB_OUTPUT",
) -> None:
    """Emit the four standard outputs the action.yml advertises.

    The values must be JSON-safe (no newlines) so the GitHub Actions
    runner doesn't choke on multi-line output without a delimiter.
    """
    output_path_env = os.environ.get(output_file_env)
    output_file = Path(output_path_env) if output_path_env else None

    summary = summarize_findings(findings)
    _set_github_output("sarif-path", str(sarif_path), output_file)
    _set_github_output("findings-count", str(len(findings)), output_file)
    _set_github_output("critical-count", str(summary["critical"]), output_file)
    _set_github_output("failing-count", str(len(failing)), output_file)


def _load_findings(path: Path) -> list[dict[str, Any]]:
    """Load + validate findings JSON. Accepts a top-level list OR a
    `{"findings": [...]}` envelope (the kryon engage CLI emits the
    latter shape — supporting both keeps the CI flexible).
    """
    if not path.is_file():
        raise FileNotFoundError(f"findings file not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        findings = raw
    elif isinstance(raw, dict) and isinstance(raw.get("findings"), list):
        findings = raw["findings"]
    else:
        raise ValueError("findings JSON must be a list or {'findings': [...]} envelope")
    # Soft-validate each entry — drop non-dicts, never raise.
    return [f for f in findings if isinstance(f, dict)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="F89.2 — CI entrypoint: findings JSON → SARIF + severity gate.",
    )
    parser.add_argument(
        "--findings",
        required=True,
        help="Path to the findings JSON (list or {'findings':[...]} envelope).",
    )
    parser.add_argument(
        "--sarif-out",
        default="kryon.sarif",
        help="Path to write the SARIF 2.1.0 output (default: kryon.sarif).",
    )
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=[*SEVERITY_ORDER, "never"],
        help=(
            "Gate threshold. Build fails when any finding meets/exceeds this severity. "
            "'never' disables the gate. Default: high."
        ),
    )
    parser.add_argument(
        "--include-evidence",
        action="store_true",
        help=(
            "Surface finding.evidence into SARIF result.message.markdown. "
            "DEFAULT OFF — banca-safety: evidence may carry token/PAN fragments."
        ),
    )
    parser.add_argument(
        "--tool-version",
        default="2.1.0",
        help="Version string surfaced in the SARIF tool driver block.",
    )
    parser.add_argument(
        "--engagement-id",
        default="",
        help="Optional engagement id stamped into SARIF run.properties.",
    )
    parser.add_argument(
        "--client",
        default="",
        help="Optional client name stamped into SARIF run.properties.",
    )
    args = parser.parse_args(argv)

    try:
        findings = _load_findings(Path(args.findings))
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except (json.JSONDecodeError, ValueError) as e:
        print(f"ERROR: invalid findings JSON — {e}", file=sys.stderr)
        return 2

    run_metadata: dict[str, Any] = {}
    if args.engagement_id:
        run_metadata["engagement_id"] = args.engagement_id
    if args.client:
        run_metadata["client"] = args.client

    sarif_path = write_sarif(
        findings,
        Path(args.sarif_out),
        tool_version=args.tool_version,
        include_evidence=args.include_evidence,
        run_metadata=run_metadata or None,
    )

    # Gate evaluation.
    if args.fail_on == "never":
        failing: list[dict[str, Any]] = []
    else:
        failing = filter_failing(findings, args.fail_on)

    write_github_outputs(
        sarif_path=sarif_path,
        findings=findings,
        failing=failing,
    )

    # Human-readable summary on stderr — never crashes CI parsers.
    summary = summarize_findings(findings)
    print(
        f"Kryon CI gate: {len(findings)} findings "
        f"(critical={summary['critical']} high={summary['high']} "
        f"medium={summary['medium']} low={summary['low']} info={summary['info']}). "
        f"Gate '{args.fail_on}' → {len(failing)} failing.",
        file=sys.stderr,
    )
    print(f"SARIF written to {sarif_path}", file=sys.stderr)

    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
