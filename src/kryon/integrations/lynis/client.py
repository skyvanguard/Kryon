"""Runner for Lynis (CISOfy) host audits.

Lynis is GPL-3.0, so — like OpenVAS — Kryon invokes it at arm's length
(subprocess / SSH exec), never modifying or importing it. Lynis is *host-local*:
it audits the box it runs on, so a remote audit means running it ON the target
over SSH (the target must have `lynis` installed). The transport is behind an
injectable ``runner`` so this is unit-testable without Lynis.

Lynis writes a machine-readable report to a `.dat` file (key=value); we run the
audit and read that file back in one command.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable

_DEFAULT_REPORT = "/tmp/kryon-lynis.dat"  # noqa: S108 — ephemeral report path on the audited host


class LynisError(RuntimeError):
    """Lynis could not be run, or produced no parseable report."""


def lynis_cmd(report_path: str = _DEFAULT_REPORT) -> str:
    """Shell command: run a quick system audit, then emit the report.dat."""
    return (
        f"lynis audit system --quick --no-colors --auditor kryon "
        f"--report-file {report_path} >/dev/null 2>&1; cat {report_path} 2>/dev/null"
    )


def _local_runner(timeout_s: int) -> Callable[[str], str]:
    def run(cmd: str) -> str:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_s)  # noqa: S602
        return proc.stdout or ""

    return run


def run_audit(
    *, runner: Callable[[str], str] | None = None, report_path: str = _DEFAULT_REPORT, timeout_s: int = 600
) -> str:
    """Run a Lynis audit and return the raw report.dat content.

    ``runner`` (command → stdout) is injectable; the caller wires the transport
    (SSH via the compliance runner, or local). Raises LynisError if no report
    was produced (lynis missing on the target, or the run failed).
    """
    cmd = lynis_cmd(report_path)
    run = runner or _local_runner(timeout_s)
    try:
        out = run(cmd)
    except subprocess.TimeoutExpired as exc:
        raise LynisError(f"lynis timed out after {timeout_s}s") from exc
    except Exception as exc:  # noqa: BLE001 — normalize any transport failure
        raise LynisError(f"lynis run failed: {exc}") from exc

    if "lynis_version" not in out and "lynis_report_version" not in out:
        raise LynisError("no Lynis report produced (is lynis installed on the target?)")
    return out
