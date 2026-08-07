"""Runner for Cinc Auditor (the FOSS build of InSpec).

Cinc Auditor is Apache-2.0 — no copyleft, unlike OpenVAS. We still invoke it as
a subprocess (it's a CLI that does its OWN transport: ssh://, winrm://,
docker://, local://), so Kryon just orchestrates it. Use the ``cinc-auditor``
binary, NOT ``inspec`` (InSpec 5+ moved to a commercial EULA; Cinc is the OSS
rebuild).

Note on exit codes: `cinc-auditor exec` returns 100 when controls FAIL — that's
the normal, expected case (failures are what we harvest), not an error. The
JSON is on stdout regardless, so we key off "did we get JSON", not the code.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable


class CincError(RuntimeError):
    """cinc-auditor could not be run, or produced no parseable output."""


def cinc_cmd(profile: str, target: str, extra_args: list[str] | None = None) -> list[str]:
    """Build the argv for `cinc-auditor exec` with JSON reporting."""
    argv = ["cinc-auditor", "exec", profile, "-t", target, "--reporter", "json"]
    if extra_args:
        argv += extra_args
    return argv


def run_profile(
    profile: str,
    target: str,
    *,
    extra_args: list[str] | None = None,
    runner: Callable | None = None,
    timeout_s: int = 900,
) -> str:
    """Run one Cinc profile against a target; return the raw JSON report.

    ``runner`` is injectable (defaults to subprocess.run) so this is unit-
    testable without cinc-auditor installed. Raises CincError only on real
    failures (binary missing, timeout, or no JSON produced) — a non-zero exit
    with JSON on stdout (controls failed) is a normal result.
    """
    run = runner or subprocess.run
    argv = cinc_cmd(profile, target, extra_args)
    try:
        proc = run(argv, capture_output=True, text=True, timeout=timeout_s)
    except FileNotFoundError as exc:
        raise CincError("cinc-auditor not found (install Cinc Auditor)") from exc
    except subprocess.TimeoutExpired as exc:
        raise CincError(f"cinc-auditor timed out after {timeout_s}s") from exc

    out = (getattr(proc, "stdout", "") or "").strip()
    if out:
        return out
    rc = getattr(proc, "returncode", 1)
    stderr = (getattr(proc, "stderr", "") or "")[:500]
    raise CincError(f"cinc-auditor produced no JSON (exit {rc}): {stderr}")
