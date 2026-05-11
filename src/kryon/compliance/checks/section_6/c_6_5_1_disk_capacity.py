"""CIS section 6 control 6.5.1 — Filesystem capacity headroom.

Out-of-disk events on a PVE/Linux host cascade into broken backups,
journal truncation, and refused VM writes. We require every locally-
mounted filesystem to stay under 85% used and swap to be under 80% used.

  - 85% disk threshold catches an imminent-OOD before apt / Proxmox
    refuse to allocate space (PVE storage stops at 95% by default).
  - 80% swap threshold catches memory pressure before the OOM-killer
    starts evicting workloads.

Evidence: `df -hT --output=source,fstype,pcent,target | grep -v tmpfs`
and `free -h | grep Swap`.

Closes ground-truth gaps M-01 (disk 89%) and M-02 (swap full).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_DISK_THRESHOLD = 85
_SWAP_THRESHOLD = 80

# `df -P` is POSIX-portable and gives `Filesystem 1024-blocks Used Available Capacity Mounted-on`.
_DF_LINE_RE = re.compile(
    r"^(?P<src>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<pct>\d+)%\s+(?P<mnt>\S+)\s*$",
)
# `free -b` line: total used free shared buff/cache available
_FREE_SWAP_RE = re.compile(
    r"^Swap:\s+(?P<total>\d+)\s+(?P<used>\d+)\s+",
)
# We ignore container / pseudo filesystems that always report 0% or
# don't represent persistent state.
_IGNORE_MNT_PREFIX = ("/run", "/dev", "/sys", "/proc", "/boot/efi")
_IGNORE_SRC_PREFIX = ("tmpfs", "devtmpfs", "overlay", "shm", "fuse")


def _parse_df(stdout: str) -> list[tuple[str, int, str]]:
    rows: list[tuple[str, int, str]] = []
    for line in stdout.splitlines()[1:]:  # skip header
        m = _DF_LINE_RE.match(line.strip())
        if not m:
            continue
        src = m.group("src")
        pct = int(m.group("pct"))
        mnt = m.group("mnt")
        if any(src.startswith(p) for p in _IGNORE_SRC_PREFIX):
            continue
        if any(mnt.startswith(p) for p in _IGNORE_MNT_PREFIX):
            continue
        rows.append((src, pct, mnt))
    return rows


class _C651Check:
    control_id = "6.5.1"
    control_title = "Filesystem and swap capacity headroom"
    section = "6"
    severity = "MEDIUM"
    remediation_static = (
        "Reclaim space on the failing filesystem (rotate logs, prune "
        "old VM images, clear apt cache). For swap pressure, free RAM "
        "(stop unused services, tune VM oversubscription) or add swap "
        "via /etc/fstab. Aim for <85% disk and <80% swap as steady-state."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        df_out, df_err, df_rc = run_cmd(ctx, ["df", "-P"], timeout_s=5)
        free_out, free_err, _ = run_cmd(ctx, ["free", "-b"], timeout_s=5)

        if df_rc != 0:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command="df -P; free -b",
                evidence_stdout=df_out[:4096],
                evidence_stderr=(df_err + "\n" + free_err)[:1024],
                evidence_parsed={},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        rows = _parse_df(df_out)
        over_disk = [(s, p, m) for s, p, m in rows if p >= _DISK_THRESHOLD]

        # Swap usage
        swap_used_pct = 0
        m = _FREE_SWAP_RE.search(free_out or "")
        if m:
            total = int(m.group("total"))
            used = int(m.group("used"))
            if total > 0:
                swap_used_pct = round((used / total) * 100)

        swap_problem = swap_used_pct >= _SWAP_THRESHOLD
        verdict = "PASS" if not over_disk and not swap_problem else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="df -P; free -b",
            evidence_stdout=(df_out + "\n---\n" + free_out)[:4096],
            evidence_stderr=(df_err + "\n" + free_err)[:1024],
            evidence_parsed={
                "filesystems_over_threshold": [
                    {"source": s, "used_pct": p, "mount": m}
                    for s, p, m in over_disk
                ],
                "disk_threshold_pct": _DISK_THRESHOLD,
                "swap_used_pct": swap_used_pct,
                "swap_threshold_pct": _SWAP_THRESHOLD,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C651Check()
register_check(CHECK)
