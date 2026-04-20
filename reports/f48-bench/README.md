# F48 — Compliance End-to-End Benchmark Results

**Run timestamp:** 2026-04-20
**Target:** localhost (kryon container — Debian 12 base)
**Frameworks:** 10 registered · 422 total checks

## Metrics

| Metric | Value |
|---|---|
| Total checks executed | **422** |
| Wall time | **8.0s** (avg 19 ms/check) |
| PASS | 127 |
| FAIL | 199 |
| N/A | 0 |
| ERROR | 96 (expected — see below) |
| Frameworks reproducible (N=2) | **10/10** |
| Consolidated PDF generated | ✅ `consolidated.pdf` (801 KB) |
| Master reproducibility hash | `9046da9f2387ae8c...` |

## Per-framework breakdown

| Framework | Checks | PASS | FAIL | N/A | ERROR | Elapsed | Repro |
|---|---:|---:|---:|---:|---:|---:|:---:|
| atm-security-bcp-2024 | 25 | 7 | 3 | 0 | 15 | 0.04s | ✅ |
| bcp-py-res-12-2021 | 18 | 2 | 16 | 0 | 0 | 0.09s | ✅ |
| cis-debian-12-l1 | 47 | 18 | 29 | 0 | 0 | 2.97s | ✅ |
| cis-docker-1.6 | 54 | 23 | 18 | 0 | 13 | 0.10s | ✅ |
| cis-rhel-9-l1 | 54 | 17 | 36 | 0 | 1 | 1.52s | ✅ |
| cis-ubuntu-22.04-l1 | 73 | 24 | 49 | 0 | 0 | 1.62s | ✅ |
| cis-windows-server-2022-l1 | 67 | 0 | 0 | 0 | 67 | 1.34s | ✅ |
| core-banking-hardening | 36 | 26 | 10 | 0 | 0 | 0.05s | ✅ |
| pci-dss-4.0 | 31 | 7 | 24 | 0 | 0 | 0.21s | ✅ |
| swift-csp-2024 | 17 | 3 | 14 | 0 | 0 | 0.05s | ✅ |

## Why 96 ERROR is expected

The bench runs inside a **Debian-based Linux container** (`kryon`). Several
frameworks target platforms or daemons that are not present:

- **Windows Server (67 ERROR):** `reg query`, `wmic`, `powershell`,
  `auditpol`, `manage-bde`, `sc query` — not available on Linux.
  In production this framework runs via `transport="winrm"` against
  a real Windows host.
- **ATM Security (15 ERROR):** same — Windows-targeted ATM commands.
- **Docker (13 ERROR):** container-in-container — the kryon container
  has no Docker daemon of its own.
- **RHEL (1 ERROR):** a single RHEL-only binary missing on Debian.

These ERRORs correctly surface as ERROR (not silent PASS) because the
evaluator refuses to interpret empty stdout as a positive match. That
is the designed behaviour.

## Drift discovered and fixed

Initial run showed **core-banking-hardening** drifting between runs:
`CBH-5.1`, `CBH-5.2`, `CBH-5.3`, `CBH-5.5` used unbounded `find /` which
walked 2M+ inodes on cold cache and timed out at 15s, but returned in
<1s on warm cache — producing different verdicts (ERROR → PASS).

**Fix:** scope the `find` to well-known Oracle/DB2 install paths
(`/u01`, `/u02`, `/opt/oracle`, `/home/oracle`, `/oracle`, `/db2`,
`/home/db2inst1`) with `-maxdepth 8`.

**Result post-fix:**
- core-banking wall time: **44.58s → 0.05s** (~900× speedup)
- repro: **FAIL → OK**
- Other frameworks unaffected

## Reproducibility hash stability

Every framework produces the same SHA-256 across consecutive runs.
For a consolidated engagement, the master hash
(`compute_repro_hash(framework_results)` from F44) also stays stable
as long as the target state does not change.

## How to regenerate

```bash
# Full bench (10 frameworks, 2x repro, render PDF)
python scripts/f48/compliance_e2e_bench.py \
    --repro-check 2 --render-pdf \
    --output-dir reports/f48-bench-$(date +%Y%m%d)

# Single framework, quick run
python scripts/f48/compliance_e2e_bench.py \
    --frameworks cis-debian-12-l1

# Against remote host via SSH
python scripts/f48/compliance_e2e_bench.py \
    --host 10.0.0.10 --ssh-user audit --ssh-key ~/.ssh/id_ed25519

# Against a Windows host via WinRM
python scripts/f48/compliance_e2e_bench.py \
    --host win-srv01 --transport winrm \
    --winrm-user audit --winrm-password "$WINRM_PASSWORD" \
    --frameworks cis-windows-server-2022-l1
```

## Files in this directory

| File | Description |
|---|---|
| `bench_report.json` | Machine-readable per-framework metrics + verdict counts + hashes |
| `consolidated.html` | Multi-framework bilingual HTML (F44 renderer) |
| `consolidated.pdf` | Same as above but rendered via WeasyPrint (801 KB) |

Raw per-check evidence (`<framework>.json`) is kept under
`workspaces/bench-final/` inside the container; not committed — too
large and rotates per run.
