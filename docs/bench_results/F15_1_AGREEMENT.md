# F15.1 external agreement bench — Kryon vs Lynis 3.0.7

Fecha: 2026-04-15. Target: Ubuntu 22.04 deliberately CIS-nonconforming
(scripts/f15/lab/). Lynis raw report: `/var/log/lynis-report.dat` inside target.
Kryon raw: `scripts/f15/lab/kryon_bench.json`.

## Per-check agreement

| PCI v4 | Kryon verdict | Lynis finding(s) | Lynis verdict | Agree? |
|--------|---------------|------------------|---------------|--------|
| 2.2.2 default accounts | **FAIL** (empty-password badacct) | `warning[]=AUTH-9283` "Found accounts without password" | **FAIL** | ✅ |
| 2.2.7 SSH hardening | **FAIL** (PermitRootLogin=yes, MaxAuthTries=10, weak ciphers) | 10× `suggestion[]=SSH-7408` (PermitRootLogin, MaxAuthTries, etc.) | **FAIL** | ✅ |
| 6.3.3 patches ≤30d | **FAIL** (last upgrade 45d ago per dpkg.log) | `warning[]=PKGS-7392` vulnerable packages + `PKGS-7420` | **FAIL** | ✅ |
| 6.4.1 web headers | **FAIL** (HSTS/CSP/X-Frame-Options/X-Content-Type-Options missing on :80) | `suggestion[]=HTTP-6710` "Add HTTPS" — NO header-specific finding | **PASS/NA** | ❌ |
| 8.3.6 password policy | **FAIL** (PASS_MIN_LEN=8, no pwquality, no pam_pwquality) | `suggestion[]=AUTH-9230`, `AUTH-9286` password-related | **FAIL** | ✅ |
| 10.2.1 audit trails | **FAIL** (auditd not running + rules empty) | `suggestion[]=ACCT-9628` "Enable auditd"; `linux_auditd_running=0` | **FAIL** | ✅ |

## Agreement

**5 / 6 = 83.3%** — **gate G2 ≥80% PASS**.

## Disagreement analysis (1 case)

**c_6_4_1_web_headers — predicted weakest pair per `docs/compliance/lynis_mapping.md`:**

- Kryon methodology: live HTTP request via curl, inspects actual response headers.
- Lynis methodology: parses `/etc/nginx/` config files for hardening directives.
- Root cause of divergence: Lynis checks if HTTPS is enabled (HTTP-6710 fires on HTTP-only sites) but does not specifically validate presence of HSTS / CSP / X-Frame-Options / X-Content-Type-Options response headers.
- This is **methodology divergence, not Kryon bug**.
- Expected agreement per mapping doc: 65%. Actual: 0% on this single pair. Both within-range since N=1 has no statistical meaning — one case either agrees or doesn't.

**Verdict: disagreement is documented a-priori as structural limitation. Kryon 6.4.1 is a valid, stricter check that Lynis does not attempt. Counts toward 80% gate calculation honestly — we do NOT exclude it post-hoc.**

## Predicted vs actual agreement (validates method)

| Pair | Predicted | Actual |
|------|-----------|--------|
| 2.2.2 | 80% | AGREE (100% on this single run) |
| 2.2.7 | 80% | AGREE |
| 6.3.3 | 85% | AGREE |
| 6.4.1 | 65% | DISAGREE |
| 8.3.6 | 85% | AGREE |
| 10.2.1 | 75% | AGREE |
| **Pooled** | **78%** | **83%** |

Actual slightly above prediction — the single-target bench is favorable because all 6 CIS violations are clear. A production environment with more subtle misconfigurations may bring agreement closer to the predicted 78% band.

## Gate status F15.1

| Gate | Threshold | Result | Status |
|------|-----------|--------|--------|
| G1 coverage | 6/6 checks implemented, smoke-passing | 6/6 registered, all FAIL correctly on target | **PASS** |
| G2 agreement | ≥80% vs Lynis-mapped | **83.3%** (5/6) | **PASS** |
| G3 reproducibility | 3 runs byte-exact | SHA-256 `46b1ea6a…` identical × 3 | **PASS** |
| G4 PDF legibility | non-technical reviewer 3/3 | PENDING | — |

**G1/G2/G3 PASS. G4 pending — proceed to PDF template build.**

## Raw artifacts

- `scripts/f15/lab/Dockerfile` — CIS-nonconforming Ubuntu 22.04 target definition
- `scripts/f15/lab/docker-compose.yml` — isolated bench network
- `scripts/f15/lab/run_kryon_bench.py` — Kryon bootstrap + run
- `/tmp/kryon_bench.json` (in f15-bench-target) — Kryon 6-check output
- `/var/log/lynis-report.dat` (in f15-bench-target) — Lynis raw report
- `/var/log/lynis.log` (in f15-bench-target) — Lynis stdout
