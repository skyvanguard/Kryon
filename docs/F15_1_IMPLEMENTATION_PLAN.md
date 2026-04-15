# F15.1 — Implementation plan (Route B, 6 checks)

Sprint: PCI-DSS v4 deterministic auditor. Framework: sections 2/6/8/10. Scope pinned,
no post-hoc expansion. All gates pre-agreed in F15.0.

## Deliverables (all must ship together)

1. `src/kryon/compliance/checks/` — 6 deterministic checks
2. `src/kryon/compliance/runner.py` — orchestrator + reproducibility harness
3. `docs/compliance/lynis_mapping.md` — taxonomy bridge Kryon ↔ Lynis
4. `scripts/f15/bench_vs_lynis.py` — external ground truth bench
5. `src/kryon/reporting/compliance_pdf.py` — PDF template (LLM narrates only context/remediation)
6. `docs/bench_results/F15_1_RESULTS.md` — gate evaluation

## Checks (scope pinned)

| # | File | Control | What it verifies |
|---|------|---------|------------------|
| 1 | `section_2/c_2_2_2_default_accounts.py` | 2.2.2 | MySQL root empty/test pw, SNMP `public`, SSH default users (`root`/`admin`/`test`) |
| 2 | `section_2/c_2_2_7_ssh_hardening.py` | 2.2.7 | SSH PermitRootLogin=no, Protocol 2 only, no CBC ciphers, MaxAuthTries≤4 |
| 3 | `section_6/c_6_3_3_patch_currency.py` | 6.3.3 | `apt list --upgradable` + last-security-update age ≤30d |
| 4 | `section_6/c_6_4_1_web_headers.py` | 6.4.1 | HSTS, CSP, X-Frame-Options, X-Content-Type-Options on exposed web |
| 5 | `section_8/c_8_3_6_password_policy.py` | 8.3.6 | `/etc/login.defs` PASS_MIN_LEN≥12, `pam_pwquality` minclass≥3 |
| 6 | `section_10/c_10_2_1_audit_trails.py` | 10.2.1 | auditd running + rules.d has `-w /etc/passwd -p wa -k identity` style PCI minimums |

## Architecture (non-negotiable)

### CheckResult schema (designed once, used by all 6)

```python
@dataclass(frozen=True)
class CheckResult:
    control_id: str                    # "2.2.2"
    control_title: str                 # "Vendor default accounts"
    section: str                       # "2"
    verdict: Literal["PASS", "FAIL", "N/A", "ERROR"]
    evidence_command: str              # exact shell command executed
    evidence_stdout: str               # raw output, capped 4KB
    evidence_stderr: str               # raw stderr, capped 1KB
    evidence_parsed: dict              # structured parse for PDF rendering
    remediation_static: str            # from check file, never modified by LLM
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    duration_ms: int
    host: str                          # target hostname or "localhost"
    run_id: str                        # shared across checks in one run
    # NOT stored in CheckResult: timestamp (normalized away at serialization)
```

### Reproducibility rules

- Checks always executed in sorted order by `control_id` (lexicographic).
- Inside each check: if parsing subprocess output, sort arrays stably.
- Serialization strips wall-clock timestamps. The `duration_ms` field is the only
  perf metric and is **only** included in a separate `_timing.json`, never in the
  reproducibility-hashed `checks.json`.
- Gate test: `sha256(sorted-checks.json run-1) == sha256(sorted-checks.json run-2) == sha256(sorted-checks.json run-3)`.

### LLM boundary (regulatory rule)

```
LLM input:  CheckResult (frozen, never mutated)
LLM output: Markdown prose for "Contexto" and "Remediación detallada" sections
LLM CANNOT: modify verdict, modify evidence_stdout, modify remediation_static,
            generate new controls, re-interpret command output
```

PDF generator writes verdict + evidence from CheckResult. LLM prose appears in
separate, clearly-labeled sections.

## Lynis mapping (pre-build, 30 min)

Built before any check code. Table in `docs/compliance/lynis_mapping.md`:

| Kryon check | PCI control | Lynis test ID | Notes |
|-------------|-------------|---------------|-------|
| c_2_2_2_default_accounts | 2.2.2 | AUTH-9286, AUTH-9204 | Lynis checks passwd/shadow, we also add MySQL/SNMP |
| c_2_2_7_ssh_hardening | 2.2.7 | SSH-7408 | direct match |
| c_6_3_3_patch_currency | 6.3.3 | PKGS-7346, PKGS-7384 | Lynis: updates available |
| c_6_4_1_web_headers | 6.4.1 | HTTP-6622 | partial — Lynis weaker on headers |
| c_8_3_6_password_policy | 8.3.6 | AUTH-9230, AUTH-9286 | direct match |
| c_10_2_1_audit_trails | 10.2.1 | ACCT-9622, LOGG-2138 | direct match |

Agreement computed per check as:
- Both PASS or both FAIL → agreement
- One N/A or ERROR → excluded from agreement denominator
- Diff → logged with analysis

## Gates (pinned, will not move)

| Gate | Threshold | How measured |
|------|-----------|--------------|
| G1 coverage | 6/6 checks implemented + smoke-passing | unit tests in `tests/compliance/checks/` |
| G2 external agreement | ≥80% vs Lynis-mapped equivalents | `scripts/f15/bench_vs_lynis.py` on CIS-nonconforming Ubuntu 22.04 VM |
| G3 reproducibility | sha256 identical across 3 consecutive runs | `compliance runner --repro-check` |
| G4 PDF legibility | non-technical reviewer understands 3/3 sampled findings | prompt Opus as stand-in reviewer + 1 human sanity check |

## Step order (executing now)

1. **CheckResult schema + runner skeleton** (30 min) — define the frozen dataclass, runner with sorted-order execution, JSON serializer with timestamp strip.
2. **Lynis mapping table** (30 min) — write `docs/compliance/lynis_mapping.md` with the 6 mappings above. Validates each Lynis test ID is real.
3. **Build 6 checks serially** (~6-8h realistic) — each check:
   - query function + subprocess
   - output parser
   - verdict logic
   - remediation static string
   - unit test with fixture outputs (PASS/FAIL/N/A)
4. **Reproducibility harness** (1h) — wrapper that runs the runner 3× and asserts sha256 equality.
5. **CIS-nonconforming Ubuntu VM + Lynis + OpenSCAP bench** (2h) — docker-based preferred: `docker-compose.yml` with Ubuntu 22.04 that's deliberately misconfigured. Run Kryon + Lynis + OpenSCAP against it, produce agreement table.
6. **PDF template + LLM narrator** (2h) — jinja2 template with clear sections: Executive Summary (LLM) | Per-Control Findings (deterministic: verdict + evidence) | Remediation Context (LLM). Regenerate using existing `reporting/demo_report.py` weasyprint infra.
7. **Gate evaluation writeup** (30 min) — `F15_1_RESULTS.md` with 4 gates pass/fail, shipping decision.

**Realistic total: 12-15h.**

## Executing now

Proceed with step 1 (CheckResult + runner skeleton) → step 2 (Lynis mapping) → step 3 (builds). Each step's output is committed before the next starts so the work is auditable.

Commit strategy: one commit per check, plus infra commits (schema, runner, bench, PDF). PR squashable but granular commits let us roll back a single check if it fails external agreement.
