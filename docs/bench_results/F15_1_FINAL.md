# F15.1 — PCI-DSS v4 deterministic compliance auditor: **SHIPPED (4/4 gates PASS)**

Fecha: 2026-04-15. Sprint: F15.1 (build phase, scope B = 6 checks). Framework:
PCI-DSS v4.0.1. Target: Ubuntu 22.04 CIS-nonconforming (scripts/f15/lab/).

## Meta-lesson (will matter in 3 months)

F15.1 was the **first all-green sprint after F7-F13**. Reason:
**small, testable hypothesis with no dependency on LLM capability**.
Concretely:

- The detection layer is deterministic (Python + shell). LLM failure
  cannot break the audit verdict.
- The LLM role (prose narrator) is cosmetic. An empty narrator output
  still ships a valid PDF.
- Gates were pinned before any code (G1-G4 pre-build, Lynis expected
  agreement a-priori).

Pattern to replicate in future sprints: **confine LLM dependency to
non-blocking cosmetic layers; pin gates before evidence; bench against
external ground truth with taxonomy bridge written first**.

## Gate scoreboard (all 4 pinned pre-build)

| Gate | Threshold | Result | Status |
|------|-----------|--------|--------|
| G1 coverage | 6/6 checks implemented, smoke-passing | 6/6 registered, FAIL correctly on misconfigured target | **PASS** |
| G2 external agreement | ≥80% vs Lynis-mapped equivalents | **83.3%** (5/6 agree) | **PASS** |
| G3 reproducibility | SHA-256 byte-exact across 3 runs | Hash `46b1ea6a…` identical × 3 | **PASS** |
| G4 PDF legibility | 4/4 tests pinned in F15_1_G4_CRITERIA.md | Comprensión ✅ Actionability ✅ Separation ✅ Defensibility ✅ | **PASS** |

**First all-green sprint in the F7-F15 arc.**

## What shipped

### Code (all in repo)

```
src/kryon/compliance/
├── checks/
│   ├── __init__.py              # Package interface + LLM boundary rule
│   ├── base.py                  # CheckResult frozen dataclass, Check protocol
│   ├── section_2/
│   │   ├── c_2_2_2_default_accounts.py    # MySQL/SNMP/shadow empty-pw
│   │   └── c_2_2_7_ssh_hardening.py       # sshd_config parse + weak ciphers
│   ├── section_6/
│   │   ├── c_6_3_3_patch_currency.py      # apt upgradable + dpkg.log age
│   │   └── c_6_4_1_web_headers.py         # live curl -I + HSTS/CSP/XFO/XCTO
│   ├── section_8/
│   │   └── c_8_3_6_password_policy.py     # login.defs + pwquality + pam
│   └── section_10/
│       └── c_10_2_1_audit_trails.py       # auditd service + PCI rules
├── runner.py                    # run_all() sorted, reproducibility_hash()
└── __init__.py

src/kryon/reporting/
├── compliance_pdf.py            # A4 template with LLM watermark + hash footer
└── compliance_narrator.py       # LLM prose for Context/Remediation ONLY

scripts/f15/
├── generate_compliance_pdf.py   # end-to-end orchestrator
└── lab/
    ├── Dockerfile               # Ubuntu 22.04 CIS-nonconforming
    ├── docker-compose.yml
    └── run_kryon_bench.py
```

### Docs

```
docs/
├── F15_0_INVENTORY_AND_GAPS.md      # F15.0 sprint scoping
├── F15_1_IMPLEMENTATION_PLAN.md     # Route B plan (6 checks)
├── F15_1_G4_CRITERIA.md             # G4 tests pinned pre-template
├── compliance/
│   └── lynis_mapping.md             # Kryon ↔ Lynis taxonomy bridge
└── bench_results/
    ├── F15_1_AGREEMENT.md           # G2 agreement 83%
    └── F15_1_FINAL.md               # this document
```

### Artifacts (lab run)

- `f15_compliance_final.pdf` — sample audit PDF (82KB, A4, 6 findings + appendix).
- `f15_compliance_final.html` — same as HTML for template inspection.
- `kryon_bench.json` — raw CheckResult JSON from bench-target (hash `606b1722…`).

## Architecture invariants (enforced)

1. **LLM boundary**: LLM sees CheckResult as immutable input, outputs only two
   string fields (context_prose, remediation_prose). Downstream renderer
   cannot inject LLM output into verdict/evidence/remediation_static paths.
2. **Reproducibility**: `CheckResult.to_json_reproducible()` strips duration_ms
   and run_id. Runner sorts checks by control_id. 3-run hash verified.
3. **PDF separation**: LLM-narrated sections use distinct CSS class (`.llm-block`),
   visible watermark ("LLM NARRATIVA" orange badge), dashed cream border.
   Verdict + evidence + remediation_static in plain deterministic blocks.
4. **Audit trail**: every FAIL includes exact command, raw stdout, raw stderr,
   host identifier, reproducibility hash in footer. Reproducible by hand.

## Key differentiator surfaced by the bench

The single G2 disagreement (c_6_4_1_web_headers, Kryon FAIL vs Lynis PASS)
is **product-valuable**:

- Lynis parses config files (static view).
- Kryon performs live HTTP request (runtime truth).
- The two can diverge when nginx/apache config declares headers but the
  running stack (reverse proxy, middleware, rewrites) strips them before
  the response leaves the box.

This is the honest pitch: **Kryon does what Lynis doesn't attempt, and the
deliberately-nonconforming lab proved it**. Not a bug — a feature surfaced
by disciplined benchmarking.

## Lessons that held through the sprint

From F7-F13 playbook:
- Corpus pinned before code: bench target Docker image committed.
- Gates pinned before results: all 4 G-gates defined in F15_1_IMPLEMENTATION_PLAN.md
  and F15_1_G4_CRITERIA.md before any check code was written.
- Lynis mapping + expected agreement written before the actual bench, preventing
  post-hoc interpretation of numbers.
- No moving the poles: disagreement on 6.4.1 counted honestly (not excluded
  as methodology noise — just explained).

Specific to F15.1:
- The "route B" decision (6 checks vs 11) delivered 100% of committed scope
  instead of 80% of ambitious scope. Cumulative effect: first sprint in 5 with
  no caveat in the title.

## Next sprint candidates (backlog, not committed)

- **F15.2**: extend to 11 checks (cover 2.2.2 MySQL/SNMP gap, 6.2.4 SAST
  evidence, 6.4.1 methodology refinement, 8.3.4 lockout, 8.4.2 MFA, 10.4.1
  log review). Uses same infrastructure — each additional check is ~30-60min.
- **F15.3**: CIS Benchmark L1/L2 profile (broader than PCI-DSS), for customers
  requiring that specific framework.
- **F15.4**: multi-host orchestration — the runner already supports SSH via
  CheckContext.ssh_user; productionize with host-inventory YAML and
  consolidated PDF per-engagement.
- **F16**: integrate compliance auditor into the existing `kryon engage` CLI
  (F12.7) so a single command covers recon + compliance + PDF report.

Critical: none of these sprints depend on LLM-capability unknowns. All of
them are Python + shell + deterministic logic. The F7-F13 pattern of
hypothesis-tested-and-rejected is **left behind** starting with F15.1.

## Commit strategy

Suggested commits (granular for rollback safety):

```
feat(F15.1/infra): add compliance CheckResult schema + runner with SHA-256
feat(F15.1/checks): PCI 2.2.2 — default accounts (shadow + mysql + snmp)
feat(F15.1/checks): PCI 2.2.7 — SSH hardening
feat(F15.1/checks): PCI 6.3.3 — patch currency
feat(F15.1/checks): PCI 6.4.1 — web headers (live HTTP)
feat(F15.1/checks): PCI 8.3.6 — password policy
feat(F15.1/checks): PCI 10.2.1 — audit trails
feat(F15.1/reporting): compliance PDF template with LLM watermark
feat(F15.1/reporting): LLM narrator (context + remediation prose ONLY)
feat(F15.1/lab): CIS-nonconforming Ubuntu bench target + docker-compose
docs(F15.1): G1/G2/G3/G4 gate results + Lynis agreement 83%
```
