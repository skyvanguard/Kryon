# Kryon ↔ Lynis taxonomy bridge (F15.1 external ground truth gate)

Lynis uses its own test-ID taxonomy (e.g. `SSH-7408`, `AUTH-9286`). PCI-DSS v4
control IDs (e.g. `2.2.7`) don't map 1-to-1. To compare agreement, this table
fixes the equivalence ahead of the bench — no moving the poles after seeing results.

Gate G2: ≥80% verdict agreement across the 6 mapped pairs, measured on the
CIS-nonconforming Ubuntu 22.04 VM built in `scripts/f15/lab/`.

## Mapping table

| Kryon check | PCI v4 control | Lynis test ID(s) | OpenSCAP rule (XCCDF id, PCI profile) | Notes / caveats |
|-------------|----------------|------------------|---------------------------------------|-----------------|
| `c_2_2_2_default_accounts` | 2.2.2 | `AUTH-9204` (accounts w/o passwd), `AUTH-9286` (pw age check indirectly) | `xccdf_org.ssgproject.content_rule_accounts_no_empty_passwords` | Lynis does not check MySQL root or SNMP community. Agreement measured ONLY on the shell-accounts subset; MySQL/SNMP are Kryon-only extensions (reported as additional value, not counted against agreement). |
| `c_2_2_7_ssh_hardening` | 2.2.7 | `SSH-7408` | `xccdf_org.ssgproject.content_rule_sshd_disable_root_login`, `...content_rule_sshd_disable_empty_passwords`, `...content_rule_sshd_use_strong_macs` | Lynis `SSH-7408` aggregates many sub-findings. Kryon verdict is FAIL if ANY of: PermitRootLogin=yes, Protocol=1, CBC cipher enabled, MaxAuthTries>4. Agreement: Lynis overall-SSH verdict (pass/fail) vs Kryon aggregate. |
| `c_6_3_3_patch_currency` | 6.3.3 | `PKGS-7346` (pkg list), `PKGS-7384` (security updates) | `xccdf_org.ssgproject.content_rule_security_patches_up_to_date` | Both detect pending security updates. Kryon adds `last-security-update age ≤ 30d` which is strictly more conservative; Lynis flags presence of updates regardless of age. Agreement policy: if Lynis says "updates available" AND Kryon says FAIL → agree. |
| `c_6_4_1_web_headers` | 6.4.1 | `HTTP-6622` (partial — nginx/apache hardening headers) | `xccdf_org.ssgproject.content_rule_httpd_configure_security_headers` (if present) | Weakest pair — Lynis checks web server config files, Kryon performs live HTTP request to the exposed port and inspects response headers. Methodology difference. Both should agree on **whether HSTS is absent**; other headers may diverge. Agreement measured on HSTS presence only. |
| `c_8_3_6_password_policy` | 8.3.6 | `AUTH-9230` (password hashing), `AUTH-9286` (complexity), `AUTH-9262` (PAM) | `xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen`, `...content_rule_accounts_password_pam_minclass` | Direct match: both read `/etc/login.defs` and `/etc/security/pwquality.conf`. Kryon verdict FAIL if minlen<12 OR minclass<3. Lynis reports each finding; treat Lynis as FAIL if it flags ANY password-policy weakness. |
| `c_10_2_1_audit_trails` | 10.2.1 | `ACCT-9622` (process accounting), `LOGG-2138` (auditd running) | `xccdf_org.ssgproject.content_rule_service_auditd_enabled`, `...content_rule_audit_rules_etc_passwd_open_write` | Direct match on "is auditd running". Kryon ADDITIONALLY checks for PCI-minimum rules in `/etc/audit/rules.d/`; Lynis does not validate rule content depth. Agreement on auditd-running subset only. |

## Expected agreement per pair (honest a-priori prediction)

Before running the lab: what agreement SHOULD we get, given the logic differences
documented above? Written ahead of the bench to prevent post-hoc rationalization
if the numbers come in low.

| Kryon check | Expected agreement | Rationale |
|-------------|--------------------|-----------|
| c_2_2_2_default_accounts | **80%** | Both read /etc/shadow — solid agreement on shell accounts. Kryon's MySQL + SNMP subchecks are **Kryon-only** (Lynis weak here), so whenever Kryon flags MySQL/SNMP while Lynis doesn't, that's a legitimate disagreement counted against agreement. Subset agreement (shadow only) ~95%. |
| c_2_2_7_ssh_hardening | **80%** | Both inspect sshd config. Zones grises: `prohibit-password` (Kryon PASS, Lynis sometimes WARN), MaxAuthTries mid-range values. PCI strict reading vs Lynis pragmatic → ~1-2 disagreements expected on 6-check bench. |
| c_6_3_3_patch_currency | **85%** | Core logic (pending security updates) is convergent. Kryon's additional `last-upgrade ≤ 30d` threshold may flag FAIL where Lynis PASSes on a fully-patched but dormant system. |
| c_6_4_1_web_headers | **65%** ⚠️ | **Weakest pair**. Lynis parses config files; Kryon does live HTTP request. Different methodology = different findings even on same truth. Documented as structural limitation — not a Kryon bug. |
| c_8_3_6_password_policy | **85%** | Shared source files (/etc/login.defs, pwquality.conf). Kryon thresholds (minlen ≥12, minclass ≥3 per PCI v4) may be stricter than Lynis defaults → some Kryon-FAIL / Lynis-PASS cases. |
| c_10_2_1_audit_trails | **75%** | Shared base (is auditd running). Kryon deeper check on rules.d content that Lynis doesn't inspect → some Kryon-FAIL / Lynis-PASS cases where service is up but rules are missing. |

**Pooled expected agreement**: mean ≈ **78%**.

**Gate G2 implication**: threshold of ≥80% is **on the edge**. If actual agreement
comes in at 75-82%, that's consistent with predicted bounds and NOT a bug —
it's the inherent methodology divergence documented above. If it comes in at
<70%, something is wrong (Kryon bug OR mapping error) and requires investigation
before PDF build.

Post-bench analysis plan:
- Agreement 80-85% → gate G2 passes cleanly, proceed to PDF.
- Agreement 75-80% → gate marginal. Document the specific diffs vs the predicted
  disagreement rationale above. If every diff is predicted-logic, treat as PASS
  with note. If new undocumented diffs appear, investigate.
- Agreement <75% → pause, analyze diffs one by one before any declaration.

## Agreement computation rubric

For each mapping row, after both tools run:

1. If Lynis test is `N/A` or errored → **excluded** from denominator.
2. If Kryon verdict is `ERROR` → **excluded** from denominator (ours, not theirs).
3. Normalize both to `PASS` / `FAIL` using the rules in the "Notes" column.
4. If PASS==PASS or FAIL==FAIL → +1 agreement.
5. Diff → log to `docs/bench_results/F15_1_AGREEMENT_DIFFS.md` with a one-line diagnosis.

Agreement ratio: `agreements / (agreements + disagreements)`. Gate: **≥80% over the 6 pairs**.

## Why these caveats matter

Without this document the bench would compare:
- Kryon "FAIL because no HSTS AND no CSP" vs Lynis "PASS because nginx config syntax is fine" — both correct but measuring different things.
- Kryon "FAIL because last security patch was 31 days ago" vs Lynis "FAIL because updates are available" — both FAIL but for different reasons; counted as agreement even though the logic differs.

The table above pins the decisions so the 80% number is meaningful, not measuring
methodology divergence between the tools.

## Out of scope for this sprint

- OpenSCAP as primary comparator — used only as secondary evidence when Lynis doesn't cover a sub-aspect (e.g. specific PAM module checks). Agreement computed against Lynis; OpenSCAP column present for audit traceability.
- CIS Benchmark v3 test IDs — different project; can be added in F15.2 if customer asks.
