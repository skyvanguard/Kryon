# F15.1 gate G4 — PDF legibility criteria (pinned pre-template)

Written **before** opening weasyprint. Prevents author bias during self-review.
Gate requires 4/4 tests pass.

## Test 1 — Comprensión

Procedure: read the PDF cover-to-cover without consulting any Kryon source code
or docs other than the PDF itself. For each FAIL finding, state in **one
sentence** what the problem is.

Pass criterion: 6/6 findings explainable in one sentence using only the PDF.

Fail criterion: any finding where the reader must consult `CheckResult` source
or `lynis_mapping.md` to understand the verdict.

## Test 2 — Actionability

Procedure: for each FAIL, identify the concrete remediation command or config
file edit from the PDF alone.

Pass criterion: 6/6 FAILs name either:
  - Exact shell command to run (e.g. `passwd -l badacct`), OR
  - Exact config file + directive (e.g. "edit `/etc/ssh/sshd_config`, set
    `PermitRootLogin no`, reload `systemctl reload sshd`").

Fail criterion: any FAIL where remediation is vague ("harden SSH") without
file/command specifics.

## Test 3 — Separation (deterministic vs LLM)

Procedure: scan the PDF looking for visual cues. Without reading the content,
identify which sections are deterministic-audit-output vs LLM-generated prose.

Pass criterion: each LLM-narrated block has a visible watermark/badge (icon,
distinct color, or labeled frame) that unambiguously identifies it. A reviewer
glancing at the PDF can immediately separate "verdict + evidence" (audit
authority) from "context + why this matters" (LLM prose, informational only).

Fail criterion: LLM prose visually indistinguishable from deterministic output.

## Test 4 — Defensibility

Procedure: for each FAIL, verify the PDF includes:
  - Exact command that was executed
  - Raw stdout/stderr from that command
  - Host identifier
  - JSON artifact hash (SHA-256 footer)

Pass criterion: 6/6 FAILs have all four elements. Reviewer can reproduce the
finding manually by re-running the command.

Fail criterion: any FAIL missing command + output + host + hash.

## Gate scoring

- **4/4 pass** → G4 PASS, ship F15.1.
- **3/4 pass** → G4 MARGINAL, ship with `F15.2 — iterate section X` backlog item.
- **≤2/4 pass** → G4 FAIL, no ship, redesign template.

## Anti-bias guardrails

- Self-review without looking at the template source during evaluation.
- Each test result recorded as pass/fail BEFORE looking at the next test.
- If unsure on any test, mark FAIL by default (conservative bias).

## Non-goals (explicitly out of scope)

- Visual polish / branding — this is an audit artifact, not marketing.
- Typography sophistication — legibility suffices.
- Multi-language — Spanish narrative only this sprint.
