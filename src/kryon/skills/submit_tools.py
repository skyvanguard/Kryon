"""
Structured finding-submission tools for the zero-day hunter.

Replaces "emit a FINDING / NO FINDING text block" (fragile to parse)
with explicit tools whose arguments ARE the finding fields. The model
calls `submit_finding(...)` or `submit_no_finding(...)` and the runner
picks up the call from the agent's tool-call history — no regex, no
parsing, zero ambiguity.

Why this matters:
  Hunt #11 (qwen3-coder, 50-turn budget): the hunter correctly called
  `run_sandboxed` twice to verify hypotheses but closed with prose.
  "hunter finished without emitting structured output" — the playbook
  mandated a FINDING/NO FINDING block; the model wrote a summary paragraph.
  Instructional compliance is unreliable on small local models.
  Tool-call compliance is deterministic: if the tool exists in the
  schema, the model can and will invoke it.

Both tools are no-ops at the Python level — they just return confirmation
JSON. The runner extracts their arguments from `agent.model.message_history`
as part of _harvest_progress.
"""

from __future__ import annotations

import json

from kryon.sdk.agents import function_tool


@function_tool(strict_mode=False)
def submit_finding(
    file_path: str,
    function_name: str,
    cwe: str,
    crash_type: str,
    severity: str = "MEDIUM",
    poc_source: str = "",
    trigger_input: str = "",
    line_range: str = "",
    stack_top: str = "",
    suggested_fix: str = "",
    deepening_outcome: str = "",
) -> str:
    """Submit a CONFIRMED vulnerability finding to the planner.

    Call this tool ONLY after `run_sandboxed` returned crashed=true AND
    you completed adversarial self-challenge (Phase 3.6).

    Args:
        file_path: absolute path of the vulnerable file.
        function_name: name of the function containing the bug.
        cwe: CWE identifier (e.g. "CWE-787" for OOB write).
        crash_type: ASAN-reported crash type (e.g. "heap-buffer-overflow",
            "use-after-free", "undefined-behavior").
        severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW".
        poc_source: full C/C++ harness that crashes under ASAN. Must be
            the SAME code that made run_sandboxed return crashed=true.
        trigger_input: optional stdin bytes that trigger the crash.
        line_range: e.g. "1635-1815".
        stack_top: comma-separated top 3 stack frames from run_sandboxed.
        suggested_fix: one-line patch description.
        deepening_outcome: Phase 3.5 result ("escalates to RCE",
            "info leak confirmed", "stays DoS-only", etc.).

    Returns JSON acknowledgment. The planner reads these arguments from
    the tool-call history.
    """
    return json.dumps(
        {
            "accepted": True,
            "type": "finding",
            "cwe": cwe,
            "crash_type": crash_type,
        }
    )


@function_tool(strict_mode=False)
def submit_no_finding(
    file_path: str,
    reason: str,
    attempted_hypotheses: int = 0,
    notes: str = "",
) -> str:
    """Submit a NEGATIVE result: investigated but no confirmed bug.

    Call this when:
      - You've exhausted your hypotheses and none crashed under ASAN
      - You've used your escape-hatch budget (>= 20 turns)
      - The function isn't reachable from any public API
      - The code is defensively coded and every plausible input is
        bounded

    This is a VALID and valuable outcome — the planner tracks it so the
    learning loop remembers which files were already investigated and
    cleared.

    Args:
        file_path: absolute path of the file investigated.
        reason: one-line summary of why no bug was confirmed
            (e.g. "all 3 hypotheses failed ASAN", "defensive bounds
            checks in all callers", "ran out of turn budget").
        attempted_hypotheses: count of hypotheses tried.
        notes: optional extra detail, e.g. hypotheses tried.

    Returns JSON acknowledgment.
    """
    return json.dumps(
        {
            "accepted": True,
            "type": "no_finding",
            "reason": reason[:200],
            "attempted_hypotheses": attempted_hypotheses,
        }
    )


@function_tool(strict_mode=False)
def reflect_on_hypothesis(
    current_hypothesis: str,
    evidence_for: str,
    evidence_against: str,
    what_would_kill_it: str,
    next_action: str,
) -> str:
    """Record a reflection checkpoint (Phase 2.5 of the playbook).

    Call this every 5 turns to step back and audit your own direction.
    The act of having to articulate "Evidence AGAINST" forces
    consideration of alternatives.

    All fields are free text (short, <= 500 chars each).

    Returns JSON acknowledgment. The planner keeps these as
    `_reflections[]` on the hunter job for post-hoc analysis.
    """
    return json.dumps(
        {
            "accepted": True,
            "type": "reflection",
        }
    )
