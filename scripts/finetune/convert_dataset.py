"""Fase 1 — convert public T-C-O walkthroughs into Kryon's tool-calling chat
format for QLoRA SFT.

Source: Pentest-R1 (MIT) `data/steps/*.json` — each file is one walkthrough:
    {"initial_prompt": "...goal...",
     "steps": [{"step_number", "thought", "command", "result"}, ...]}

Pentest-R1's own SFT script trains the model to emit *plain text*
("Thought:/Command:"). Kryon uses **native tool_calls**, so we map each
``command`` to a ``run_command`` tool call (the generic shell tool), keep the
``thought`` as the assistant's reasoning content, and the ``result`` as the
tool response. We then append an explicit **STOP** turn so the model learns to
recognize the objective is met and halt — directly targeting the loop/no-stop
failure observed live (qwen3-8b spinning ~48× on one call).

Output: `data/finetune/{train,val}.jsonl` ({"messages": [...]}) +
`data/finetune/tools.json` (the run_command spec for apply_chat_template).

Usage:
    python scripts/finetune/convert_dataset.py \
        --steps data/finetune/pentest-r1/data/steps \
        --out   data/finetune
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

SYSTEM_PROMPT = (
    "You are Kryon, an autonomous offensive-security agent. You have ONE tool, "
    "`run_command`, which runs a single shell command on the Kali attack box and "
    "returns its output.\n"
    "Operate as a tight loop: read the previous observation, reason briefly, then "
    "EITHER call `run_command` with the single next command that advances the "
    "objective, OR — when the objective is met — STOP and report the result. "
    "Never repeat a command that already ran, never loop, and do not call a tool "
    "once the goal is achieved."
)

# Tool spec passed to the tokenizer's apply_chat_template(tools=...) at train time.
RUN_COMMAND_TOOL = {
    "type": "function",
    "function": {
        "name": "run_command",
        "description": "Run a single shell command on the Kali attack box and return its stdout/stderr.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The exact shell command to run."}
            },
            "required": ["command"],
        },
    },
}

# Heuristics to label a walkthrough's terminal step (for the STOP turn wording).
_SUCCESS_MARKERS = ("flag", "captured", "completed", "root.txt", "shell", "uid=0", "compromis")


def _stop_message(last_result: str) -> dict:
    """Build the explicit STOP turn — the assistant concludes and does NOT
    emit another tool_call. This is the anti-loop / convergence signal."""
    low = last_result.lower()
    confirmed = any(m in low for m in _SUCCESS_MARKERS)
    if confirmed:
        body = (
            "Objective achieved — the goal was confirmed by the last observation. "
            "Stopping here; no further commands are needed."
        )
    else:
        body = (
            "I have gathered the relevant evidence above and the objective is met. "
            "Stopping here rather than issuing redundant commands."
        )
    return {"role": "assistant", "content": body}


def convert_walkthrough(data: dict, wid: str) -> list[dict] | None:
    initial = (data.get("initial_prompt") or "").strip()
    steps = data.get("steps") or []
    if not initial or not steps:
        return None

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Goal: {initial}\n\nWhat is the next command?"},
    ]
    last_result = ""
    for step in steps:
        thought = (step.get("thought") or "").strip()
        command = (step.get("command") or "").strip()
        result = (step.get("result") or "").strip()
        if not command:
            continue
        call_id = f"call_{wid}_{step.get('step_number', len(messages))}"
        messages.append(
            {
                "role": "assistant",
                "content": thought,
                "tool_calls": [
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": "run_command",
                            # arguments is a JSON *string* (matches run_to_jsonl.py).
                            "arguments": json.dumps({"command": command}),
                        },
                    }
                ],
            }
        )
        messages.append({"role": "tool", "tool_call_id": call_id, "content": result})
        last_result = result

    if len(messages) <= 2:  # no usable steps
        return None
    messages.append(_stop_message(last_result))
    return messages


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--steps", default="data/finetune/pentest-r1/data/steps")
    ap.add_argument("--out", default="data/finetune")
    ap.add_argument("--val-frac", type=float, default=0.1)
    args = ap.parse_args()

    steps_dir = Path(args.steps)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(steps_dir.glob("*.json"))
    if not files:
        print(f"no walkthroughs under {steps_dir}")
        return 1

    examples: list[dict] = []
    skipped = 0
    for fp in files:
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            skipped += 1
            continue
        msgs = convert_walkthrough(data, fp.stem)
        if msgs is None:
            skipped += 1
            continue
        examples.append({"messages": msgs})

    # Deterministic split by walkthrough (no step leakage across train/val).
    n_val = max(1, int(len(examples) * args.val_frac))
    val, train = examples[:n_val], examples[n_val:]

    (out_dir / "tools.json").write_text(json.dumps([RUN_COMMAND_TOOL], indent=2), encoding="utf-8")
    for name, rows in (("train", train), ("val", val)):
        path = out_dir / f"{name}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    turns = [len(e["messages"]) for e in examples]
    print(f"walkthroughs={len(files)}  converted={len(examples)}  skipped={skipped}")
    print(f"train={len(train)}  val={len(val)}")
    print(f"messages/example: min={min(turns)} max={max(turns)} avg={sum(turns) / len(turns):.1f}")
    print(f"wrote {out_dir}/train.jsonl, val.jsonl, tools.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
