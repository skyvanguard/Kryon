# Kryon REPL — Visual Design (F77.D)

This document describes the operator-visible terminal UI of the Kryon REPL
after the Fase 0–7 redesign. It is the source of truth — if code drifts from
this document, fix the code.

## Goals

- **Density**: a single tool call must fit in ≤ 5 vertical lines on a normal
  terminal. The legacy CAI-fork pipeline rendered ~12 lines (3 nested panels)
  per call; that's gone.
- **Hierarchy**: the agent's narrative reply has no border; tool invocations
  have a 1-line glyph; only collapsed output gets a panel. The visual weight
  matches the semantic weight.
- **Recoverability**: outputs longer than `COLLAPSE_THRESHOLD_LINES` (8) are
  collapsed inline and recoverable via `/show <step_id>`.
- **Palette B** (cybersec modern): cyan primary + magenta secondary. Semantic
  colors (red=error, green=ok, yellow=warn) are reserved for status — not
  decoration.
- **Local-first**: cost displays are gated behind `_hide_cost()` because the
  recommended runtime is local Ollama (free). Token counts stay; cost goes.

## Anatomy of a turn

```
─────────────────────────  per-turn status line  ──────────────────────────
skills: fortigate-audit · ollama: kryon-14b · drafts: 0 · last-exp: e_42
                                                                          ←
operator narrative answer rendered as Markdown, no border, no title       ←  agent body (Live + Markdown)
                                                                          ←
[hh:mm:ss (kryon-14b)] I:1500 O:250 · ctx 5% OK                           ←  compact footer

▸ run_command  echo hello                                                 ←  invocation glyph (1 line)
  ✓ 0.4s  ·  2 lines                                                      ←  completion glyph (1 line)
┌─ output ─┐                                                              ←  inline panel (≤ 8 lines)
│ hello    │
│ world    │
└──────────┘
```

If the output is > 8 lines, the panel is replaced with:

```
▸ nmap  10.0.0.1
  ✓ 8.1s  ·  40 lines  ·  40 lines  ·  /show 3
```

The operator types `/show 3` to recover the full body (printed between two
horizontal Rules).

## Layers

### 1. Tool call renderer (Fase 1)

`src/kryon/repl/ui/tool_call_renderer.py` — three primitives:

- `render_tool_invocation(tool_name, args_summary, console)`
  → 1-line cyan glyph: `▸ tool_name  arg-preview`
- `render_tool_completion(tool_name, duration_s, status, summary, output,
  console, step_id)` → 1-line glyph + inline panel ≤ 8 lines OR collapse hint
- `render_collapsed_output(full_output, step_id, tool_name, console)` →
  full body between Rules, used by `/show <N>`

Status mapping (semantic):
- `ok` → green check `✓`
- `warn` → yellow `!`
- `error` → red cross `✗`

`summarize_args(tool_name, args)` strips Python-call form
(`run_command(command='nmap …')` → `nmap …`) using the `_PRIMARY_ARG`
table — extend this table when adding new tools, don't invent ad-hoc parsers.

### 2. Per-turn output buffer (Fase 2)

`src/kryon/repl/ui/tool_output_buffer.py` — thread-safe, per-turn singleton.

- `record(tool_name, output) -> step_id` — call from the renderer when the
  output is collapsed
- `get(step_id) -> dict | None` — `/show` reads this
- `new_turn()` — REPL calls this at the start of each turn
- `MAX_OUTPUT_BYTES_PER_STEP = 65_536` (above that, the body is truncated
  with a marker — protects RAM during long sessions)
- `MAX_STEPS_PER_TURN = 256`

### 3. `/show <N>` (Fase 2)

`src/kryon/repl/commands/show.py` — `Command.handler` looks up `step_id`
in the buffer and calls `render_collapsed_output`. If the step is unknown,
prints a friendly error.

### 4. Streaming integration (Fase 3)

`src/kryon/util/streaming.py`:

- `start_tool_streaming(tool_name, args, …)` — for non-`execute_code` tools,
  short-circuits to `render_tool_invocation` (the 1-line glyph). The legacy
  "Executing Command" panel remains only for `execute_code`.
- `finish_tool_streaming(tool_name, args, output, execution_info, …)` —
  for non-`execute_code`, delegates to `_render_simple_tool_completion`
  which builds the status from `execution_info` and calls
  `render_tool_completion`.
- `cli_print_tool_output(…)` (legacy entrypoint, still called by parallel
  agents and the model adapter) has the same delegation block at the top.

### 5. Agent narrative (Fase 4)

`create_agent_streaming_context` / `update_agent_streaming_content` /
`finish_agent_streaming` no longer wrap content in a `Panel(title="Stream",
border_style="cyan")`. The Live region renders `Text.assemble(header, content,
footer)` (or `Group(header, body, tokens, footer)` for the final Markdown
body) directly. The `╭─ Stream ─╮` envelope is gone.

### 6. Token footer (Fase 5)

`_create_token_display` (in both `message_utils.py` and `streaming.py`)
returns a single `Text` line:

```
I:1500 O:250 · ctx 5% OK
```

- `R:` is hidden when reasoning_tokens == 0
- `($cost)` is hidden when `_hide_cost()` returns True (Ollama default)
- `Total:` and `Session:` rollups are removed — they were noise in a
  local-only setup
- `ctx X%` indicator keeps semantic colors (green < 50%, yellow < 80%,
  red ≥ 80%)

### 7. Border palette (Fase 6)

For panels we still render (`execute_code`, parallel agent panels):

| Status     | Border | Title style    |
| ---------- | ------ | -------------- |
| running    | cyan   | `bold cyan`    |
| completed  | green  | `bold green`   |
| error      | red    | `bold red`     |
| timeout    | red    | `bold red`     |

Neutral default is cyan (was blue/yellow). Semantic colors stay.

## Constants

| Name                          | Value  | Where                                              |
| ----------------------------- | ------ | -------------------------------------------------- |
| `COLLAPSE_THRESHOLD_LINES`    | 8      | `tool_call_renderer.py`                            |
| `OUTPUT_PREVIEW_BYTES`        | 4096   | `tool_call_renderer.py`                            |
| `MAX_OUTPUT_BYTES_PER_STEP`   | 65_536 | `tool_output_buffer.py`                            |
| `MAX_STEPS_PER_TURN`          | 256    | `tool_output_buffer.py`                            |

## Testing

- `tests/repl/test_tool_call_renderer.py` — 18 cases (invocation, completion
  ok/warn/error, collapse threshold, args summarization)
- `tests/repl/test_tool_output_buffer.py` — 11 cases (record, get, turn
  rotation, byte cap, step cap, thread safety smoke)
- `tests/repl/test_show_command.py` — `/show` happy path + missing step
- `tests/repl/test_runtime_state.py` — toolbar runtime state contract

Smoke test (manual):

```bash
docker compose -f docker/docker-compose.kali.yml \
  -f docker/docker-compose.override.yml exec kryon kryon
> hola
> /skill list
> /show 1   # if any tool collapsed
```

## What NOT to do

- Do not reintroduce `Panel(..., title="Stream", border_style="cyan")`
  around the agent reply.
- Do not add `cost`, `Session:` or `Total:` to the token footer.
- Do not animate panel borders (yellow→green flash). Status is conveyed by
  the completion glyph (`✓`/`!`/`✗`), not by border color flicker.
- Do not bypass `tool_output_buffer.record()` when collapsing — `/show`
  depends on it.
- Do not raise `COLLAPSE_THRESHOLD_LINES`. The whole point of the redesign
  is density; if a tool produces 30 lines of meaningful summary inline,
  fix the tool's summary, don't slacken the threshold.
