# REPL Rendering Audit (Fase 0)

> Status: audit baseline
> Date: 2026-04-29
> Owner: skyvanguard
> Scope: `src/kryon/util/streaming.py` + `src/kryon/util/message_utils.py`

This document maps every render path the user sees during a turn,
identifying which functions construct which panels and their purpose.
Used as the contract for Fases 1–6 of the REPL redesign.

## Public entrypoints (the SDK lifecycle)

| Function | Trigger | Renders |
|---|---|---|
| `start_tool_streaming(tool_name, args, call_id, token_info)` | Agent decides to call a tool. Fired by `RunHooks.on_tool_start`. | Header line + "Executing Command" panel + Live stream panel |
| `update_tool_streaming(tool_name, args, output, call_id, ...)` | Tool emits output incrementally. | Live update inside the streaming panel |
| `finish_tool_streaming(tool_name, args, output, call_id, exec_info, token_info)` | Tool returned. Fired by `RunHooks.on_tool_end`. | "Completed" wrapper panel + tool output panel + token footer |
| `create_agent_streaming_context(agent_name, counter, model)` | Agent starts emitting its narrative reply. | Empty Live panel ready to fill |
| `update_agent_streaming_content(context, text_delta, token_stats)` | Each markdown token from the LLM. | Live update of the content panel |
| `finish_agent_streaming(context, final_stats)` | Agent finishes its narrative. | Final "Stream" panel with `╭─ Kryon ─╮` border, markdown body, token footer |

## Panel inventory (13 Panel constructors)

| Line | Variable | Title | Border | Purpose | Plan |
|----:|---|---|---|---|---|
| 643 | `actual_panel1` | (dynamic) | dynamic (cyan/yellow/red) | execute_code main panel | Keep, semantic borders OK |
| 674 | `output_panel` | "Container Output" | cyan | execute_code container stdout | **Replace** with `render_tool_completion` collapse-aware |
| 687 | `output_panel` | "Container Output" | cyan | execute_code error path | **Replace** same as 674 |
| 719 | `output_display_panel` | "Output" / "Logs" | cyan | execute_code logs/output | **Replace** same |
| 943 | `panel` | (dynamic) | dynamic (yellow/green/red) | Generic tool panel for non-execute_code | **Replace** entirely |
| 1170 | `panel` | (dynamic) | dynamic (blue/green/red) | `cli_print_tool_output` main panel | **Replace** entirely |
| 1199 | `command_panel` | "Executing Command" | cyan | The azure panel above the tool output | **REMOVE** — collapsed into 1-line `▸ tool args` |
| 1257 | `panel` | "Stream" | cyan | Live streaming panel for tools | **Reduce** scope — only when output > 8 lines |
| 1376 | `updated_panel` | "Stream" | cyan | Live update during agent streaming | **REMOVE** panel — markdown plano |
| 1514 | `final_panel` | "Stream" | cyan | The `╭─ Kryon ─╮` envelope of agent reply | **REMOVE** — Fase 4 |
| 1635 | `code_panel` | "Code Submitted" | cyan | execute_code source preview | Keep, syntax-highlighted code earns the box |
| 1765 | `code_panel` | "Code Submitted" | cyan | execute_code source preview (other branch) | Keep |
| 1921 | `output_panel` | (dynamic) | dynamic (green/red) | execute_code completion output | Keep, semantic borders OK |

## What the user sees per tool call (today)

```
╭─ Kryon - Executing Command ────────────────────╮  ← line 1199 (REMOVE)
│ {"command":"echo 'Hola'","interactive":false}  │
╰────────────────────────────────────────────────╯

╭─ Kryon - run_command(command=echo 'Hola', interactive=False) [Completed] ╮  ← line 1170 (REPLACE)
│ run_command(...) [Total: 46.3s | Tool: 0.0s]                              │
│                                                                            │
│ ╭─ Command Output ─────────────────────────────╮                          │  ← line 943 (REPLACE)
│ │ ¡Hola!                                       │                          │
│ ╰──────────────────────────────────────────────╯                          │
│                                                                            │
│ Current: I:0 O:0 R:0 ($0.0000) | Total: I:5066 O:112 R:0 | Session: ...  │  ← Already guarded
╰────────────────────────────────────────────────────────────────────────────╯
```

**3 nested panels for one `echo`.** ~25 vertical lines.

## What the user will see (target after Fases 1-6)

```
▸ run_command  echo '¡Hola!'
  ╭ output ─────────╮
  │ ¡Hola!          │
  ╰─────────────────╯
  ✓ 0.0s · 1 line · /show 1
```

**Zero nesting, 5 vertical lines, output ≤ 8 lines stays inline. Long
outputs collapse to `… N lines · /show N`.**

## Helpers map (called by entrypoints)

| Function | Called from | Purpose | Plan |
|---|---|---|---|
| `_format_tool_args` (277) | finish_tool_streaming | Pretty-print args dict | Keep, simplify output |
| `_get_timing_info` (313) | finish_tool_streaming | "[Total: 46.3s | Tool: 0.0s]" | Keep, integrate inline |
| `_create_token_display` (335) | various | Token stats text | Keep, used by Fase 5 footer |
| `_create_token_info_display` (401) | finish_agent_streaming | Token info | Replace by Fase 5 compact footer |
| `_print_simple_tool_output` (430) | unused-ish | Simple output path | Probably delete |
| `_create_tool_panel_content` (504) | cli_print_tool_output | Build the panel content | **Major rewrite** in Fase 1 |
| `cli_print_tool_output` (743) | finish_tool_streaming | The big render fn | **Replace** by `tool_call_renderer` |

## `message_utils.py` render paths

| Function | Purpose | Plan |
|---|---|---|
| `render_token_usage_panel` (~858) | Footer with `Current: ... | Total: ... | Session:` | **Replace** by Fase 5 compact footer |
| Panel at line 661 | (unidentified — likely error/info display) | Audit deeper if needed |
| Panel at lines 1148, 1158 | Reasoner Agent / blue agent panels | Audit deeper if needed |

## Status colors (semantic — KEEP these)

These borders ARE semantic status signals and should remain colored
distinctly from chrome:

- `red` border (lines 924, 1123, 1125, 1918) — error / failure
- `yellow` border (lines 631, 922) — warning / partial
- `green` border (line 1121, 1915) — success state — change to **cyan** since
  "completed OK" is the default state in palette B; reserve green
  exclusively for explicit PASS findings in compliance reports.

## Replacement strategy for Fase 3

Per-callsite replacement, ordered by safety:

1. **Lines 1199, 1170, 943** (the Executing/Completed wrappers + nested
   tool output panel) → call `render_tool_invocation` + `render_tool_completion`.
2. **Line 1376, 1514** (agent streaming) → markdown plain, no panel.
3. **Lines 674, 687, 719** (execute_code outputs) → use `render_tool_completion`
   collapse logic; box-style preserved for code only.
4. **Lines 1257, 1921** (Stream panel + execute output) → reduce scope
   to only-when-needed (output > 8 lines).
5. **Lines 643, 1635, 1765** (execute_code main + code preview) — KEEP.
   syntax-highlighted code earns the box; semantic colors are signal.

## Risk register

| Risk | Probability | Mitigation |
|---|---|---|
| Output truncation hides finding from auditor | Low | JSONL log retains full output; `/show N` recovers |
| Live streaming flicker when removing Stream panel | Medium | Keep Live for output > 8 lines; remove for short |
| `execute_code` (sandboxed RCE) loses its prominent panel | Low | KEEP execute_code panels (lines 643, 1635, 1765) |
| `cli_print_tool_output` (line 743) is 480 LOC of conditionals | High | Rewrite as smaller `tool_call_renderer` + delete the helper |
| `_create_tool_panel_content` is 240 LOC dispatcher | High | Same — replace by 3 simple functions |

## Lines of code accounting

- `streaming.py`: 1968 LOC current → estimated 1200 LOC after redesign (-40%).
- `message_utils.py`: footer function 60 LOC → 20 LOC after Fase 5.
- New `tool_call_renderer.py`: ~250 LOC.
- New `tool_output_buffer.py`: ~80 LOC.
- New `repl/commands/show.py`: ~60 LOC.

Net change: ~−500 LOC + better separation of concerns.

## Constants (for Fases 1-6 implementation reference)

```python
COLLAPSE_THRESHOLD_LINES = 8   # Output > 8 lines → collapsed
OUTPUT_PREVIEW_BYTES = 4096    # Chars of output kept in step buffer; full goes to JSONL
INLINE_PANEL_BORDER = "cyan"   # Palette B chrome
SEMANTIC_ERROR = "red"         # Tool failure
SEMANTIC_WARN = "yellow"       # Partial / N/A
SEMANTIC_PASS = "green"        # Reserved: explicit PASS in compliance only
```

## Open questions

1. **What about `update_tool_streaming` mid-flight updates?** Today they
   redraw the Live panel as the tool emits chunks. New design: skip the
   live panel for ≤ 8 line outputs, only show after completion. Live
   stays for execute_code (long outputs expected).

2. **Spinner behavior during long tool execution?** Already covered by
   `repl/ui/spinner.py` (mejorado en sesión actual). Status display
   while tool runs comes from spinner, not streaming.py — no change needed.

3. **Tool name "namespacing"** — currently `run_command:nmap` is
   sometimes shown as `run_command(command=nmap...)`. Should be just
   `run_command  nmap -sV target`. Strip the verbose Python-call format.
