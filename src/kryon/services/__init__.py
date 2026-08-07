"""
KRYON services — cross-cutting concerns ported from Claude Code CLI.

- micro_compact: trim old tool outputs to free context window
- session_memory: auto-maintained session notes file (R2: dedup + cap)
- auto_extract: save experiences on REPL exit
- tool_output_cap: save oversized tool outputs to disk
- lead_tracker: track pending follow-up leads across turns (R4)
- intent_shift: detect objective pivots to re-trigger experience recall (R5)
"""
