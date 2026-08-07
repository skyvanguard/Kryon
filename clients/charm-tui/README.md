# Kryon Charm TUI

A terminal UI for Kryon built on the **Charm stack** (Bubbletea + Lipgloss +
Bubbles + Glamour — all MIT). It drives the **full Kryon** — determinism +
pre_hooks + reflective loop — over the server's rich-events SSE stream, and
renders the same crystalline look as the Rich REPL.

It is a **client**: it does not embed the agent. Kryon's brain stays in Python;
this only renders the `AgentEvent` stream. That keeps the moat (determinism)
intact — unlike forking Crush/OpenCode/Goose, whose agent loops are fixed.

## Architecture

```
kryon-tui  ──POST /runs {rich_events:true, stream:true}──▶  Kryon FastAPI server
    │                                                            │
    └──GET /runs/{id}/stream (SSE: AgentEvent JSON)◀────  turn_service.run_turn
                                                          (determinism → pre_hooks
                                                           → run_with_reflection)
```

- `events.go`  — the `AgentEvent` contract (mirrors `services/agent_events.py`).
- `client.go`  — starts a run + parses the SSE stream into events.
- `model.go`   — the Bubbletea model (Elm: events → Update → View).
- `theme.go`   — Lipgloss styles (Kryon crystalline palette).
- `main.go`    — flags + program bootstrap.

## Build

Needs Go 1.24+.

```sh
go build -o kryon-tui .
```

## Run

The Kryon FastAPI server must be running (`kryon serve`) and reachable.

```sh
export KRYON_SERVER=http://localhost:8000
export KRYON_API_KEY=<your-api-key>
./kryon-tui "auditá https://ejemplo.com"

# or with flags
./kryon-tui --server http://localhost:8000 --api-key KEY --agent kryon "qué CVEs aplican a nginx 1.18"
```

Keys: `q` / `Ctrl+C` quit · arrows / PgUp/PgDn scroll the log.

## Status

Phase 1 scaffold — compiles, `go vet` clean, renders the full event stream
(tool calls, findings with severity colour, `◇ Kryon` markdown, engine/reflection
notices). **Pending:** live end-to-end test against a running `kryon serve`.
