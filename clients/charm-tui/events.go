package main

// AgentEvent mirrors kryon.services.agent_events.AgentEvent.to_dict() — the
// flattened {kind, seq, ...payload} JSON shape streamed over SSE by the Kryon
// server (`GET /runs/{id}/stream` when the run was created with rich_events).
//
// The Python side is the source of truth (services/agent_events.py); keep the
// json tags in lock-step with the factory helpers there. Every payload field of
// every kind is represented here (omitempty on absent fields), so a single
// struct decodes any event without a per-kind type switch at the JSON layer.
type AgentEvent struct {
	Kind string `json:"kind"`
	Seq  int    `json:"seq"`

	// turn_start / turn_end
	TurnIndex int `json:"turn_index,omitempty"`

	// engine_phase / done
	Note           string `json:"note,omitempty"`
	FindingsCount  int    `json:"findings_count,omitempty"`
	ReportMarkdown string `json:"report_markdown,omitempty"`

	// pre_hook
	Name string `json:"name,omitempty"`

	// thinking
	Text string `json:"text,omitempty"`

	// tool_started / tool_output
	Tool        string  `json:"tool,omitempty"`
	ArgsSummary string  `json:"args_summary,omitempty"`
	StepID      int     `json:"step_id,omitempty"`
	Status      string  `json:"status,omitempty"`
	DurationS   float64 `json:"duration_s,omitempty"`
	Summary     string  `json:"summary,omitempty"`
	Output      string  `json:"output,omitempty"`
	Collapsed   bool    `json:"collapsed,omitempty"`

	// finding
	Severity string `json:"severity,omitempty"`
	Detail   string `json:"detail,omitempty"`
	CWE      string `json:"cwe,omitempty"`
	Location string `json:"location,omitempty"`
	Verified bool   `json:"verified,omitempty"`

	// assistant
	Markdown string `json:"markdown,omitempty"`

	// reflection — reuses Note

	// error
	Message string `json:"message,omitempty"`
}

// Event kinds — mirror kryon.services.agent_events.EventKind.
const (
	KindTurnStart   = "turn_start"
	KindEnginePhase = "engine_phase"
	KindPreHook     = "pre_hook"
	KindThinking    = "thinking"
	KindToolStarted = "tool_started"
	KindToolOutput  = "tool_output"
	KindFinding     = "finding"
	KindAssistant   = "assistant"
	KindReflection  = "reflection"
	KindTurnEnd     = "turn_end"
	KindDone        = "done"
	KindError       = "error"
)

// IsTerminal reports whether this event ends the turn stream.
func (e AgentEvent) IsTerminal() bool {
	return e.Kind == KindTurnEnd
}
