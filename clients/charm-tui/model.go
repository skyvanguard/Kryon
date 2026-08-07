package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
)

// --- Bubbletea messages ---

type runStartedMsg struct {
	runID string
	ch    <-chan AgentEvent
	err   error
}

type eventMsg AgentEvent

type streamClosedMsg struct{}

// synthetic kind used only in the local log to echo the user's prompt.
const kindUser = "_user"

// --- Model (Elm architecture) ---

type mode int

const (
	modeInput   mode = iota // waiting for the operator to type a prompt
	modeRunning             // a turn is streaming
)

type model struct {
	client   *Client
	maxTurns int

	mode    mode
	events  []AgentEvent
	status  string
	errText string

	ch          <-chan AgentEvent
	runID       string    // active server run — cancelled on quit
	currentTool string    // tool currently executing (between started/output)
	toolStart   time.Time // when the current tool began
	viewport    viewport.Model
	spinner     spinner.Model
	input       textinput.Model
	md          *glamour.TermRenderer

	initialPrompt string    // optional prompt passed on the CLI (run once at startup)
	tick          int       // drives the pulsing Ghost eye on the welcome banner
	turnStart     time.Time // when the current turn began (for the live elapsed)

	// live session state — the header/eye/spinner react to these.
	peakSev   string         // peak finding severity seen this session
	sevCounts map[string]int // findings by severity
	toolCount int            // tools invoked
	phase     string         // "recon" | "exploit" | "report"
	critical  bool           // a CRITICAL landed (persistent alert)

	width, height int
	ready         bool
}

func newModel(client *Client, initialPrompt string, maxTurns int) model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(colAccent)

	ti := textinput.New()
	ti.Placeholder = "auditá https://…   ·   qué CVEs aplican a nginx 1.18"
	ti.Prompt = ""
	ti.CharLimit = 4000
	ti.Focus()

	// Initialise the viewport + markdown renderer up-front with sane defaults so
	// the TUI renders the welcome banner IMMEDIATELY — no dependency on the first
	// WindowSizeMsg arriving (which, over docker exec + SSH, can lag behind the
	// terminal's background query and leave the screen stuck at "iniciando…").
	vp := viewport.New(90, 20)
	md, _ := glamour.NewTermRenderer(glamour.WithStandardStyle("dark"), glamour.WithWordWrap(86))
	m := model{
		client:        client,
		maxTurns:      maxTurns,
		mode:          modeInput,
		spinner:       sp,
		input:         ti,
		status:        "listo",
		sevCounts:     map[string]int{},
		initialPrompt: strings.TrimSpace(initialPrompt),
		viewport:      vp,
		md:            md,
		ready:         true,
	}
	m.viewport.SetContent(m.renderLog())
	return m
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.spinner.Tick, textinput.Blink}
	if m.initialPrompt != "" {
		cmds = append(cmds, m.submit(m.initialPrompt))
	}
	return tea.Batch(cmds...)
}

// submit kicks off a turn for `prompt` (POST /runs + open the SSE stream).
func (m model) submit(prompt string) tea.Cmd {
	return func() tea.Msg {
		runID, err := m.client.StartRun(prompt, m.maxTurns)
		if err != nil {
			return runStartedMsg{err: err}
		}
		ch, err := m.client.StreamEvents(runID)
		return runStartedMsg{runID: runID, ch: ch, err: err}
	}
}

func waitForEvent(ch <-chan AgentEvent) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return streamClosedMsg{}
		}
		return eventMsg(ev)
	}
}

func (m *model) beginTurn(prompt string) tea.Cmd {
	m.events = append(m.events, AgentEvent{Kind: kindUser, Note: prompt})
	m.mode = modeRunning
	m.status = "conectando…"
	m.errText = ""
	m.phase = "" // fresh kill-chain for this turn (counters accumulate)
	m.turnStart = time.Now()
	m.input.Reset()
	m.input.Blur()
	m.refreshLog()
	return m.submit(prompt)
}

// track updates the live session state the header/eye/spinner react to.
func (m *model) track(ev AgentEvent) {
	switch ev.Kind {
	case KindFinding:
		sev := strings.ToUpper(ev.Severity)
		m.sevCounts[sev]++
		if sevRank(sev) > sevRank(m.peakSev) {
			m.peakSev = sev
		}
		if sev == "CRITICAL" {
			m.critical = true
		}
	case KindToolStarted:
		m.toolCount++
		m.currentTool = ev.Tool
		m.toolStart = time.Now()
	case KindToolOutput:
		m.currentTool = ""
	}
	m.phase = phaseFor(ev.Kind, ev.Tool, m.phase)
}

// totalFindings sums findings across severities.
func (m model) totalFindings() int {
	n := 0
	for _, c := range m.sevCounts {
		n += c
	}
	return n
}

func (m *model) endTurn(status string) {
	m.mode = modeInput
	m.status = status
	m.ch = nil
	m.runID = ""
	m.currentTool = ""
	m.input.Focus()
}

// cancelCmd cancels the active server run (used on Ctrl+C, sequenced before Quit).
func (m model) cancelCmd() tea.Cmd {
	rid, client := m.runID, m.client
	return func() tea.Msg {
		client.Cancel(rid)
		return nil
	}
}

func (m *model) refreshLog() {
	if m.ready {
		m.viewport.SetContent(m.renderLog())
		m.viewport.GotoBottom()
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		vh := msg.Height - 4 // header + input/footer + spacing
		if vh < 1 {
			vh = 1
		}
		m.input.Width = maxInt(10, msg.Width-16)
		// Viewport + md renderer already exist (newModel); just resize. The body
		// panel has a rounded border (−2 cols, −2 rows) and there's a header (1) +
		// footer (1). Fixed dark style — WithAutoStyle queries OSC 11 and can block.
		m.viewport.Width = maxInt(20, msg.Width-2)
		m.viewport.Height = vh
		m.md, _ = glamour.NewTermRenderer(glamour.WithStandardStyle("dark"), glamour.WithWordWrap(maxInt(20, msg.Width-6)))
		m.refreshLog()

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			// Cancel the active server run BEFORE quitting so it doesn't keep
			// running headless (and pile up across sessions).
			if m.runID != "" {
				return m, tea.Sequence(m.cancelCmd(), tea.Quit)
			}
			return m, tea.Quit
		case "esc":
			if m.mode == modeInput {
				return m, tea.Quit
			}
		case "enter":
			if m.mode == modeInput {
				prompt := strings.TrimSpace(m.input.Value())
				if prompt != "" {
					cmds = append(cmds, m.beginTurn(prompt))
				}
				return m, tea.Batch(cmds...)
			}
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
		// Pulse the welcome-banner eye while the log is still empty.
		m.tick++
		// Repaint on ticks while empty (banner pulse) or running (live working
		// line + elapsed), so the body never looks frozen during a slow turn.
		if len(m.events) == 0 || m.mode == modeRunning {
			m.refreshLog()
		}

	case runStartedMsg:
		if msg.err != nil {
			m.errText = msg.err.Error()
			m.endTurn("error")
		} else {
			m.ch = msg.ch
			m.runID = msg.runID
			m.status = "auditando…"
			cmds = append(cmds, waitForEvent(m.ch))
		}

	case eventMsg:
		ev := AgentEvent(msg)
		m.events = append(m.events, ev)
		m.track(ev)
		m.status = statusFor(ev)
		m.refreshLog()
		if ev.IsTerminal() {
			m.endTurn("listo")
		} else {
			cmds = append(cmds, waitForEvent(m.ch))
		}

	case streamClosedMsg:
		m.endTurn("stream cerrado")
	}

	// Route residual input to the text field (typing) or the viewport (scroll).
	if m.mode == modeInput {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		cmds = append(cmds, cmd)
	} else if m.ready {
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	var bottom string
	switch {
	case m.errText != "":
		bottom = styleErr.Render("  ⚠ "+m.errText) + "\n" + m.promptLine()
	case m.mode == modeRunning:
		bottom = m.runningFooter()
	default:
		bottom = m.promptLine()
	}
	return lipgloss.JoinVertical(lipgloss.Left, m.renderHeader(), m.bodyPanel(), bottom)
}

// bodyPanel frames the scrollable event log in a rounded border (the lazygit /
// Crush look) — turns a flat text stream into a designed panel.
func (m model) bodyPanel() string {
	return lipgloss.NewStyle().
		Width(m.viewport.Width). // force exact content width → clean, non-ragged border
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colSteel).
		Render(m.viewport.View())
}

// renderHeader: the live mark (eye tinted by peak severity) + findings/tools
// counters + kill-chain phase + a CRITICAL alert bar when one has landed.
func (m model) renderHeader() string {
	eyeCol := sevColor(m.peakSev)
	mark := lipgloss.NewStyle().Foreground(colSteel).Render("◀") +
		lipgloss.NewStyle().Foreground(eyeCol).Bold(true).Render("◉") +
		lipgloss.NewStyle().Foreground(colSteel).Render("▶")

	left := " " + mark + " " + styleGhost.Render("KRYON") + styleDim.Render("  ·  ofensivo autónomo")

	var right []string
	if n := m.totalFindings(); n > 0 {
		right = append(right, severityStyle(m.peakSev).Render(fmt.Sprintf("%s %d findings", severityGlyph(m.peakSev), n)))
	}
	if m.toolCount > 0 {
		right = append(right, styleDim.Render(fmt.Sprintf("▸ %d tools", m.toolCount)))
	}
	if m.mode == modeRunning {
		label, glyph, col := phaseInfo(m.phase)
		right = append(right, lipgloss.NewStyle().Foreground(col).Bold(true).Render(glyph+" "+label))
	}
	rightStr := strings.Join(right, styleDim.Render("   ·   "))
	if m.critical {
		crit := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff")).Background(colErr).Bold(true).Render(" ⚠ CRITICAL ")
		if rightStr != "" {
			rightStr = crit + "  " + rightStr
		} else {
			rightStr = crit
		}
	}

	w := m.width
	if w < 20 {
		w = 20
	}
	gap := w - lipgloss.Width(left) - lipgloss.Width(rightStr) - 1
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + rightStr + " "
}

// runningFooter: a phase-tinted spinner + phase label while a turn streams.
func (m model) runningFooter() string {
	label, glyph, col := phaseInfo(m.phase)
	phaseTag := lipgloss.NewStyle().Foreground(col).Bold(true).Render(glyph + " " + label)
	return m.spinner.View() + " " + phaseTag + styleFooter.Render("  ·  "+m.status+"  ·  Ctrl+C sale")
}

// promptLine renders the interactive input row: the Ghost marker (eye tinted by
// peak severity) + the field.
func (m model) promptLine() string {
	marker := lipgloss.NewStyle().Foreground(sevColor(m.peakSev)).Bold(true).Render("◆ ") +
		styleToolName.Render("KRYON") + lipgloss.NewStyle().Foreground(colSteel).Render("❯ ")
	return marker + m.input.View() + styleFooter.Render("   ·   Enter corre · Ctrl+C sale")
}

// --- rendering ---

func (m model) renderLog() string {
	if len(m.events) == 0 {
		// Centre the welcome banner in the panel (also pads every line to the full
		// width → clean, non-ragged border).
		banner := ghostBanner(eyeFrame(m.tick/8), sevColor(m.peakSev))
		return lipgloss.Place(m.viewport.Width, m.viewport.Height, lipgloss.Center, lipgloss.Center, banner)
	}
	var b strings.Builder
	for _, ev := range m.events {
		s := m.renderEvent(ev)
		if s == "" {
			continue
		}
		b.WriteString(s)
		b.WriteString("\n")
	}
	// Live "working" line so the body never looks frozen during a slow turn.
	// When a tool is mid-flight, name it + its own elapsed (you SEE which command
	// is running for how long); otherwise the model is reasoning between tools.
	if m.mode == modeRunning {
		_, glyph, col := phaseInfo(m.phase)
		var label string
		if m.currentTool != "" {
			label = fmt.Sprintf("▸ %s corriendo   ·   %ds", m.currentTool, int(time.Since(m.toolStart).Seconds()))
		} else {
			label = fmt.Sprintf("%s Kryon razonando   ·   %ds", glyph, int(time.Since(m.turnStart).Seconds()))
		}
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(col).Bold(true).Render(m.spinner.View() + " " + label))
		b.WriteString("\n")
	}
	return b.String()
}

func (m model) renderEvent(ev AgentEvent) string {
	switch ev.Kind {
	case kindUser:
		return lipgloss.NewStyle().Foreground(colSteel).Render("❯ ") + styleText.Render(ev.Note)
	case KindEnginePhase:
		return styleNotice.Render("◆ " + ev.Note)
	case KindPreHook:
		return styleToolMark.Render("▸ ") + styleDim.Render(ev.Name)
	case KindToolStarted:
		s := styleToolMark.Render("▸ ") + styleToolName.Render(ev.Tool)
		if ev.ArgsSummary != "" {
			s += "  " + styleArgs.Render(ev.ArgsSummary)
		}
		return s
	case KindToolOutput:
		mark := styleOK.Render("✓")
		if ev.Status == "error" {
			mark = styleErr.Render("✗")
		} else if ev.Status == "warn" {
			mark = styleWarn.Render("!")
		}
		line := "  " + mark + styleDim.Render(fmt.Sprintf("  %.1fs", ev.DurationS))
		if ev.Summary != "" {
			line += styleDim.Render("  ·  ") + styleText.Render(ev.Summary)
		}
		// Preview the command output inline (gutter │) so it reads like a terminal.
		if strings.TrimSpace(ev.Output) != "" {
			for _, ln := range previewLines(ev.Output, 6) {
				line += "\n" + styleDim.Render("    │ ") + styleText.Render(ln)
			}
			if ev.Collapsed {
				line += "\n" + styleDim.Render(fmt.Sprintf("    │ … /show %d para el resto", ev.StepID))
			}
		}
		return line
	case KindFinding:
		sev := strings.ToUpper(ev.Severity)
		if sev == "CRITICAL" {
			// A landed CRITICAL gets a filled red bar — impossible to miss.
			tag := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff")).Background(colErr).Bold(true).Render(" ◈ CRITICAL ")
			return tag + " " + styleText.Render(ev.Detail)
		}
		st := severityStyle(sev)
		return st.Render(severityGlyph(sev)+" "+sev) +
			styleDim.Render("  ·  ") + styleText.Render(ev.Detail)
	case KindThinking:
		return styleDim.Render(ev.Text)
	case KindReflection:
		return styleNotice.Render("🪞 " + ev.Note)
	case KindAssistant:
		return styleGhost.Render("◇ Kryon") + "\n" + m.renderMarkdown(ev.Markdown)
	case KindDone:
		if strings.TrimSpace(ev.ReportMarkdown) != "" {
			return m.renderMarkdown(ev.ReportMarkdown)
		}
		return ""
	case KindError:
		return styleErr.Render("⚠ " + ev.Message)
	default:
		return ""
	}
}

func (m model) renderMarkdown(md string) string {
	if m.md == nil {
		return md
	}
	out, err := m.md.Render(md)
	if err != nil {
		return md
	}
	return strings.TrimRight(out, "\n")
}

// statusFor gives the footer a live, on-brand verb per event.
func statusFor(ev AgentEvent) string {
	switch ev.Kind {
	case KindEnginePhase:
		return "determinismo…"
	case KindToolStarted:
		return ev.Tool + "…"
	case KindFinding:
		return "hallazgo: " + ev.Severity
	case KindAssistant:
		return "narrando…"
	case KindReflection:
		return "reflexionando…"
	case KindDone, KindTurnEnd:
		return "listo"
	default:
		return "auditando…"
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// previewLines returns up to n non-empty lines of s for a compact terminal-style
// output preview (drops blank lines, trims trailing space).
func previewLines(s string, n int) []string {
	var out []string
	for _, ln := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		ln = strings.TrimRight(ln, " \t")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		if len(ln) > 160 {
			ln = ln[:157] + "…"
		}
		out = append(out, ln)
		if len(out) >= n {
			break
		}
	}
	return out
}
