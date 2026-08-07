package main

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Kryon crystalline palette — matches the Rich REPL theme
// (steel-blue #2f6ea6 + electric-cyan #45e0ef light seams) so the Charm TUI and
// the terminal REPL read as the same product.
var (
	colAccent    = lipgloss.Color("#45e0ef") // electric-cyan — primary accent
	colSteel     = lipgloss.Color("#2f6ea6") // steel-blue — secondary
	colDim       = lipgloss.Color("#5f8bb0") // muted context
	colText      = lipgloss.Color("#e6edf3")
	colOK        = lipgloss.Color("#45e0ef")
	colWarn      = lipgloss.Color("#eab308")
	colErr       = lipgloss.Color("#ef4444")
	colHighSev   = lipgloss.Color("#ff8c00")
	colMediumSev = lipgloss.Color("#eab308")
	colLowSev    = lipgloss.Color("#45e0ef")
	colInfoSev   = lipgloss.Color("#5f8bb0")
)

var (
	styleGhost = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	styleTitle = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	styleDim   = lipgloss.NewStyle().Foreground(colDim)
	styleText  = lipgloss.NewStyle().Foreground(colText)

	// tool_started: "▸ name  args"
	styleToolMark = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	styleToolName = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	styleArgs     = lipgloss.NewStyle().Foreground(colText)

	// tool_output completion marker
	styleOK   = lipgloss.NewStyle().Foreground(colOK)
	styleWarn = lipgloss.NewStyle().Foreground(colWarn)
	styleErr  = lipgloss.NewStyle().Foreground(colErr).Bold(true)

	// engine_phase / pre_hook / reflection notices
	styleNotice = lipgloss.NewStyle().Foreground(colSteel)

	// output panel border
	stylePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colSteel).
			Padding(0, 1)

	// footer / status bar
	styleFooter = lipgloss.NewStyle().Foreground(colDim)
)

// severityStyle maps a PCI/CIS-conventional severity to its colour (the severity
// layer NEVER changes with the chrome palette — auditors expect these).
func severityStyle(sev string) lipgloss.Style {
	switch sev {
	case "CRITICAL":
		return lipgloss.NewStyle().Foreground(colErr).Bold(true)
	case "HIGH":
		return lipgloss.NewStyle().Foreground(colHighSev).Bold(true)
	case "MEDIUM":
		return lipgloss.NewStyle().Foreground(colMediumSev)
	case "LOW":
		return lipgloss.NewStyle().Foreground(colLowSev)
	default:
		return lipgloss.NewStyle().Foreground(colInfoSev)
	}
}

func severityGlyph(sev string) string {
	switch sev {
	case "CRITICAL", "HIGH":
		return "◈"
	default:
		return "◆"
	}
}

// ghostBanner renders the crystalline Kryon mark + wordmark — the welcome shown
// while the log is empty. Mirrors the REPL banner so the TUI reads as the same
// product. `eyeGlyph` lets the caller pulse the ◉ eye for a live heartbeat.
func ghostBanner(eyeGlyph string, eyeColor lipgloss.Color) string {
	steel := lipgloss.NewStyle().Foreground(colSteel)
	eye := lipgloss.NewStyle().Foreground(eyeColor).Bold(true)
	if eyeGlyph == "" {
		eyeGlyph = "◉"
	}
	ghost := lipgloss.JoinVertical(lipgloss.Center,
		steel.Render("▲"),
		steel.Render("◤███◥"),
		steel.Render("◀███")+eye.Render(eyeGlyph)+steel.Render("███▶"),
		steel.Render("◣███◢"),
		steel.Render("▼"),
	)
	side := lipgloss.JoinVertical(lipgloss.Left,
		"",
		styleGhost.Render("K R Y O N"),
		styleDim.Render("agente ofensivo autónomo"),
		styleDim.Render("determinismo + IA · toda acción registrada"),
		"",
	)
	body := lipgloss.JoinHorizontal(lipgloss.Center, ghost, "     ", side)
	hint := styleDim.Render("Escribí tu objetivo abajo y Enter:") +
		styleToolName.Render("  \"auditá https://…\"")
	return lipgloss.JoinVertical(lipgloss.Left, "", "", body, "", hint)
}

// eyeFrame picks the ◉ eye glyph for a slow pulse (drives the heartbeat).
func eyeFrame(tick int) string {
	frames := []string{"◉", "◉", "◎", "◉"}
	return frames[tick%len(frames)]
}

// --- severity ranking + colour (the Ghost eye + counters react to these) ---

var sevRankMap = map[string]int{"": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

func sevRank(s string) int { return sevRankMap[strings.ToUpper(s)] }

func sevColor(sev string) lipgloss.Color {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return colErr
	case "HIGH":
		return colHighSev
	case "MEDIUM":
		return colMediumSev
	case "LOW":
		return colLowSev
	default:
		return colInfoSev
	}
}

// --- kill-chain phase (drives the header verb + spinner tint) ---

// phaseInfo maps a phase key to its label, glyph and accent colour.
func phaseInfo(key string) (label, glyph string, col lipgloss.Color) {
	switch key {
	case "recon":
		return "reconocimiento", "🔍", colAccent
	case "exploit":
		return "explotación", "⚔", colHighSev
	case "report":
		return "informe", "📄", colOK
	default:
		return "auditando", "◆", colAccent
	}
}

var exploitTools = []string{
	"nuclei", "sqlmap", "sqli", "xss", "ffuf", "feroxbuster", "hydra", "idor",
	"ssrf", "rce", "exploit", "jwt", "nikto", "metasploit", "msf", "payload",
}

func isExploitTool(tool string) bool {
	t := strings.ToLower(tool)
	for _, e := range exploitTools {
		if strings.Contains(t, e) {
			return true
		}
	}
	return false
}

// phaseFor infers the current kill-chain phase from an event (keeps the last
// phase when the event isn't a phase signal).
func phaseFor(kind, tool, current string) string {
	switch kind {
	case KindEnginePhase, KindPreHook:
		return "recon"
	case KindToolStarted:
		if isExploitTool(tool) {
			return "exploit"
		}
		if current == "" {
			return "recon"
		}
		return current
	case KindFinding:
		if current != "report" {
			return "exploit"
		}
		return current
	case KindAssistant, KindDone:
		return "report"
	default:
		return current
	}
}
