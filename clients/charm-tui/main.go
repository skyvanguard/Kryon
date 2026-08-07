package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func main() {
	base := flag.String("server", envOr("KRYON_SERVER", "http://localhost:8000"), "Kryon server base URL")
	apiKey := flag.String("api-key", os.Getenv("KRYON_API_KEY"), "Kryon API key (X-API-Key)")
	agent := flag.String("agent", "kryon", "agent key")
	maxTurns := flag.Int("max-turns", 14, "max reflective turns")
	flag.Parse()

	// Optional initial prompt. Empty → the TUI opens interactive; you type
	// prompts inside it (REPL-style). Non-empty → it runs that first, then
	// returns to the input for follow-ups.
	initialPrompt := strings.TrimSpace(strings.Join(flag.Args(), " "))

	// Tell lipgloss the background is dark up-front so it doesn't query the
	// terminal (OSC 11) and block over docker exec + SSH.
	lipgloss.SetHasDarkBackground(true)

	client := NewClient(*base, *apiKey, *agent)
	p := tea.NewProgram(newModel(client, initialPrompt, *maxTurns), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
