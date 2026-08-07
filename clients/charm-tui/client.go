package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client talks to the Kryon FastAPI server: it starts a rich-events run and
// streams the resulting AgentEvents over SSE.
type Client struct {
	BaseURL   string // e.g. http://localhost:8000
	APIKey    string // sent as X-API-Key (server require_api_key)
	AgentKey  string // e.g. "kryon"
	SessionID string // #1 continuity — created once, reused across turns
	HTTP      *http.Client
}

// apiV1 is the Kryon server's router prefix (app.py mounts every router under it).
const apiV1 = "/api/v1"

// NewClient builds a Client with a long timeout (runs stream for minutes).
func NewClient(baseURL, apiKey, agentKey string) *Client {
	return &Client{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		APIKey:   apiKey,
		AgentKey: agentKey,
		HTTP:     &http.Client{Timeout: 0}, // no timeout — SSE is long-lived
	}
}

type runRequest struct {
	AgentKey   string `json:"agent_key"`
	Input      string `json:"input"`
	Stream     bool   `json:"stream"`
	RichEvents bool   `json:"rich_events"`
	MaxTurns   int    `json:"max_turns"`
	SessionID  string `json:"session_id,omitempty"`
}

type runResponse struct {
	RunID  string `json:"run_id"`
	Status string `json:"status"`
}

// ensureSession creates a server session once (POST /sessions) so the agent
// REMEMBERS across turns (#1 continuity). Best-effort: on failure the run still
// proceeds, just without cross-turn memory.
func (c *Client) ensureSession() {
	if c.SessionID != "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"agent_key": c.AgentKey})
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+apiV1+"/sessions", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return
	}
	var s struct {
		SessionID string `json:"session_id"`
	}
	if json.NewDecoder(resp.Body).Decode(&s) == nil {
		c.SessionID = s.SessionID
	}
}

func (c *Client) setAuth(req *http.Request) {
	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}
}

// StartRun creates a streaming rich-events run and returns its run_id.
func (c *Client) StartRun(input string, maxTurns int) (string, error) {
	c.ensureSession() // #1 continuity — reuse one session across turns
	body, _ := json.Marshal(runRequest{
		AgentKey:   c.AgentKey,
		Input:      input,
		Stream:     true,
		RichEvents: true,
		MaxTurns:   maxTurns,
		SessionID:  c.SessionID,
	})
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+apiV1+"/runs", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("POST /runs: status %d", resp.StatusCode)
	}
	var rr runResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return "", err
	}
	if rr.RunID == "" {
		return "", fmt.Errorf("POST /runs: empty run_id")
	}
	return rr.RunID, nil
}

// Cancel asks the server to stop a run (DELETE /runs/{id}). Best-effort + bounded
// timeout — called on quit so a Ctrl+C'd turn doesn't keep running server-side.
func (c *Client) Cancel(runID string) {
	if runID == "" {
		return
	}
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s%s/runs/%s", c.BaseURL, apiV1, runID), nil)
	if err != nil {
		return
	}
	c.setAuth(req)
	cl := &http.Client{Timeout: 5 * time.Second}
	if resp, err := cl.Do(req); err == nil {
		resp.Body.Close()
	}
}

// StreamEvents connects to the run's SSE stream and forwards each parsed
// AgentEvent onto the returned channel, closing it when the stream ends (or on
// error, after sending a synthetic error event).
func (c *Client) StreamEvents(runID string) (<-chan AgentEvent, error) {
	url := fmt.Sprintf("%s"+apiV1+"/runs/%s/stream", c.BaseURL, runID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	c.setAuth(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("GET stream: status %d", resp.StatusCode)
	}

	out := make(chan AgentEvent, 64)
	go func() {
		defer close(out)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // large tool outputs
		for sc.Scan() {
			line := sc.Text()
			// SSE data frames: "data: {json}". event: lines carry the kind but
			// the kind is also in the JSON, so we parse only the data payload.
			data, ok := strings.CutPrefix(line, "data: ")
			if !ok {
				continue
			}
			var ev AgentEvent
			if err := json.Unmarshal([]byte(data), &ev); err != nil {
				continue // skip malformed frames rather than kill the stream
			}
			out <- ev
			if ev.IsTerminal() {
				return
			}
		}
		if err := sc.Err(); err != nil {
			out <- AgentEvent{Kind: KindError, Message: fmt.Sprintf("stream read: %v", err)}
		}
	}()

	// A tiny settle so the caller's Bubbletea Cmd doesn't race the goroutine.
	time.Sleep(10 * time.Millisecond)
	return out, nil
}
