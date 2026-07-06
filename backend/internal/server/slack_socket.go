// Slack Socket Mode listener: receives in-message "Re-analyze" button clicks
// over an outbound WebSocket, so no public HTTPS endpoint (domain/ingress) is
// needed for Slack interactivity.
//
// Protocol (https://docs.slack.dev/apis/slack-api/socket-mode):
//  1. POST apps.connections.open with the app-level token (xapp-, scope
//     connections:write) → a one-time wss:// URL
//  2. Read JSON envelopes; every envelope carrying an envelope_id must be
//     acked within 3s or Slack retries the delivery
//  3. Slack periodically sends a "disconnect" envelope to refresh the
//     connection — drop it and reconnect
//
// Requires Socket Mode + Interactivity toggled on in the Slack app settings
// and SLACK_APP_TOKEN in the environment.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const slackReanalyzeActionID = "reanalyze_incident"

type socketEnvelope struct {
	Type       string          `json:"type"`
	EnvelopeID string          `json:"envelope_id"`
	Payload    json.RawMessage `json:"payload"`
}

// runSlackSocketMode keeps one Socket Mode connection alive for the process
// lifetime. Exits immediately when Slack or the app token is not configured.
func (s *Server) runSlackSocketMode(ctx context.Context) {
	if !s.slack.IsConfigured() || s.slack.appToken == "" {
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := s.slackSocketSession(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second // the session was healthy; reset the backoff
		}
		if err != nil {
			log.Printf("slack socket mode: %v (reconnecting in %s)", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// slackSocketSession runs a single WebSocket connection until Slack asks for a
// refresh (nil) or the connection breaks (error).
func (s *Server) slackSocketSession(ctx context.Context) error {
	wssURL, err := s.slack.openSocketURL(ctx)
	if err != nil {
		return err
	}
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wssURL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Unblock ReadMessage when the server shuts down.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	// Slack pings every few seconds; a stretch of silence means a dead peer.
	const readDeadline = 75 * time.Second
	_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
	conn.SetPingHandler(func(data string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
		return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(5*time.Second))
	})

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
		var env socketEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			log.Printf("slack socket mode: skipping malformed envelope: %v", err)
			continue
		}
		if env.EnvelopeID != "" {
			if err := conn.WriteJSON(map[string]string{"envelope_id": env.EnvelopeID}); err != nil {
				return err
			}
		}
		switch env.Type {
		case "hello":
			log.Printf("slack socket mode connected")
		case "disconnect":
			return nil
		case "interactive":
			go s.handleSlackInteractive(env.Payload)
		}
	}
}

// openSocketURL asks Slack for a one-time Socket Mode WebSocket URL.
func (n *SlackNotifier) openSocketURL(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.connectionsOpenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+n.appToken)
	resp, err := n.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var parsed struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		URL   string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", fmt.Errorf("parse apps.connections.open response: %w", err)
	}
	if !parsed.OK || parsed.URL == "" {
		return "", fmt.Errorf("apps.connections.open failed: %s", parsed.Error)
	}
	return parsed.URL, nil
}

// handleSlackInteractive reacts to block_actions payloads: a Re-analyze click
// starts a manual incident run — its completion then lands in the thread via
// the normal delivery path — and drops an immediate note into the thread so
// the click has visible feedback.
func (s *Server) handleSlackInteractive(raw json.RawMessage) {
	var payload struct {
		Type string `json:"type"`
		User struct {
			Username string `json:"username"`
			Name     string `json:"name"`
		} `json:"user"`
		Actions []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Type != "block_actions" {
		return
	}
	for _, action := range payload.Actions {
		if action.ActionID != slackReanalyzeActionID || action.Value == "" {
			continue
		}
		s.reanalyzeFromSlack(action.Value, first(payload.User.Username, payload.User.Name, "unknown"))
	}
}

func (s *Server) reanalyzeFromSlack(incidentID string, requestedBy string) {
	run, started := s.startAnalysisRun("incident", incidentID, "manual", "")
	note := fmt.Sprintf("🔄 Re-analysis started by @%s — the result will follow in this thread.", requestedBy)
	switch {
	case started:
	case run != nil && run.Status == "analyzing":
		note = "⏳ An analysis is already running for this incident — its result will land in this thread."
	default:
		note = "⚠️ Could not start a re-analysis — the incident has no analyzable alerts."
	}
	detail, ok := s.store.IncidentDetail(incidentID)
	if !ok || detail.SlackThreadTS == "" {
		return
	}
	if err := s.slack.postThreadNote(detail.SlackThreadTS, note); err != nil {
		log.Printf("slack reanalyze note failed for incident %s: %v", incidentID, err)
	}
}
