// Package health is the single source of truth the dashboard, header, node map
// and every card read from. One poller walks the tunnels, asks each engine for
// status, records a rolling state, and — only on a real transition — raises a
// webhook/Telegram alert and (when enabled) hands the tunnel to Autopilot.
package health

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"rakhsh/internal/engine"
	"rakhsh/internal/store"
)

// Level is a tunnel's coarse health.
type Level string

const (
	Up       Level = "up"
	Degraded Level = "degraded"
	Down     Level = "down"
	Unknown  Level = "unknown"
)

// Link is the recorded health of one tunnel.
type Link struct {
	TunnelID  string        `json:"tunnel_id"`
	Name      string        `json:"name"`
	Engine    store.Engine  `json:"engine"`
	Level     Level         `json:"level"`
	LatencyMS float64       `json:"latency_ms"`
	RxBytes   int64         `json:"rx_bytes"`
	TxBytes   int64         `json:"tx_bytes"`
	Since     time.Time     `json:"since"`
	Detail    string        `json:"detail,omitempty"`
}

// Monitor polls tunnels and keeps the live model.
type Monitor struct {
	st     *store.Store
	mu     sync.RWMutex
	links  map[string]Link
	onDown func(store.Tunnel) // Autopilot hook
}

// New builds a Monitor over the given store.
func New(st *store.Store) *Monitor {
	return &Monitor{st: st, links: map[string]Link{}}
}

// SetAutopilot registers the callback invoked when a tunnel goes Down.
func (m *Monitor) SetAutopilot(fn func(store.Tunnel)) { m.onDown = fn }

// Run polls forever until the channel closes.
func (m *Monitor) Run(stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	m.poll()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m.poll()
		}
	}
}

func (m *Monitor) poll() {
	snap := m.st.Snapshot()
	for _, tn := range snap.Tunnels {
		if !tn.Enabled {
			continue
		}
		eng, err := engine.Get(tn.Engine)
		if err != nil {
			continue
		}
		s := eng.Status(tn)
		lvl := levelOf(s)
		m.record(snap.Role, snap.Settings, tn, lvl, s)
	}
}

func levelOf(s engine.Status) Level {
	switch {
	case !s.Up:
		return Down
	case s.LatencyMS > 400:
		return Degraded
	default:
		return Up
	}
}

func (m *Monitor) record(role store.Role, set store.Settings, tn store.Tunnel, lvl Level, s engine.Status) {
	m.mu.Lock()
	prev, had := m.links[tn.ID]
	changed := !had || prev.Level != lvl
	link := Link{
		TunnelID: tn.ID, Name: tn.Name, Engine: tn.Engine, Level: lvl,
		LatencyMS: s.LatencyMS, RxBytes: s.RxBytes, TxBytes: s.TxBytes,
		Detail: s.Detail, Since: prev.Since,
	}
	if changed {
		link.Since = time.Now()
	}
	m.links[tn.ID] = link
	m.mu.Unlock()

	if changed && had {
		m.alert(set, tn, prev.Level, lvl)
		if lvl == Down && set.Autopilot && m.onDown != nil {
			go m.onDown(tn)
		}
	}
}

// Links returns a snapshot of all tracked links.
func (m *Monitor) Links() []Link {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Link, 0, len(m.links))
	for _, l := range m.links {
		out = append(out, l)
	}
	return out
}

// LatencyOf returns the last latency for a tunnel, or -1 if unknown.
func (m *Monitor) LatencyOf(tunnelID string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if l, ok := m.links[tunnelID]; ok {
		return l.LatencyMS
	}
	return -1
}

// Overall rolls the links into one top-level level for the header.
func (m *Monitor) Overall() Level {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.links) == 0 {
		return Unknown
	}
	worst := Up
	for _, l := range m.links {
		switch l.Level {
		case Down:
			return Down
		case Degraded:
			worst = Degraded
		}
	}
	return worst
}

func (m *Monitor) alert(set store.Settings, tn store.Tunnel, from, to Level) {
	msg := fmt.Sprintf("Rakhsh: tunnel %q %s → %s", tn.Name, from, to)
	if set.AlertWebhook != "" {
		body, _ := json.Marshal(map[string]string{"text": msg})
		req, _ := http.NewRequest(http.MethodPost, set.AlertWebhook, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c := &http.Client{Timeout: 8 * time.Second}
		if resp, err := c.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	if set.AlertTGToken != "" && set.AlertTGChat != "" {
		api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", set.AlertTGToken)
		v := url.Values{"chat_id": {set.AlertTGChat}, "text": {msg}}
		c := &http.Client{Timeout: 8 * time.Second}
		if resp, err := c.PostForm(api, v); err == nil {
			resp.Body.Close()
		}
	}
}
