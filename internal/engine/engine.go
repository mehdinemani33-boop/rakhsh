// Package engine defines the tunnel-engine contract and a registry. Each
// engine knows how to probe a path, bring a tunnel up on a given role, tear
// it down, and report live status. GRE+FRP is the free default; the rest are
// gated behind a Pro license but share the exact same interface so carrier
// failover and Autopilot can move a tunnel between them with no special cases.
package engine

import (
	"fmt"
	"sort"
	"time"

	"rakhsh/internal/store"
)

// Role mirrors store.Role to avoid import cycles at call sites.
type Role = store.Role

// Probe is the result of testing one transport on a path.
type Probe struct {
	Engine    store.Engine  `json:"engine"`
	Overlay   store.Overlay `json:"overlay,omitempty"`
	Transport string        `json:"transport,omitempty"`
	OK        bool          `json:"ok"`
	LatencyMS float64       `json:"latency_ms"`
	Jitter    float64       `json:"jitter_ms"`
	Score     float64       `json:"score"` // higher is better
	Note      string        `json:"note,omitempty"`
}

// Status is a live health snapshot of a running tunnel.
type Status struct {
	Up        bool    `json:"up"`
	LatencyMS float64 `json:"latency_ms"`
	RxBytes   int64   `json:"rx_bytes"`
	TxBytes   int64   `json:"tx_bytes"`
	Conns     int     `json:"conns"`
	Detail    string  `json:"detail,omitempty"`
}

// Engine is implemented by every carrier.
type Engine interface {
	ID() store.Engine
	// Pro reports whether this engine needs a license.
	Pro() bool
	// Transports lists the transports this engine can offer.
	Transports() []string
	// Probe tests one transport on the path to peerIP without building a tunnel.
	Probe(t store.Tunnel) Probe
	// Up brings the tunnel up for the given role (idempotent).
	Up(role store.Role, t store.Tunnel) error
	// Down tears it down (idempotent; safe if never up).
	Down(t store.Tunnel) error
	// Status reports live health.
	Status(t store.Tunnel) Status
}

var registry = map[store.Engine]Engine{}

// Register adds an engine to the registry.
func Register(e Engine) { registry[e.ID()] = e }

// Get returns the engine for id.
func Get(id store.Engine) (Engine, error) {
	e, ok := registry[id]
	if !ok {
		return nil, fmt.Errorf("unknown engine %q", id)
	}
	return e, nil
}

// All returns every registered engine, stable-sorted by id.
func All() []Engine {
	out := make([]Engine, 0, len(registry))
	for _, e := range registry {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// RouteTest probes every transport of every engine for a path and returns
// results sorted best-first. Pro engines are skipped unless licensed.
func RouteTest(t store.Tunnel, licensed bool) []Probe {
	var res []Probe
	for _, e := range All() {
		if e.Pro() && !licensed {
			continue
		}
		for _, tr := range e.Transports() {
			cand := t
			cand.Engine = e.ID()
			cand.Transport = tr
			p := e.Probe(cand)
			res = append(res, p)
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Score > res[j].Score })
	return res
}

// scoreFromLatency maps a latency/jitter probe to a 0..100 score.
func scoreFromLatency(ok bool, latency, jitter float64) float64 {
	if !ok || latency < 0 {
		return 0
	}
	s := 100.0 - latency - jitter*2
	if s < 1 {
		s = 1
	}
	return s
}

// nowUTC is a seam for tests.
var nowUTC = func() time.Time { return time.Now().UTC() }
