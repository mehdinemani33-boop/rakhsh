// Package cluster puts several foreign servers behind one public port on the
// Iran edge. Each member tunnel terminates on a local 127.0.0.1 port here; the
// cluster binds the real public port and spreads connections across the live
// members with a chosen strategy. It is a passive-health TCP balancer — a dead
// member is skipped and retried, so a failing carrier never black-holes users.
package cluster

import (
	"hash/fnv"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"rakhsh/internal/store"
)

// Backend is one cluster member reachable at Addr (host:port on this edge).
type Backend struct {
	TunnelID string
	Addr     string
	conns    int64 // live connection count
	downTill int64 // unix seconds a failed member is parked until
}

// LatencyFn reports a member's current latency in ms (or <0 if unknown).
type LatencyFn func(tunnelID string) float64

type pool struct {
	id       string
	strategy string
	ln       net.Listener
	backends []*Backend
	rr       uint64
	latency  LatencyFn
	stop     chan struct{}
	mu       sync.Mutex
}

// Manager owns the running pools and reconciles them to the desired set.
type Manager struct {
	mu      sync.Mutex
	pools   map[string]*pool
	latency LatencyFn
}

// New builds a Manager. latency may be nil (least_latency falls back to RR).
func New(latency LatencyFn) *Manager {
	return &Manager{pools: map[string]*pool{}, latency: latency}
}

// Apply reconciles running pools to want. resolve maps a member tunnel ID to
// its local backend address on this edge.
func (m *Manager) Apply(want []store.Pool, resolve func(tunnelID string) (string, bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[string]bool{}
	for _, p := range want {
		keep[p.ID] = true
		var bes []*Backend
		for _, id := range p.Members {
			if addr, ok := resolve(id); ok {
				bes = append(bes, &Backend{TunnelID: id, Addr: addr})
			}
		}
		if cur, ok := m.pools[p.ID]; ok {
			cur.strategy = p.Strategy
			cur.setBackends(bes)
			continue
		}
		m.start(p, bes)
	}
	for id, pl := range m.pools {
		if !keep[id] {
			pl.close()
			delete(m.pools, id)
		}
	}
}

// Stats returns live connection counts per pool.
func (m *Manager) Stats() map[string]map[string]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]map[string]int64{}
	for id, pl := range m.pools {
		pl.mu.Lock()
		bm := map[string]int64{}
		for _, b := range pl.backends {
			bm[b.TunnelID] = atomic.LoadInt64(&b.conns)
		}
		pl.mu.Unlock()
		out[id] = bm
	}
	return out
}

func (m *Manager) start(p store.Pool, bes []*Backend) {
	ln, err := net.Listen("tcp", listenAddr(p.Public))
	if err != nil {
		return // port busy; health will surface it
	}
	pl := &pool{id: p.ID, strategy: p.Strategy, ln: ln, backends: bes,
		latency: m.latency, stop: make(chan struct{})}
	m.pools[p.ID] = pl
	go pl.serve()
}

func listenAddr(port int) string { return "0.0.0.0:" + itoa(port) }

// pool methods -------------------------------------------------------------

func (p *pool) setBackends(bes []*Backend) {
	p.mu.Lock()
	// carry live conn counts across reconfig
	old := map[string]int64{}
	for _, b := range p.backends {
		old[b.TunnelID] = atomic.LoadInt64(&b.conns)
	}
	for _, b := range bes {
		atomic.StoreInt64(&b.conns, old[b.TunnelID])
	}
	p.backends = bes
	p.mu.Unlock()
}

func (p *pool) close() {
	close(p.stop)
	_ = p.ln.Close()
}

func (p *pool) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			select {
			case <-p.stop:
				return
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		go p.handle(conn)
	}
}

func (p *pool) handle(client net.Conn) {
	defer client.Close()
	clientIP, _, _ := net.SplitHostPort(client.RemoteAddr().String())
	// Try up to len(backends) members (failover) starting from the picked one.
	tried := map[string]bool{}
	for i := 0; i < p.count(); i++ {
		b := p.pick(clientIP, tried)
		if b == nil {
			return
		}
		tried[b.TunnelID] = true
		up, err := net.DialTimeout("tcp", b.Addr, 4*time.Second)
		if err != nil {
			atomic.StoreInt64(&b.downTill, time.Now().Add(10*time.Second).Unix())
			continue
		}
		atomic.AddInt64(&b.conns, 1)
		pipe(client, up)
		atomic.AddInt64(&b.conns, -1)
		return
	}
}

func (p *pool) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.backends)
}

// pick chooses a live backend per strategy, skipping parked/tried ones.
func (p *pool) pick(clientIP string, tried map[string]bool) *Backend {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().Unix()
	var live []*Backend
	for _, b := range p.backends {
		if tried[b.TunnelID] || atomic.LoadInt64(&b.downTill) > now {
			continue
		}
		live = append(live, b)
	}
	if len(live) == 0 {
		// everyone parked/tried — fall back to any untried
		for _, b := range p.backends {
			if !tried[b.TunnelID] {
				live = append(live, b)
			}
		}
	}
	if len(live) == 0 {
		return nil
	}
	switch p.strategy {
	case "sticky":
		h := fnv.New32a()
		h.Write([]byte(clientIP))
		return live[int(h.Sum32())%len(live)]
	case "least_conn":
		best := live[0]
		for _, b := range live[1:] {
			if atomic.LoadInt64(&b.conns) < atomic.LoadInt64(&best.conns) {
				best = b
			}
		}
		return best
	case "least_latency":
		if p.latency != nil {
			best, bl := live[0], p.latency(live[0].TunnelID)
			for _, b := range live[1:] {
				if l := p.latency(b.TunnelID); l >= 0 && (bl < 0 || l < bl) {
					best, bl = b, l
				}
			}
			return best
		}
		fallthrough
	case "failover":
		return live[0]
	default: // balance = round robin
		p.rr++
		return live[int(p.rr)%len(live)]
	}
}

// pipe shuttles bytes both ways until either side closes.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) { _, _ = io.Copy(dst, src); done <- struct{}{} }
	go cp(a, b)
	go cp(b, a)
	<-done
	_ = a.Close()
	_ = b.Close()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
