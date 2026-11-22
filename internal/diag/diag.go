// Package diag is the deep troubleshooting suite: it separates a filtered port
// from a filtered IP, measures the clock gap between two servers, walks the
// hop path, runs a stability sample you can chart, and checks every forwarded
// port end to end.
package diag

import (
	"fmt"
	"net"
	"strings"
	"time"

	"rakhsh/internal/store"
	"rakhsh/internal/sysutil"
)

// Reach distinguishes "IP blocked" from "port blocked".
type Reach struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	ICMPOK    bool   `json:"icmp_ok"`     // IP answers ping
	PortOK    bool   `json:"port_ok"`     // TCP connect succeeds
	Verdict   string `json:"verdict"`     // reachable|port-filtered|ip-filtered|down
	LatencyMS float64 `json:"latency_ms"`
}

// Reachability probes an IP+port and classifies the failure.
func Reachability(host string, port int) Reach {
	r := Reach{Host: host, Port: port}
	r.LatencyMS = sysutil.PingLatency(host)
	r.ICMPOK = r.LatencyMS >= 0
	r.PortOK = sysutil.TCPOpen(fmt.Sprintf("%s:%d", host, port), 4*time.Second)
	switch {
	case r.PortOK:
		r.Verdict = "reachable"
	case r.ICMPOK && !r.PortOK:
		r.Verdict = "port-filtered" // host up, this port blocked
	case !r.ICMPOK && !r.PortOK:
		r.Verdict = "ip-filtered" // nothing answers — IP blocked or host down
	}
	return r
}

// Clock reports the time gap to a peer running Rakhsh (via its /api/time).
type Clock struct {
	PeerURL string  `json:"peer_url"`
	SkewMS  float64 `json:"skew_ms"`
	OK      bool    `json:"ok"`
	Note    string  `json:"note,omitempty"`
}

// ClockSkew pings the peer's time endpoint and compares to local time.
func ClockSkew(peerURL string) Clock {
	c := Clock{PeerURL: peerURL}
	t0 := time.Now()
	out, err := sysutil.Run(6*time.Second, "curl", "-fsS", "-m", "5", peerURL)
	if err != nil {
		c.Note = "peer time endpoint unreachable"
		return c
	}
	rtt := time.Since(t0)
	var peerUnix int64
	if _, e := fmt.Sscanf(strings.TrimSpace(out), "%d", &peerUnix); e != nil {
		c.Note = "bad time reply"
		return c
	}
	// account for half the round trip
	local := time.Now().Add(-rtt / 2).Unix()
	c.SkewMS = float64(peerUnix-local) * 1000
	c.OK = true
	return c
}

// Hop is one row of the path.
type Hop struct {
	N      int     `json:"n"`
	Addr   string  `json:"addr"`
	MS     float64 `json:"ms"`
}

// HopPath runs traceroute to host (best effort; empty if the tool is absent).
func HopPath(host string) []Hop {
	out, err := sysutil.Run(25*time.Second, "traceroute", "-n", "-q", "1", "-w", "2", "-m", "20", host)
	if err != nil {
		if o2, e2 := sysutil.Run(25*time.Second, "mtr", "-n", "-r", "-c", "1", host); e2 == nil {
			out = o2
		} else {
			return nil
		}
	}
	var hops []Hop
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		var n int
		if _, e := fmt.Sscanf(f[0], "%d", &n); e != nil {
			continue
		}
		h := Hop{N: n, Addr: f[1]}
		for _, tok := range f[2:] {
			var ms float64
			if _, e := fmt.Sscanf(tok, "%f", &ms); e == nil {
				h.MS = ms
				break
			}
		}
		hops = append(hops, h)
	}
	return hops
}

// StabilitySample is one point of a stability run.
type StabilitySample struct {
	T  int64   `json:"t"`
	MS float64 `json:"ms"`
}

// Stability pings host count times and returns a chartable series plus loss%.
func Stability(host string, count int) ([]StabilitySample, float64) {
	if count <= 0 || count > 120 {
		count = 20
	}
	var pts []StabilitySample
	lost := 0
	for i := 0; i < count; i++ {
		ms := sysutil.PingLatency(host)
		if ms < 0 {
			lost++
		}
		pts = append(pts, StabilitySample{T: time.Now().Unix(), MS: ms})
		time.Sleep(300 * time.Millisecond)
	}
	return pts, float64(lost) / float64(count) * 100
}

// PortCheck is the result for one forwarded port.
type PortCheck struct {
	Name   string `json:"name"`
	Public int    `json:"public"`
	Open   bool   `json:"open"`
}

// PortForwards checks each mapped public port is accepting on the edge IP.
func PortForwards(edgeIP string, ports []store.PortMap) []PortCheck {
	var out []PortCheck
	for _, p := range ports {
		open := sysutil.TCPOpen(net.JoinHostPort(edgeIP, itoa(p.Public)), 4*time.Second)
		out = append(out, PortCheck{Name: p.Name, Public: p.Public, Open: open})
	}
	return out
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
