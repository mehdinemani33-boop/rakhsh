// Package dns is Rakhsh's automatic DNS switching: a domain that follows the
// healthy Iran hubs. It health-checks each hub and keeps the domain's A records
// pointed only at the hubs that are up, so when one Iran server dies its IP
// leaves the domain within seconds and new clients resolve only to live hubs.
// Backed by the Cloudflare API (Zone → DNS → Edit token).
package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Hub is one Iran edge the domain can point at.
type Hub struct {
	Name  string `json:"name"`
	IP    string `json:"ip"`
	Share int    `json:"share"` // display weight (Cloudflare round-robin is equal)
	Port  int    `json:"port"`  // TCP port used for the health check
}

// Config is the whole DNS-switching setup, persisted in the store.
type Config struct {
	Enabled   bool   `json:"enabled"`
	Domain    string `json:"domain"`     // FQDN record, e.g. full.melodifypath.info
	Token     string `json:"token"`      // Cloudflare API token
	CheckPort int    `json:"check_port"` // default health-check port
	EverySec  int    `json:"every_sec"`  // check interval
	Fall      int    `json:"fall"`       // consecutive fails before a hub leaves (default 3)
	Rise      int    `json:"rise"`       // consecutive successes before it returns (default 3)
	Hubs      []Hub  `json:"hubs"`
	// runtime status (not persisted meaningfully)
	ZoneID string `json:"zone_id,omitempty"`
}

// Status is the live view the panel renders.
type Status struct {
	Domain   string          `json:"domain"`
	Enabled  bool            `json:"enabled"`
	LiveIPs  []string        `json:"live_ips"`
	Health   map[string]bool `json:"health"` // ip -> healthy
	LastSync string          `json:"last_sync"`
	LastErr  string          `json:"last_err,omitempty"`
}

const cfAPI = "https://api.cloudflare.com/client/v4"

// cfClient talks to the Cloudflare API with a bearer token.
type cfClient struct {
	token string
	hc    *http.Client
}

func newCF(token string) *cfClient {
	return &cfClient{token: token, hc: &http.Client{Timeout: 12 * time.Second}}
}

func (c *cfClient) do(method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, cfAPI+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var env struct {
		Success bool              `json:"success"`
		Errors  []json.RawMessage `json:"errors"`
		Result  json.RawMessage   `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("cloudflare: bad response: %s", strings.TrimSpace(string(raw)))
	}
	if !env.Success {
		return fmt.Errorf("cloudflare error: %s", string(raw))
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// zoneID resolves the Cloudflare zone that owns the given FQDN.
func (c *cfClient) zoneID(fqdn string) (string, error) {
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := c.do(http.MethodGet, "/zones?per_page=50", nil, &zones); err != nil {
		return "", err
	}
	// pick the longest zone name that is a suffix of the fqdn
	bestID, bestLen := "", -1
	for _, z := range zones {
		if (fqdn == z.Name || strings.HasSuffix(fqdn, "."+z.Name)) && len(z.Name) > bestLen {
			bestID, bestLen = z.ID, len(z.Name)
		}
	}
	if bestID == "" {
		return "", fmt.Errorf("no Cloudflare zone found for %s", fqdn)
	}
	return bestID, nil
}

type aRecord struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Name    string `json:"name"`
}

func (c *cfClient) listA(zone, name string) ([]aRecord, error) {
	var recs []aRecord
	err := c.do(http.MethodGet, fmt.Sprintf("/zones/%s/dns_records?type=A&name=%s&per_page=100", zone, name), nil, &recs)
	return recs, err
}

func (c *cfClient) createA(zone, name, ip string) error {
	return c.do(http.MethodPost, "/zones/"+zone+"/dns_records", map[string]any{
		"type": "A", "name": name, "content": ip, "ttl": 60, "proxied": false,
	}, nil)
}

func (c *cfClient) deleteA(zone, id string) error {
	return c.do(http.MethodDelete, "/zones/"+zone+"/dns_records/"+id, nil, nil)
}

// healthy reports whether ip:port accepts a TCP connection.
func healthy(ip string, port int) bool {
	if port <= 0 {
		port = 443
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 4*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Switcher runs the health + reconcile loop.
type Switcher struct {
	mu     sync.RWMutex
	cfg    Config
	status Status
	get    func() Config // pulls the latest config from the store each tick
	// debounce state (touched only from the single tick goroutine)
	eff   map[string]bool // effective (debounced) health per IP
	fails map[string]int  // consecutive failed checks
	rises map[string]int  // consecutive successful checks
	seen  map[string]bool // whether we've ever observed this IP
}

// New builds a Switcher. get returns the current config on every tick so the
// panel can change it live.
func New(get func() Config) *Switcher {
	return &Switcher{get: get, status: Status{Health: map[string]bool{}},
		eff: map[string]bool{}, fails: map[string]int{}, rises: map[string]int{}, seen: map[string]bool{}}
}

// debounce applies Fall/Rise hysteresis and returns the effective health. A hub
// flips to down only after `fall` straight failures, and back up only after
// `rise` straight successes, so one transient blip never moves DNS.
func (s *Switcher) debounce(ip string, ok bool, fall, rise int) bool {
	if fall < 1 {
		fall = 3
	}
	if rise < 1 {
		rise = 3
	}
	if !s.seen[ip] {
		s.seen[ip] = true
		s.eff[ip] = ok // seed with the first observation, no delay
		if ok {
			s.rises[ip] = rise
		} else {
			s.fails[ip] = fall
		}
		return ok
	}
	if ok {
		s.rises[ip]++
		s.fails[ip] = 0
		if s.rises[ip] >= rise {
			s.eff[ip] = true
		}
	} else {
		s.fails[ip]++
		s.rises[ip] = 0
		if s.fails[ip] >= fall {
			s.eff[ip] = false
		}
	}
	return s.eff[ip]
}

// Snapshot returns the current live status.
func (s *Switcher) Snapshot() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// Run reconciles until stop closes.
func (s *Switcher) Run(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	s.tick()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.tick()
		}
	}
}

func (s *Switcher) setErr(cfg Config, e string) {
	s.mu.Lock()
	s.status = Status{Domain: cfg.Domain, Enabled: cfg.Enabled, Health: s.status.Health, LastErr: e, LastSync: time.Now().Format("15:04:05")}
	s.mu.Unlock()
}

func (s *Switcher) tick() {
	cfg := s.get()
	if !cfg.Enabled || cfg.Domain == "" || cfg.Token == "" || len(cfg.Hubs) == 0 {
		s.mu.Lock()
		s.status.Enabled = cfg.Enabled
		s.status.Domain = cfg.Domain
		s.mu.Unlock()
		return
	}
	// health of each hub, with Fall/Rise debounce
	health := map[string]bool{}
	var liveIPs []string
	for _, h := range cfg.Hubs {
		port := h.Port
		if port <= 0 {
			port = cfg.CheckPort
		}
		raw := healthy(h.IP, port)
		eff := s.debounce(h.IP, raw, cfg.Fall, cfg.Rise)
		health[h.IP] = eff
		if eff {
			liveIPs = append(liveIPs, h.IP)
		}
	}
	// never empty the domain: if all hubs look down (edge-side probe glitch),
	// leave DNS as-is rather than cutting everyone off.
	if len(liveIPs) == 0 {
		s.mu.Lock()
		s.status = Status{Domain: cfg.Domain, Enabled: true, Health: health,
			LastErr: "all hubs failed health check — DNS left unchanged", LastSync: time.Now().Format("15:04:05")}
		s.mu.Unlock()
		return
	}
	cf := newCF(cfg.Token)
	zone := cfg.ZoneID
	if zone == "" {
		z, err := cf.zoneID(cfg.Domain)
		if err != nil {
			s.setErr(cfg, err.Error())
			return
		}
		zone = z
	}
	recs, err := cf.listA(zone, cfg.Domain)
	if err != nil {
		s.setErr(cfg, err.Error())
		return
	}
	have := map[string]string{} // ip -> record id
	for _, r := range recs {
		have[r.Content] = r.ID
	}
	want := map[string]bool{}
	for _, ip := range liveIPs {
		want[ip] = true
	}
	// add missing healthy IPs
	for ip := range want {
		if _, ok := have[ip]; !ok {
			if err := cf.createA(zone, cfg.Domain, ip); err != nil {
				s.setErr(cfg, "add "+ip+": "+err.Error())
				return
			}
		}
	}
	// remove records for IPs that are not healthy hubs
	for ip, id := range have {
		if !want[ip] {
			if err := cf.deleteA(zone, id); err != nil {
				s.setErr(cfg, "del "+ip+": "+err.Error())
				return
			}
		}
	}
	s.mu.Lock()
	s.status = Status{Domain: cfg.Domain, Enabled: true, LiveIPs: liveIPs, Health: health, LastSync: time.Now().Format("15:04:05")}
	s.status.LastErr = ""
	s.mu.Unlock()
}

// Test verifies a token+domain and returns the resolved zone and current A set.
func Test(cfg Config) (zone string, ips []string, err error) {
	if cfg.Token == "" || cfg.Domain == "" {
		return "", nil, fmt.Errorf("token and domain required")
	}
	cf := newCF(cfg.Token)
	zone, err = cf.zoneID(cfg.Domain)
	if err != nil {
		return "", nil, err
	}
	recs, err := cf.listA(zone, cfg.Domain)
	if err != nil {
		return zone, nil, err
	}
	for _, r := range recs {
		ips = append(ips, r.Content)
	}
	return zone, ips, nil
}
