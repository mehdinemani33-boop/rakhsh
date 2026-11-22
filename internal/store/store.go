// Package store is a dependency-free, file-backed JSON state store with an
// advisory lock. It holds everything Rakhsh needs to survive a restart:
// the local role, tunnels, nodes, cluster pools, customers and settings.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"rakhsh/internal/dns"
)

const Version = "1.0.0"

// Role of this host in a tunnel pair.
type Role string

const (
	RoleIran    Role = "iran"    // public edge users connect to
	RoleForeign Role = "foreign" // runs the real services behind the tunnel
	RoleUnset   Role = ""
)

// Engine identifiers.
type Engine string

const (
	EngGREFRP   Engine = "gre_frp"  // GRE link + FRP (default, free)
	EngBackhaul Engine = "backhaul" // Backhaul transports
	EngXray     Engine = "xray"     // VLESS/Reality/XHTTP/gRPC/mKCP
	EngBagher   Engine = "bagher"   // FRP inside multiplexed SSH
	EngSpoof    Engine = "spoof"    // spoofed-source pipe + WireGuard
)

// Overlay for the GRE link.
type Overlay string

const (
	OverlayDirect Overlay = "direct" // IP proto 47
	OverlayWSS    Overlay = "wss"    // TLS over a web port
	Overlay6to4   Overlay = "6to4"   // IP proto 41
	Overlay4in6   Overlay = "4in6"   // GRE over IPv6
)

// PortMap is one forwarded public port -> foreign target.
type PortMap struct {
	Name       string `json:"name"`
	Public     int    `json:"public"`      // port opened on the Iran edge
	TargetHost string `json:"target_host"` // usually 127.0.0.1 on the foreign side
	TargetPort int    `json:"target_port"`
	Proto      string `json:"proto"` // tcp|udp
}

// Tunnel is one configured carrier between this host and a peer.
type Tunnel struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Engine    Engine    `json:"engine"`
	Overlay   Overlay   `json:"overlay,omitempty"`
	LocalIP   string    `json:"local_ip"`
	PeerIP    string    `json:"peer_ip"`
	GRELocal  string    `json:"gre_local,omitempty"` // inner /30 addr, e.g. 10.200.0.1
	GREPeer   string    `json:"gre_peer,omitempty"`
	CtrlPort  int       `json:"ctrl_port"`           // FRP/Backhaul control port
	Transport string    `json:"transport,omitempty"` // tcp|kcp|quic|ws|wss|...
	Token     string    `json:"token"`               // shared auth secret
	Ports     []PortMap `json:"ports"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	// Carrier failover: ordered fallback engines/transports to try.
	Carriers []Carrier `json:"carriers,omitempty"`
}

// Carrier is one entry in a tunnel's failover chain.
type Carrier struct {
	Engine    Engine  `json:"engine"`
	Overlay   Overlay `json:"overlay,omitempty"`
	Transport string  `json:"transport,omitempty"`
}

// Node is another server managed from this central panel.
type Node struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Addr     string    `json:"addr"`   // host:port of its node core
	Role     Role      `json:"role"`
	JoinKey  string    `json:"join_key"`
	LastSeen time.Time `json:"last_seen"`
	Core     bool      `json:"core"` // true = headless node core, false = full panel
}

// Pool is a cluster of foreign servers behind one Iran public port.
type Pool struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Public   int      `json:"public"`
	Strategy string   `json:"strategy"` // failover|balance|sticky|least_latency|least_conn
	Members  []string `json:"members"`  // tunnel IDs
}

// Customer is a sold tunnel with a plan that expires.
type Customer struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	TunnelID    string    `json:"tunnel_id"`
	Days        int       `json:"days"`
	VolumeGB    int       `json:"volume_gb"`  // 0 = unlimited
	SpeedMbit   int       `json:"speed_mbit"` // 0 = unlimited
	UsedBytes   int64     `json:"used_bytes"`
	ExpiresAt   time.Time `json:"expires_at"`
	Suspended   bool      `json:"suspended"`
	CreatedAt   time.Time `json:"created_at"`
}

// Settings are panel-wide knobs.
type Settings struct {
	PanelSecret   string `json:"panel_secret"`   // random path segment
	AdminUser     string `json:"admin_user"`
	AdminHash     string `json:"admin_hash"`     // argon2id
	TOTPSecret    string `json:"totp_secret"`    // optional 2FA
	UpdateChannel string `json:"update_channel"` // stable|dev
	Autopilot     bool   `json:"autopilot"`
	Watchdog      bool   `json:"watchdog"`
	NodeKey       string `json:"node_key"` // shared key nodes use to join this central
	CentralURL    string `json:"central_url,omitempty"` // set on a node that joined a central
	NodeName      string `json:"node_name,omitempty"`
	AlertWebhook  string `json:"alert_webhook"`
	AlertTGToken  string `json:"alert_tg_token"`
	AlertTGChat   string `json:"alert_tg_chat"`
	LicenseKey    string `json:"license_key"` // unlocks Pro engines/features
}

// State is the whole persisted document.
type State struct {
	Role      Role       `json:"role"`
	Settings  Settings   `json:"settings"`
	Tunnels   []Tunnel   `json:"tunnels"`
	Nodes     []Node     `json:"nodes"`
	Pools     []Pool     `json:"pools"`
	Customers []Customer `json:"customers"`
	DNS       dns.Config `json:"dns"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Store guards a State on disk.
type Store struct {
	path string
	mu   sync.Mutex
	st   State
}

// Open loads (or creates) the state file at path.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.st = State{Role: RoleUnset, Settings: Settings{UpdateChannel: "stable", Watchdog: true}}
		return s, s.flush()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) flush() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	s.st.UpdatedAt = time.Now()
	b, err := json.MarshalIndent(&s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Update runs fn under the lock and persists the result atomically.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.st); err != nil {
		return err
	}
	return s.flush()
}

// View runs fn under the lock with a copy-safe read.
func (s *Store) View(fn func(State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.st)
}

// Snapshot returns a shallow copy of the current state.
func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}
