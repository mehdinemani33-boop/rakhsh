package engine

import (
	"fmt"
	"os"
	"strings"
	"time"

	"rakhsh/internal/store"
	"rakhsh/internal/sysutil"
)

// GREFRP is the default, free engine: an optional GRE link carrying FRP.
// On the Iran edge it runs frps (the server) and opens the public ports; on
// the foreign side it runs frpc (the client) that dials out and exposes the
// local services. The GRE link gives a stable private /30 between the two so
// FRP's control channel rides an address that does not change with NAT.
type GREFRP struct {
	frpDir string // where frps/frpc binaries live
}

// NewGREFRP builds the engine; frpDir defaults to /opt/rakhsh/frp.
func NewGREFRP(frpDir string) *GREFRP {
	if frpDir == "" {
		frpDir = "/opt/rakhsh/frp"
	}
	return &GREFRP{frpDir: frpDir}
}

func (g *GREFRP) ID() store.Engine { return store.EngGREFRP }
func (g *GREFRP) Pro() bool        { return false }
func (g *GREFRP) Transports() []string {
	return []string{"tcp", "kcp", "quic", "websocket", "wss"}
}

// --- GRE link ---------------------------------------------------------------

func greName(t store.Tunnel) string {
	// deterministic, <=15 chars for an interface name
	id := strings.ReplaceAll(t.ID, "-", "")
	if len(id) > 8 {
		id = id[:8]
	}
	return "rkh" + id
}

// greUp creates the GRE interface and assigns the inner /30.
func (g *GREFRP) greUp(role store.Role, t store.Tunnel) error {
	if t.Overlay == "" || t.GRELocal == "" {
		return nil // GRE optional; FRP can run on public IPs directly
	}
	name := greName(t)
	_, _ = sysutil.Run(5*time.Second, "ip", "link", "del", name) // clean slate
	mode := "gre"
	if t.Overlay == store.Overlay6to4 || t.Overlay == store.Overlay4in6 {
		mode = "ip6gre"
	}
	if _, err := sysutil.Run(5*time.Second, "ip", "tunnel", "add", name,
		"mode", mode, "local", t.LocalIP, "remote", t.PeerIP, "ttl", "255"); err != nil {
		return fmt.Errorf("gre add: %w", err)
	}
	if _, err := sysutil.Run(5*time.Second, "ip", "addr", "add", t.GRELocal+"/30", "dev", name); err != nil {
		return fmt.Errorf("gre addr: %w", err)
	}
	if _, err := sysutil.Run(5*time.Second, "ip", "link", "set", name, "up", "mtu", "1400"); err != nil {
		return fmt.Errorf("gre up: %w", err)
	}
	return nil
}

func (g *GREFRP) greDown(t store.Tunnel) {
	if t.GRELocal == "" {
		return
	}
	_, _ = sysutil.Run(5*time.Second, "ip", "link", "del", greName(t))
}

// controlHost is the address FRP binds/dials: the GRE peer when present,
// otherwise the public peer IP.
func controlHost(role store.Role, t store.Tunnel) string {
	if t.GRELocal != "" {
		if role == store.RoleForeign {
			return t.GREPeer // dial the Iran inner addr
		}
		return t.GRELocal
	}
	if role == store.RoleForeign {
		return t.PeerIP
	}
	return "0.0.0.0"
}

// --- FRP config -------------------------------------------------------------

func (g *GREFRP) frpsTOML(t store.Tunnel) string {
	var b strings.Builder
	fmt.Fprintf(&b, "bindAddr = %q\n", controlHost(store.RoleIran, t))
	fmt.Fprintf(&b, "bindPort = %d\n", t.CtrlPort)
	switch t.Transport {
	case "kcp":
		fmt.Fprintf(&b, "kcpBindPort = %d\n", t.CtrlPort)
	case "quic":
		fmt.Fprintf(&b, "quicBindPort = %d\n", t.CtrlPort)
	}
	fmt.Fprintf(&b, "auth.method = \"token\"\nauth.token = %q\n", t.Token)
	fmt.Fprintf(&b, "transport.maxPoolCount = 50\n")
	fmt.Fprintf(&b, "log.to = \"/opt/rakhsh/log/frps-%s.log\"\nlog.level = \"warn\"\nlog.maxDays = 2\n", t.ID)
	// memory ceiling guard for busy hubs is enforced by systemd (see unit).
	return b.String()
}

func (g *GREFRP) frpcTOML(t store.Tunnel) string {
	var b strings.Builder
	fmt.Fprintf(&b, "serverAddr = %q\n", controlHost(store.RoleForeign, t))
	fmt.Fprintf(&b, "serverPort = %d\n", t.CtrlPort)
	proto := t.Transport
	if proto == "" || proto == "wss" {
		proto = "websocket"
	}
	fmt.Fprintf(&b, "transport.protocol = %q\n", proto)
	if t.Transport == "wss" {
		fmt.Fprintf(&b, "transport.tls.enable = true\n")
	}
	fmt.Fprintf(&b, "auth.method = \"token\"\nauth.token = %q\n", t.Token)
	fmt.Fprintf(&b, "log.to = \"/opt/rakhsh/log/frpc-%s.log\"\nlog.level = \"warn\"\nlog.maxDays = 2\n", t.ID)
	for _, p := range t.Ports {
		proto := p.Proto
		if proto == "" {
			proto = "tcp"
		}
		fmt.Fprintf(&b, "\n[[proxies]]\nname = %q\ntype = %q\n", t.ID+"-"+p.Name, proto)
		fmt.Fprintf(&b, "localIP = %q\nlocalPort = %d\nremotePort = %d\n", p.TargetHost, p.TargetPort, p.Public)
	}
	return b.String()
}

func (g *GREFRP) unit(role store.Role, t store.Tunnel) (string, string) {
	bin, cfg, name := "frps", "frps-"+t.ID+".toml", "rakhsh-frps-"+t.ID+".service"
	if role == store.RoleForeign {
		bin, cfg, name = "frpc", "frpc-"+t.ID+".toml", "rakhsh-frpc-"+t.ID+".service"
	}
	u := fmt.Sprintf(`[Unit]
Description=Rakhsh %s tunnel %s
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s/%s -c /opt/rakhsh/conf/%s
Restart=always
RestartSec=3
MemoryMax=512M
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, bin, t.Name, g.frpDir, bin, cfg)
	return name, u
}

// --- Engine interface -------------------------------------------------------

func (g *GREFRP) Up(role store.Role, t store.Tunnel) error {
	if err := g.greUp(role, t); err != nil {
		return err
	}
	var cfg string
	if role == store.RoleIran {
		cfg = g.frpsTOML(t)
	} else {
		cfg = g.frpcTOML(t)
	}
	name := "frps"
	if role == store.RoleForeign {
		name = "frpc"
	}
	if err := sysutil.WriteFile("/opt/rakhsh/conf/"+name+"-"+t.ID+".toml", cfg); err != nil {
		return err
	}
	unit, contents := g.unit(role, t)
	return sysutil.SystemdInstall(unit, contents)
}

func (g *GREFRP) Down(t store.Tunnel) error {
	sysutil.SystemdStop("rakhsh-frps-" + t.ID + ".service")
	sysutil.SystemdStop("rakhsh-frpc-" + t.ID + ".service")
	g.greDown(t)
	return nil
}

func (g *GREFRP) Probe(t store.Tunnel) Probe {
	// Latency to the peer public IP as a cheap proxy; real benchmark adds
	// a throughput pass in the diagnostics package.
	lat := sysutil.PingLatency(t.PeerIP)
	ok := lat >= 0
	return Probe{
		Engine: g.ID(), Overlay: t.Overlay, Transport: t.Transport,
		OK: ok, LatencyMS: lat, Score: scoreFromLatency(ok, lat, 0),
		Note: "gre+frp " + t.Transport,
	}
}

func (g *GREFRP) Status(t store.Tunnel) Status {
	unit := "rakhsh-frps-" + t.ID + ".service"
	if _, err := os.Stat("/opt/rakhsh/conf/frpc-" + t.ID + ".toml"); err == nil {
		unit = "rakhsh-frpc-" + t.ID + ".service"
	}
	up := sysutil.SystemdActive(unit)
	st := Status{Up: up}
	if t.GRELocal != "" {
		st.LatencyMS = sysutil.PingLatency(t.GREPeer)
		if st.LatencyMS < 0 {
			st.Up = false
			st.Detail = "gre peer unreachable"
		}
		// Real per-tunnel traffic from the GRE interface counters.
		st.RxBytes, st.TxBytes = sysutil.IfaceBytes(greName(t))
	}
	return st
}
