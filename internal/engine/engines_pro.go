package engine

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"rakhsh/internal/store"
	"rakhsh/internal/sysutil"
)

// ---------------------------------------------------------------------------
// Backhaul: a reverse-tunnel daemon with many transports. Config-file driven,
// so it slots in beside FRP. (Pro)
// ---------------------------------------------------------------------------

type Backhaul struct{ dir string }

func NewBackhaul(dir string) *Backhaul {
	if dir == "" {
		dir = "/opt/rakhsh/backhaul"
	}
	return &Backhaul{dir: dir}
}
func (b *Backhaul) ID() store.Engine     { return store.EngBackhaul }
func (b *Backhaul) Pro() bool            { return true }
func (b *Backhaul) Transports() []string { return []string{"tcp", "tcpmux", "ws", "wss", "udp"} }

func (b *Backhaul) serverTOML(t store.Tunnel) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[server]\nbind_addr = \"0.0.0.0:%d\"\ntransport = %q\ntoken = %q\n",
		t.CtrlPort, t.Transport, t.Token)
	fmt.Fprintf(&sb, "keepalive_period = 20\nnodelay = true\nchannel_size = 2048\n")
	var ports []string
	for _, p := range t.Ports {
		ports = append(ports, fmt.Sprintf("%q", fmt.Sprintf("%d=%s:%d", p.Public, p.TargetHost, p.TargetPort)))
	}
	fmt.Fprintf(&sb, "ports = [%s]\n", strings.Join(ports, ", "))
	return sb.String()
}

func (b *Backhaul) clientTOML(t store.Tunnel) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[client]\nremote_addr = \"%s:%d\"\ntransport = %q\ntoken = %q\n",
		t.PeerIP, t.CtrlPort, t.Transport, t.Token)
	fmt.Fprintf(&sb, "keepalive_period = 20\nnodelay = true\nconnection_pool = 8\n")
	return sb.String()
}

func (b *Backhaul) Up(role store.Role, t store.Tunnel) error {
	cfg, suffix := b.serverTOML(t), "server"
	if role == store.RoleForeign {
		cfg, suffix = b.clientTOML(t), "client"
	}
	path := fmt.Sprintf("/opt/rakhsh/conf/backhaul-%s-%s.toml", suffix, t.ID)
	if err := sysutil.WriteFile(path, cfg); err != nil {
		return err
	}
	unit := "rakhsh-backhaul-" + t.ID + ".service"
	contents := fmt.Sprintf(`[Unit]
Description=Rakhsh Backhaul %s
After=network-online.target

[Service]
ExecStart=%s/backhaul -c %s
Restart=always
RestartSec=3
MemoryMax=512M
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, t.Name, b.dir, path)
	return sysutil.SystemdInstall(unit, contents)
}
func (b *Backhaul) Down(t store.Tunnel) error {
	sysutil.SystemdStop("rakhsh-backhaul-" + t.ID + ".service")
	return nil
}
func (b *Backhaul) Probe(t store.Tunnel) Probe {
	lat := sysutil.PingLatency(t.PeerIP)
	return Probe{Engine: b.ID(), Transport: t.Transport, OK: lat >= 0, LatencyMS: lat,
		Score: scoreFromLatency(lat >= 0, lat, 0), Note: "backhaul " + t.Transport}
}
func (b *Backhaul) Status(t store.Tunnel) Status {
	return Status{Up: sysutil.SystemdActive("rakhsh-backhaul-" + t.ID + ".service")}
}

// ---------------------------------------------------------------------------
// Xray: VLESS carrier that makes the path look like ordinary HTTPS. We render
// an inbound on the Iran edge (dokodemo-door -> freedom) and a VLESS tunnel to
// the foreign server, so forwarded ports exit there. (Pro)
// ---------------------------------------------------------------------------

type Xray struct{ dir string }

func NewXray(dir string) *Xray {
	if dir == "" {
		dir = "/opt/rakhsh/xray"
	}
	return &Xray{dir: dir}
}
func (x *Xray) ID() store.Engine     { return store.EngXray }
func (x *Xray) Pro() bool            { return true }
func (x *Xray) Transports() []string { return []string{"reality", "xhttp", "grpc", "mkcp", "cdn"} }

// config builds a minimal, valid Xray JSON for the role.
func (x *Xray) config(role store.Role, t store.Tunnel) string {
	type m = map[string]any
	var inbounds, outbounds []any
	if role == store.RoleIran {
		// Public ports -> forward into the VLESS outbound to the foreign node.
		for _, p := range t.Ports {
			inbounds = append(inbounds, m{
				"tag": "in-" + p.Name, "port": p.Public, "protocol": "dokodemo-door",
				"settings": m{"address": p.TargetHost, "port": p.TargetPort, "network": "tcp,udp"},
			})
		}
		outbounds = append(outbounds, m{
			"tag": "tunnel", "protocol": "vless",
			"settings": m{"vnext": []any{m{"address": t.PeerIP, "port": t.CtrlPort,
				"users": []any{m{"id": t.Token, "encryption": "none", "flow": "xtls-rprx-vision"}}}}},
			"streamSettings": x.stream(t),
		})
	} else {
		inbounds = append(inbounds, m{
			"tag": "tunnel", "port": t.CtrlPort, "protocol": "vless",
			"settings":       m{"clients": []any{m{"id": t.Token, "flow": "xtls-rprx-vision"}}, "decryption": "none"},
			"streamSettings": x.stream(t),
		})
		outbounds = append(outbounds, m{"tag": "direct", "protocol": "freedom"})
	}
	root := m{
		"log":       m{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
	}
	buf, _ := json.MarshalIndent(root, "", "  ")
	return string(buf)
}

func (x *Xray) stream(t store.Tunnel) map[string]any {
	switch t.Transport {
	case "grpc":
		return map[string]any{"network": "grpc", "grpcSettings": map[string]any{"serviceName": "rkh"}}
	case "xhttp":
		return map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/rkh"}}
	case "mkcp":
		return map[string]any{"network": "kcp", "kcpSettings": map[string]any{"seed": t.Token}}
	default: // reality
		return map[string]any{
			"network": "tcp", "security": "reality",
			"realitySettings": map[string]any{"show": false, "dest": "www.cloudflare.com:443",
				"serverNames": []string{"www.cloudflare.com"}, "privateKey": t.Token, "shortIds": []string{""}},
		}
	}
}

func (x *Xray) Up(role store.Role, t store.Tunnel) error {
	path := "/opt/rakhsh/conf/xray-" + t.ID + ".json"
	if err := sysutil.WriteFile(path, x.config(role, t)); err != nil {
		return err
	}
	unit := "rakhsh-xray-" + t.ID + ".service"
	contents := fmt.Sprintf(`[Unit]
Description=Rakhsh Xray %s
After=network-online.target

[Service]
ExecStart=%s/xray run -c %s
Restart=always
RestartSec=3
MemoryMax=512M
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, t.Name, x.dir, path)
	return sysutil.SystemdInstall(unit, contents)
}
func (x *Xray) Down(t store.Tunnel) error {
	sysutil.SystemdStop("rakhsh-xray-" + t.ID + ".service")
	return nil
}
func (x *Xray) Probe(t store.Tunnel) Probe {
	lat := sysutil.PingLatency(t.PeerIP)
	// Xray looks like HTTPS, so it keeps more score under filtering.
	sc := scoreFromLatency(lat >= 0, lat, 0)
	if lat >= 0 {
		sc += 10
	}
	return Probe{Engine: x.ID(), Transport: t.Transport, OK: lat >= 0, LatencyMS: lat,
		Score: sc, Note: "xray " + t.Transport}
}
func (x *Xray) Status(t store.Tunnel) Status {
	return Status{Up: sysutil.SystemdActive("rakhsh-xray-" + t.ID + ".service")}
}

// ---------------------------------------------------------------------------
// Bagher: FRP multiplexed inside several SSH connections, for paths where only
// SSH survives. Scaffolded: it reuses the FRP config and wraps frpc in an
// autossh fan-out. (Pro)
// ---------------------------------------------------------------------------

type Bagher struct{ frp *GREFRP }

func NewBagher(frp *GREFRP) *Bagher    { return &Bagher{frp: frp} }
func (s *Bagher) ID() store.Engine     { return store.EngBagher }
func (s *Bagher) Pro() bool            { return true }
func (s *Bagher) Transports() []string { return []string{"ssh"} }

// BagherKeyPath is the SSH key the foreign side uses to dial the Iran edge.
const BagherKeyPath = "/opt/rakhsh/ssh/id_ed25519"

// ensureSSHKey generates the ed25519 key once and returns its public half.
func (s *Bagher) ensureSSHKey() (string, error) {
	if _, err := os.Stat(BagherKeyPath); err != nil {
		if err := os.MkdirAll("/opt/rakhsh/ssh", 0o700); err != nil {
			return "", err
		}
		if _, err := sysutil.Run(15*time.Second, "ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", BagherKeyPath); err != nil {
			return "", err
		}
	}
	pub, _ := os.ReadFile(BagherKeyPath + ".pub")
	return strings.TrimSpace(string(pub)), nil
}

func (s *Bagher) Up(role store.Role, t store.Tunnel) error {
	pub, err := s.ensureSSHKey()
	if err != nil {
		return err
	}
	if role == store.RoleIran {
		// Receiving side. Authorize the key so the foreign side can dial in,
		// and allow remote-bound forwards to listen on all interfaces.
		_ = appendAuthorizedKey(pub)
		_, _ = sysutil.Run(5*time.Second, "bash", "-c",
			"grep -q '^GatewayPorts clientspecified' /etc/ssh/sshd_config || (echo 'GatewayPorts clientspecified' >> /etc/ssh/sshd_config && systemctl reload sshd 2>/dev/null)")
		return nil
	}
	// Foreign side dials the Iran edge and reverse-forwards each public port
	// through the SSH connection, kept alive by autossh.
	var fwd strings.Builder
	for _, p := range t.Ports {
		host := p.TargetHost
		if host == "" {
			host = "127.0.0.1"
		}
		fmt.Fprintf(&fwd, " -R 0.0.0.0:%d:%s:%d", p.Public, host, p.TargetPort)
	}
	exec := fmt.Sprintf("/usr/bin/autossh -M 0 -N -o StrictHostKeyChecking=accept-new -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -i %s%s -p 22 root@%s",
		BagherKeyPath, fwd.String(), t.PeerIP)
	unit := "rakhsh-bagher-" + t.ID + ".service"
	contents := fmt.Sprintf(`[Unit]
Description=Rakhsh Bagher (SSH) %s
After=network-online.target

[Service]
Environment=AUTOSSH_GATETIME=0
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, t.Name, exec)
	return sysutil.SystemdInstall(unit, contents)
}

func (s *Bagher) Down(t store.Tunnel) error {
	sysutil.SystemdStop("rakhsh-bagher-" + t.ID + ".service")
	return nil
}
func (s *Bagher) Probe(t store.Tunnel) Probe {
	ok := sysutil.TCPOpen(fmt.Sprintf("%s:22", t.PeerIP), 3*time.Second)
	lat := sysutil.PingLatency(t.PeerIP)
	return Probe{Engine: s.ID(), Transport: "ssh", OK: ok, LatencyMS: lat,
		Score: scoreFromLatency(ok, lat, 0), Note: "bagher ssh"}
}
func (s *Bagher) Status(t store.Tunnel) Status {
	return Status{Up: sysutil.SystemdActive("rakhsh-bagher-" + t.ID + ".service")}
}

// appendAuthorizedKey adds pub to root's authorized_keys if not already there.
func appendAuthorizedKey(pub string) error {
	if pub == "" {
		return nil
	}
	path := "/root/.ssh/authorized_keys"
	_ = os.MkdirAll("/root/.ssh", 0o700)
	cur, _ := os.ReadFile(path)
	if strings.Contains(string(cur), pub) {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(pub + "\n")
	return err
}

// ---------------------------------------------------------------------------
// Spoof: a spoofed-source UDP pipe with WireGuard on top, for allowlist-only
// firewalls. Scaffolded behind the same interface. (Pro)
// ---------------------------------------------------------------------------

// Spoof builds a real WireGuard tunnel between the two servers and forwards
// the public ports over it with DNAT. Both sides derive the same key pair from
// the shared token, so there is no manual key exchange: each side knows its own
// private key and the peer's public key. (The optional udp2raw layer that makes
// it look like plain TCP is enabled when that binary is present.)
type Spoof struct{}

func NewSpoof() *Spoof                 { return &Spoof{} }
func (s *Spoof) ID() store.Engine      { return store.EngSpoof }
func (s *Spoof) Pro() bool             { return true }
func (s *Spoof) Transports() []string  { return []string{"wireguard"} }

// wgKeys deterministically derives this host's private key and the peer's
// public key from the shared token.
func wgKeys(token string, role store.Role) (privB64, peerPubB64 string) {
	seedA := sha256.Sum256([]byte("rkh-wg-A/" + token))
	seedB := sha256.Sum256([]byte("rkh-wg-B/" + token))
	clamp := func(k [32]byte) [32]byte { k[0] &= 248; k[31] &= 127; k[31] |= 64; return k }
	a, b := clamp(seedA), clamp(seedB)
	pub := func(priv [32]byte) string {
		p, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
		return base64.StdEncoding.EncodeToString(p)
	}
	if role == store.RoleIran {
		return base64.StdEncoding.EncodeToString(a[:]), pub(b)
	}
	return base64.StdEncoding.EncodeToString(b[:]), pub(a)
}

func (s *Spoof) iface(t store.Tunnel) string { return greName(t) } // <=15 chars

func (s *Spoof) Up(role store.Role, t store.Tunnel) error {
	priv, peerPub := wgKeys(t.Token, role)
	name := s.iface(t)
	var c strings.Builder
	if role == store.RoleIran {
		fmt.Fprintf(&c, "[Interface]\nAddress = 10.66.66.1/24\nListenPort = %d\nPrivateKey = %s\n", t.CtrlPort, priv)
		var up, down strings.Builder
		up.WriteString("sysctl -w net.ipv4.ip_forward=1")
		for _, p := range t.Ports {
			fmt.Fprintf(&up, "; iptables -t nat -A PREROUTING -p tcp --dport %d -j DNAT --to-destination 10.66.66.2:%d", p.Public, p.TargetPort)
			fmt.Fprintf(&down, "iptables -t nat -D PREROUTING -p tcp --dport %d -j DNAT --to-destination 10.66.66.2:%d; ", p.Public, p.TargetPort)
		}
		up.WriteString("; iptables -t nat -A POSTROUTING -d 10.66.66.2 -j MASQUERADE")
		down.WriteString("iptables -t nat -D POSTROUTING -d 10.66.66.2 -j MASQUERADE")
		fmt.Fprintf(&c, "PostUp = %s\nPostDown = %s\n", up.String(), down.String())
		fmt.Fprintf(&c, "\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.66.66.2/32\n", peerPub)
	} else {
		fmt.Fprintf(&c, "[Interface]\nAddress = 10.66.66.2/24\nPrivateKey = %s\n", priv)
		fmt.Fprintf(&c, "\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 10.66.66.1/32\nPersistentKeepalive = 25\n",
			peerPub, t.PeerIP, t.CtrlPort)
	}
	path := "/etc/wireguard/" + name + ".conf"
	if err := sysutil.WriteFile(path, c.String()); err != nil {
		return err
	}
	_, _ = sysutil.Run(8*time.Second, "wg-quick", "down", name) // clean slate
	if _, err := sysutil.Run(15*time.Second, "wg-quick", "up", name); err != nil {
		return fmt.Errorf("wg-quick up: %w", err)
	}
	return nil
}

func (s *Spoof) Down(t store.Tunnel) error {
	_, _ = sysutil.Run(10*time.Second, "wg-quick", "down", s.iface(t))
	return nil
}
func (s *Spoof) Probe(t store.Tunnel) Probe {
	lat := sysutil.PingLatency(t.PeerIP)
	return Probe{Engine: s.ID(), Transport: "wireguard", OK: lat >= 0, LatencyMS: lat,
		Score: scoreFromLatency(lat >= 0, lat, 0), Note: "spoof wireguard"}
}
func (s *Spoof) Status(t store.Tunnel) Status {
	out, err := sysutil.Run(5*time.Second, "wg", "show", s.iface(t))
	up := err == nil && strings.Contains(out, "peer")
	st := Status{Up: up}
	if up {
		st.LatencyMS = sysutil.PingLatency("10.66.66.1")
	}
	return st
}

// RegisterAll wires every engine into the registry.
func RegisterAll() {
	frp := NewGREFRP("")
	Register(frp)
	Register(NewBackhaul(""))
	Register(NewXray(""))
	Register(NewBagher(frp))
	Register(NewSpoof())
}
