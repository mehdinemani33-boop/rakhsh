// Command rakhsh is the single binary behind the whole tool: the web panel,
// the headless node core, and the CLI. Subcommands:
//
//	rakhsh run                 start the panel (default)
//	rakhsh setup --role …      first-run: role, admin, panel secret
//	rakhsh status              print tunnel health
//	rakhsh carrier next <id>   rotate a tunnel to its next carrier
//	rakhsh bundle make <id>    print the rkh1_ bundle for a tunnel
//	rakhsh show-panel-url      print the panel URL
//	rakhsh reset-password      set a new admin password
//	rakhsh version
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"rakhsh/internal/billing"
	"rakhsh/internal/bundle"
	"rakhsh/internal/cluster"
	"rakhsh/internal/dns"
	"rakhsh/internal/engine"
	"rakhsh/internal/health"
	"rakhsh/internal/node"
	"rakhsh/internal/panel"
	"rakhsh/internal/store"
	"rakhsh/internal/sysutil"
	"rakhsh/internal/watchdog"
)

const statePath = "/opt/rakhsh/state.json"

// panelPort is the panel's HTTP port: the RAKHSH_PORT env wins, then the saved
// setting, else 7777. This lets a server whose 7777 is taken run on another port.
func panelPort(fromSettings int) int {
	if v := os.Getenv("RAKHSH_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	if fromSettings > 0 {
		return fromSettings
	}
	return 7777
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func mustStore() *store.Store {
	st, err := store.Open(statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "state:", err)
		os.Exit(1)
	}
	return st
}

func main() {
	engine.RegisterAll()
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "run")
	}
	switch os.Args[1] {
	case "run":
		cmdRun()
	case "setup":
		cmdSetup(os.Args[2:])
	case "status":
		cmdStatus()
	case "carrier":
		cmdCarrier(os.Args[2:])
	case "bundle":
		cmdBundle(os.Args[2:])
	case "show-panel-url":
		cmdURL()
	case "reset-password":
		cmdReset(os.Args[2:])
	case "node-join":
		cmdNodeJoin(os.Args[2:])
	case "autopilot":
		cmdAutopilot(os.Args[2:])
	case "doctor":
		cmdDoctor()
	case "version":
		fmt.Println("rakhsh", store.Version)
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}

func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	role := fs.String("role", "iran", "iran|foreign")
	user := fs.String("user", "admin", "admin username")
	pass := fs.String("pass", "", "admin password (random if empty)")
	lic := fs.String("license", "", "Pro license key")
	port := fs.Int("port", 0, "panel HTTP port (0 = 7777)")
	_ = fs.Parse(args)

	st := mustStore()
	if *pass == "" {
		*pass = randHex(9)
	}
	hash, err := panel.HashPassword(*pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	secret := randHex(18)
	nodeKey := randHex(18)
	err = st.Update(func(s *store.State) error {
		s.Role = store.Role(*role)
		s.Settings.AdminUser = *user
		s.Settings.AdminHash = hash
		s.Settings.PanelSecret = secret
		s.Settings.NodeKey = nodeKey
		s.Settings.Watchdog = true
		s.Settings.PanelPort = *port
		if *lic != "" {
			s.Settings.LicenseKey = *lic
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ip := sysutil.PublicIP()
	fmt.Println("Rakhsh setup complete.")
	fmt.Printf("  Role      : %s\n", *role)
	fmt.Printf("  Panel URL : http://%s:%d/%s\n", ip, panelPort(*port), secret)
	fmt.Printf("  Admin     : %s\n", *user)
	fmt.Printf("  Password  : %s\n", *pass)
}

func cmdRun() {
	st := mustStore()
	snap := st.Snapshot()
	if snap.Settings.PanelSecret == "" {
		fmt.Fprintln(os.Stderr, "not set up yet — run: rakhsh setup --role iran|foreign")
		os.Exit(1)
	}
	ip := sysutil.PublicIP()
	panel.SetEdgeIP(ip)

	mon := health.New(st)
	cl := cluster.New(mon.LatencyOf)
	dnsS := dns.New(func() dns.Config { return st.Snapshot().DNS })
	// Autopilot: on a down tunnel, route-test and move to the best carrier.
	mon.SetAutopilot(func(t store.Tunnel) {
		if !st.Snapshot().Settings.Autopilot {
			return
		}
		best := engine.RouteTest(t, st.Snapshot().Settings.LicenseKey != "")
		if len(best) == 0 || !best[0].OK {
			return
		}
		if old, err := engine.Get(t.Engine); err == nil {
			_ = old.Down(t)
		}
		t.Engine, t.Overlay, t.Transport = best[0].Engine, best[0].Overlay, best[0].Transport
		_ = st.Update(func(s *store.State) error {
			for i := range s.Tunnels {
				if s.Tunnels[i].ID == t.ID {
					s.Tunnels[i] = t
				}
			}
			return nil
		})
		if eng, err := engine.Get(t.Engine); err == nil {
			_ = eng.Up(snap.Role, t)
		}
	})
	stop := make(chan struct{})
	go mon.Run(stop, 10*time.Second)
	go watchdog.New(st).Run(stop, 20*time.Second)
	go billing.New(st, snap.Role).Run(stop, 60*time.Second)
	go dnsS.Run(stop)

	// If this host joined a central panel, run the heartbeat agent.
	if snap.Settings.CentralURL != "" {
		name := snap.Settings.NodeName
		if name == "" {
			name = ip
		}
		go node.Agent(snap.Settings.CentralURL, name, snap.Settings.NodeKey, stop, 15*time.Second)
	}

	// Bring enabled tunnels up on boot and start cluster pools.
	for _, t := range snap.Tunnels {
		if t.Enabled {
			if eng, err := engine.Get(t.Engine); err == nil {
				_ = eng.Up(snap.Role, t)
			}
		}
	}
	srv := panel.New(st, mon, cl, dnsS, snap.Settings.PanelSecret)
	srv.ReconcilePools()

	// Optional HTTPS on :7443 when a cert pair is present.
	certFile, keyFile := "/opt/rakhsh/tls/fullchain.pem", "/opt/rakhsh/tls/key.pem"
	if _, e1 := os.Stat(certFile); e1 == nil {
		go func() {
			hs := &http.Server{Addr: ":7443", Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
			fmt.Printf("Rakhsh panel (TLS) on https://%s:7443/%s\n", ip, snap.Settings.PanelSecret)
			_ = hs.ListenAndServeTLS(certFile, keyFile)
		}()
	}

	pport := panelPort(snap.Settings.PanelPort)
	fmt.Printf("Rakhsh panel on http://%s:%d/%s\n", ip, pport, snap.Settings.PanelSecret)
	s := &http.Server{Addr: fmt.Sprintf(":%d", pport), Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if err := s.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func cmdStatus() {
	st := mustStore()
	for _, t := range st.Snapshot().Tunnels {
		eng, err := engine.Get(t.Engine)
		if err != nil {
			continue
		}
		s := eng.Status(t)
		state := "DOWN"
		if s.Up {
			state = "UP"
		}
		fmt.Printf("%-16s %-10s %-5s lat=%.0fms\n", t.Name, t.Engine, state, s.LatencyMS)
	}
}

func cmdCarrier(args []string) {
	if len(args) < 2 || args[0] != "next" {
		fmt.Fprintln(os.Stderr, "usage: rakhsh carrier next <tunnel-id>")
		os.Exit(2)
	}
	st := mustStore()
	snap := st.Snapshot()
	for _, t := range snap.Tunnels {
		if t.ID == args[1] && len(t.Carriers) > 0 {
			n := t.Carriers[0]
			if old, err := engine.Get(t.Engine); err == nil {
				_ = old.Down(t)
			}
			t.Engine, t.Overlay, t.Transport = n.Engine, n.Overlay, n.Transport
			_ = st.Update(func(s *store.State) error {
				for i := range s.Tunnels {
					if s.Tunnels[i].ID == t.ID {
						s.Tunnels[i] = t
					}
				}
				return nil
			})
			if eng, err := engine.Get(t.Engine); err == nil {
				_ = eng.Up(snap.Role, t)
			}
			fmt.Println("switched to", t.Engine, t.Transport)
			return
		}
	}
	fmt.Fprintln(os.Stderr, "no such tunnel or no carrier chain")
}

func cmdBundle(args []string) {
	if len(args) < 2 || args[0] != "make" {
		fmt.Fprintln(os.Stderr, "usage: rakhsh bundle make <tunnel-id>")
		os.Exit(2)
	}
	st := mustStore()
	ip := sysutil.PublicIP()
	for _, t := range st.Snapshot().Tunnels {
		if t.ID == args[1] {
			b, err := bundle.Encode(t, ip)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(b)
			return
		}
	}
	fmt.Fprintln(os.Stderr, "no such tunnel")
}

func cmdURL() {
	st := mustStore()
	snap := st.Snapshot()
	fmt.Printf("http://%s:%d/%s\n", sysutil.PublicIP(), panelPort(snap.Settings.PanelPort), snap.Settings.PanelSecret)
}

func cmdNodeJoin(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: rakhsh node-join <rkhjoin_…>")
		os.Exit(2)
	}
	url, key, err := node.ParseJoinCode(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	st := mustStore()
	name := sysutil.PublicIP()
	_ = st.Update(func(s *store.State) error {
		s.Settings.CentralURL = url
		s.Settings.NodeKey = key
		s.Settings.NodeName = name
		return nil
	})
	if err := node.Beat(url, name, key); err != nil {
		fmt.Fprintln(os.Stderr, "joined, but first heartbeat failed:", err)
		return
	}
	fmt.Println("joined central panel as node", name)
}

func cmdAutopilot(args []string) {
	if len(args) < 1 || (args[0] != "on" && args[0] != "off") {
		fmt.Fprintln(os.Stderr, "usage: rakhsh autopilot on|off")
		os.Exit(2)
	}
	on := args[0] == "on"
	st := mustStore()
	_ = st.Update(func(s *store.State) error { s.Settings.Autopilot = on; return nil })
	fmt.Println("autopilot:", args[0])
}

func cmdDoctor() {
	st := mustStore()
	for _, t := range st.Snapshot().Tunnels {
		lat := sysutil.PingLatency(t.PeerIP)
		state := "ok"
		if lat < 0 {
			state = "UNREACHABLE"
		} else if lat > 400 {
			state = "slow"
		}
		fmt.Printf("%-16s peer=%-15s latency=%6.1fms  %s\n", t.Name, t.PeerIP, lat, state)
	}
}

func cmdReset(args []string) {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	pass := fs.String("pass", "", "new password (random if empty)")
	_ = fs.Parse(args)
	st := mustStore()
	if *pass == "" {
		*pass = randHex(9)
	}
	hash, err := panel.HashPassword(*pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = st.Update(func(s *store.State) error { s.Settings.AdminHash = hash; return nil })
	fmt.Println("new password:", *pass)
}
