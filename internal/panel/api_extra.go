package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"rakhsh/internal/backup"
	"rakhsh/internal/billing"
	"rakhsh/internal/diag"
	"rakhsh/internal/dns"
	"rakhsh/internal/license"
	"rakhsh/internal/node"
	"rakhsh/internal/store"
	"rakhsh/internal/sysutil"
	"rakhsh/internal/update"
)

// nodeMetrics holds the latest heartbeat metrics per node name.
var (
	nmMu        sync.Mutex
	nodeMetrics = map[string]node.Metrics{}
)

func (s *Server) extraRoutes() {
	b := s.base()
	// Unauthenticated helpers used by peers/nodes (they already hold the secret path).
	s.mux.HandleFunc(b+"/api/time", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%d", time.Now().Unix())
	})
	s.mux.HandleFunc(b+"/api/node/heartbeat", s.hNodeHeartbeat)

	// Node management
	s.mux.HandleFunc(b+"/api/node/joincode", s.auth(s.hJoinCode))

	// Cluster
	s.mux.HandleFunc(b+"/api/cluster/stats", s.auth(s.hClusterStats))
	s.mux.HandleFunc(b+"/api/pool/save", s.auth(s.csrf(s.hPoolSave)))
	s.mux.HandleFunc(b+"/api/pool/delete", s.auth(s.csrf(s.hPoolDelete)))

	// Customers / billing
	s.mux.HandleFunc(b+"/api/customer/save", s.auth(s.csrf(s.hCustomerSave)))
	s.mux.HandleFunc(b+"/api/customer/renew", s.auth(s.csrf(s.hCustomerRenew)))
	s.mux.HandleFunc(b+"/api/customer/delete", s.auth(s.csrf(s.hCustomerDelete)))

	// Diagnostics
	s.mux.HandleFunc(b+"/api/diag/reach", s.auth(s.csrf(s.hDiagReach)))
	s.mux.HandleFunc(b+"/api/diag/hops", s.auth(s.csrf(s.hDiagHops)))
	s.mux.HandleFunc(b+"/api/diag/stability", s.auth(s.csrf(s.hDiagStability)))
	s.mux.HandleFunc(b+"/api/diag/ports", s.auth(s.csrf(s.hDiagPorts)))

	// Settings / 2FA
	s.mux.HandleFunc(b+"/api/settings/save", s.auth(s.csrf(s.hSettingsSave)))
	s.mux.HandleFunc(b+"/api/2fa/enable", s.auth(s.csrf(s.h2FAEnable)))
	s.mux.HandleFunc(b+"/api/2fa/disable", s.auth(s.csrf(s.h2FADisable)))

	// License
	s.mux.HandleFunc(b+"/api/license/status", s.auth(s.hLicenseStatus))
	s.mux.HandleFunc(b+"/api/license/set", s.auth(s.csrf(s.hLicenseSet)))

	// DNS switching (hub cluster)
	s.mux.HandleFunc(b+"/api/dns/get", s.auth(s.hDNSGet))
	s.mux.HandleFunc(b+"/api/dns/save", s.auth(s.csrf(s.hDNSSave)))
	s.mux.HandleFunc(b+"/api/dns/test", s.auth(s.csrf(s.hDNSTest)))

	// Backup / update
	s.mux.HandleFunc(b+"/api/backup/create", s.auth(s.csrf(s.hBackupCreate)))
	s.mux.HandleFunc(b+"/api/update/apply", s.auth(s.csrf(s.hUpdateApply)))
	s.mux.HandleFunc(b+"/api/update/rollback", s.auth(s.csrf(s.hUpdateRollback)))
}

// --- nodes ------------------------------------------------------------------

func (s *Server) hNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	var hb node.Heartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad heartbeat"})
		return
	}
	set := s.st.Snapshot().Settings
	if set.NodeKey == "" || hb.JoinKey != set.NodeKey {
		writeJSON(w, 403, map[string]string{"error": "bad node key"})
		return
	}
	nmMu.Lock()
	nodeMetrics[hb.Name] = hb.Metrics
	nmMu.Unlock()
	_ = s.st.Update(func(st *store.State) error {
		for i := range st.Nodes {
			if st.Nodes[i].Name == hb.Name {
				st.Nodes[i].LastSeen = time.Now()
				st.Nodes[i].Addr = hb.Metrics.PubIP
				return nil
			}
		}
		st.Nodes = append(st.Nodes, store.Node{ID: hb.Name, Name: hb.Name,
			Addr: hb.Metrics.PubIP, Core: true, LastSeen: time.Now()})
		return nil
	})
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) hJoinCode(w http.ResponseWriter, r *http.Request) {
	snap := s.st.Snapshot()
	central := fmt.Sprintf("http://%s:7777/%s", edgeIP(), snap.Settings.PanelSecret)
	code := node.JoinCode(central, snap.Settings.NodeKey)
	oneLiner := "bash <(curl -fsSL https://.../install.sh) && rakhsh node-join " + code
	writeJSON(w, 200, map[string]string{"code": code, "install": oneLiner})
}

// --- cluster ----------------------------------------------------------------

// ReconcilePools is the exported entry used at startup.
func (s *Server) ReconcilePools() { s.reconcilePools() }

func (s *Server) reconcilePools() {
	snap := s.st.Snapshot()
	resolve := func(id string) (string, bool) {
		for _, t := range snap.Tunnels {
			if t.ID == id && len(t.Ports) > 0 {
				return fmt.Sprintf("127.0.0.1:%d", t.Ports[0].Public), true
			}
		}
		return "", false
	}
	if s.cl != nil {
		s.cl.Apply(snap.Pools, resolve)
	}
}

func (s *Server) hClusterStats(w http.ResponseWriter, r *http.Request) {
	if s.cl == nil {
		writeJSON(w, 200, map[string]any{})
		return
	}
	writeJSON(w, 200, s.cl.Stats())
}

func (s *Server) hPoolSave(w http.ResponseWriter, r *http.Request) {
	if !license.Valid(s.st.Snapshot().Settings.LicenseKey) {
		writeJSON(w, 402, map[string]string{"error": "کلاستر لایسنس Pro می‌خواهد"})
		return
	}
	var p store.Pool
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad pool"})
		return
	}
	if p.ID == "" {
		p.ID = randToken(5)
	}
	if p.Strategy == "" {
		p.Strategy = "failover"
	}
	_ = s.st.Update(func(st *store.State) error {
		for i := range st.Pools {
			if st.Pools[i].ID == p.ID {
				st.Pools[i] = p
				return nil
			}
		}
		st.Pools = append(st.Pools, p)
		return nil
	})
	s.reconcilePools()
	writeJSON(w, 200, map[string]any{"ok": "1", "pool": p})
}

func (s *Server) hPoolDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	_ = s.st.Update(func(st *store.State) error {
		out := st.Pools[:0]
		for _, p := range st.Pools {
			if p.ID != id {
				out = append(out, p)
			}
		}
		st.Pools = out
		return nil
	})
	s.reconcilePools()
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// --- customers --------------------------------------------------------------

func (s *Server) hCustomerSave(w http.ResponseWriter, r *http.Request) {
	var c store.Customer
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad customer"})
		return
	}
	c = billing.Create(s.st, c)
	writeJSON(w, 200, map[string]any{"ok": "1", "customer": c})
}

func (s *Server) hCustomerRenew(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	days := 30
	fmt.Sscanf(r.URL.Query().Get("days"), "%d", &days)
	billing.Renew(s.st, id, days)
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) hCustomerDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	_ = s.st.Update(func(st *store.State) error {
		out := st.Customers[:0]
		for _, c := range st.Customers {
			if c.ID != id {
				out = append(out, c)
			}
		}
		st.Customers = out
		return nil
	})
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// --- diagnostics ------------------------------------------------------------

func (s *Server) hDiagReach(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host string
		Port int
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	writeJSON(w, 200, diag.Reachability(in.Host, in.Port))
}

func (s *Server) hDiagHops(w http.ResponseWriter, r *http.Request) {
	var in struct{ Host string }
	_ = json.NewDecoder(r.Body).Decode(&in)
	writeJSON(w, 200, diag.HopPath(in.Host))
}

func (s *Server) hDiagStability(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host  string
		Count int
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	pts, loss := diag.Stability(in.Host, in.Count)
	writeJSON(w, 200, map[string]any{"samples": pts, "loss_pct": loss})
}

func (s *Server) hDiagPorts(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	for _, t := range s.st.Snapshot().Tunnels {
		if t.ID == id {
			writeJSON(w, 200, diag.PortForwards(edgeIP(), t.Ports))
			return
		}
	}
	writeJSON(w, 404, map[string]string{"error": "tunnel not found"})
}

// --- settings / 2fa ---------------------------------------------------------

func (s *Server) hSettingsSave(w http.ResponseWriter, r *http.Request) {
	var in store.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad settings"})
		return
	}
	_ = s.st.Update(func(st *store.State) error {
		// Only the operator-tunable knobs; never overwrite secrets/hash here.
		st.Settings.Autopilot = in.Autopilot
		st.Settings.Watchdog = in.Watchdog
		st.Settings.UpdateChannel = in.UpdateChannel
		st.Settings.AlertWebhook = in.AlertWebhook
		st.Settings.AlertTGToken = in.AlertTGToken
		st.Settings.AlertTGChat = in.AlertTGChat
		if in.LicenseKey != "" {
			st.Settings.LicenseKey = in.LicenseKey
		}
		return nil
	})
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) h2FAEnable(w http.ResponseWriter, r *http.Request) {
	secret := NewTOTPSecret()
	user := s.st.Snapshot().Settings.AdminUser
	_ = s.st.Update(func(st *store.State) error { st.Settings.TOTPSecret = secret; return nil })
	writeJSON(w, 200, map[string]string{"secret": secret, "uri": TOTPURI(secret, user)})
}

func (s *Server) h2FADisable(w http.ResponseWriter, r *http.Request) {
	_ = s.st.Update(func(st *store.State) error { st.Settings.TOTPSecret = ""; return nil })
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// --- backup / update --------------------------------------------------------

func (s *Server) hBackupCreate(w http.ResponseWriter, r *http.Request) {
	var in struct{ Passphrase string }
	_ = json.NewDecoder(r.Body).Decode(&in)
	if in.Passphrase == "" {
		writeJSON(w, 400, map[string]string{"error": "passphrase required"})
		return
	}
	out := "/opt/rakhsh/backup-" + time.Now().Format("20060102-150405") + ".rkhbak"
	if err := backup.Create(out, in.Passphrase); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1", "file": out})
}

func (s *Server) hUpdateApply(w http.ResponseWriter, r *http.Request) {
	snap := s.st.Snapshot()
	ver, err := update.Apply(snap.Settings.UpdateChannel, goArch())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1", "version": ver})
}

func (s *Server) hUpdateRollback(w http.ResponseWriter, r *http.Request) {
	if err := update.Rollback(); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// --- DNS switching ----------------------------------------------------------

func (s *Server) hDNSGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.st.Snapshot().DNS
	masked := cfg
	if masked.Token != "" {
		masked.Token = "set" // never echo the token back
	}
	var st dns.Status
	if s.dnsS != nil {
		st = s.dnsS.Snapshot()
	}
	writeJSON(w, 200, map[string]any{"config": masked, "status": st})
}

func (s *Server) hDNSSave(w http.ResponseWriter, r *http.Request) {
	if !license.Valid(s.st.Snapshot().Settings.LicenseKey) {
		writeJSON(w, 402, map[string]string{"error": "جابه‌جایی DNS لایسنس Pro می‌خواهد"})
		return
	}
	var in dns.Config
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad config"})
		return
	}
	if in.EverySec <= 0 {
		in.EverySec = 10
	}
	if in.CheckPort <= 0 {
		in.CheckPort = 8080
	}
	if in.Fall <= 0 {
		in.Fall = 3
	}
	if in.Rise <= 0 {
		in.Rise = 3
	}
	_ = s.st.Update(func(st *store.State) error {
		// keep the existing token when the client sends the masked placeholder
		if in.Token == "" || in.Token == "set" {
			in.Token = st.DNS.Token
		}
		st.DNS = in
		return nil
	})
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) hDNSTest(w http.ResponseWriter, r *http.Request) {
	var in dns.Config
	_ = json.NewDecoder(r.Body).Decode(&in)
	if in.Token == "" || in.Token == "set" {
		in.Token = s.st.Snapshot().DNS.Token
	}
	if in.Domain == "" {
		in.Domain = s.st.Snapshot().DNS.Domain
	}
	zone, ips, err := dns.Test(in)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "zone": zone, "records": ips})
}

// --- license ----------------------------------------------------------------

func (s *Server) hLicenseStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, license.Describe(s.st.Snapshot().Settings.LicenseKey))
}

func (s *Server) hLicenseSet(w http.ResponseWriter, r *http.Request) {
	var in struct{ License string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	key := strings.TrimSpace(in.License)
	if key != "" {
		if _, err := license.Verify(key); err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}
	_ = s.st.Update(func(st *store.State) error { st.Settings.LicenseKey = key; return nil })
	writeJSON(w, 200, map[string]any{"ok": true, "status": license.Describe(key)})
}

// goArch returns amd64/arm64 for update downloads.
func goArch() string {
	out, _ := sysutil.Run(3*time.Second, "uname", "-m")
	switch out {
	case "aarch64", "arm64":
		return "arm64"
	default:
		return "amd64"
	}
}
