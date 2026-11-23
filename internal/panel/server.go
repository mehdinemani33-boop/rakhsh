// Package panel serves the Rakhsh web UI and JSON API. It mounts under a long
// random secret path, authenticates with argon2id + a session cookie, and
// enforces a CSRF token on every mutating call. The same binary serves this
// panel or, with --core, runs headless as a node.
package panel

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"rakhsh/internal/bundle"
	"rakhsh/internal/cluster"
	"rakhsh/internal/dns"
	"rakhsh/internal/engine"
	"rakhsh/internal/health"
	"rakhsh/internal/license"
	"rakhsh/internal/store"
)

// WebFS holds the embedded dashboard assets (set by the main package).
var WebFS embed.FS

// Server is the panel HTTP server.
type Server struct {
	st     *store.Store
	mon    *health.Monitor
	cl     *cluster.Manager
	dnsS   *dns.Switcher
	sess   *sessions
	secret string
	mux    *http.ServeMux
}

// New builds a Server. secret is the random path segment under which
// everything is mounted (e.g. /8f3a.../...).
func New(st *store.Store, mon *health.Monitor, cl *cluster.Manager, dnsS *dns.Switcher, secret string) *Server {
	s := &Server{st: st, mon: mon, cl: cl, dnsS: dnsS, sess: newSessions(), secret: secret, mux: http.NewServeMux()}
	s.routes()
	s.extraRoutes()
	return s
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.logwrap(s.mux) }

func (s *Server) base() string { return "/" + s.secret }

// webRoot serves the dashboard from /opt/rakhsh/web when present (so design
// tweaks need only a file copy, no rebuild), falling back to the embedded copy.
func (s *Server) webRoot() fs.FS {
	if st, err := os.Stat("/opt/rakhsh/web"); err == nil && st.IsDir() {
		return os.DirFS("/opt/rakhsh/web")
	}
	sub, _ := fs.Sub(WebFS, "web")
	return sub
}

func (s *Server) routes() {
	b := s.base()
	// Static dashboard assets. Strip only the secret base so "assets/app.css"
	// survives and resolves under the web root.
	s.mux.Handle(b+"/assets/", http.StripPrefix(b+"/", http.FileServer(http.FS(s.webRoot()))))
	s.mux.HandleFunc(b+"/", s.serveIndex)

	// Auth
	s.mux.HandleFunc(b+"/api/login", s.hLogin)
	s.mux.HandleFunc(b+"/api/logout", s.hLogout)
	s.mux.HandleFunc(b+"/api/me", s.auth(s.hMe))

	// Read
	s.mux.HandleFunc(b+"/api/health", s.auth(s.hHealth))
	s.mux.HandleFunc(b+"/api/tunnels", s.auth(s.hTunnels))
	s.mux.HandleFunc(b+"/api/nodes", s.auth(s.hNodes))
	s.mux.HandleFunc(b+"/api/pools", s.auth(s.hPools))
	s.mux.HandleFunc(b+"/api/customers", s.auth(s.hCustomers))
	s.mux.HandleFunc(b+"/api/engines", s.auth(s.hEngines))

	// Mutations (CSRF-guarded inside csrf())
	s.mux.HandleFunc(b+"/api/tunnel/save", s.auth(s.csrf(s.hTunnelSave)))
	s.mux.HandleFunc(b+"/api/tunnel/delete", s.auth(s.csrf(s.hTunnelDelete)))
	s.mux.HandleFunc(b+"/api/tunnel/toggle", s.auth(s.csrf(s.hTunnelToggle)))
	s.mux.HandleFunc(b+"/api/routetest", s.auth(s.csrf(s.hRouteTest)))
	s.mux.HandleFunc(b+"/api/bundle/make", s.auth(s.csrf(s.hBundleMake)))
	s.mux.HandleFunc(b+"/api/bundle/apply", s.auth(s.csrf(s.hBundleApply)))
	s.mux.HandleFunc(b+"/api/carrier/next", s.auth(s.csrf(s.hCarrierNext)))
}

// --- middleware -------------------------------------------------------------

func (s *Server) logwrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect bare root to the secret path to avoid leaking 404 shape.
		if r.URL.Path == "/" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("rkh_sid")
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		sv, ok := s.sess.get(c.Value)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
			return
		}
		r.Header.Set("X-RKH-User", sv.user)
		r.Header.Set("X-RKH-CSRF", sv.csrf)
		next(w, r)
	}
}

func (s *Server) csrf(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
			return
		}
		if r.Header.Get("X-CSRF-Token") != r.Header.Get("X-RKH-CSRF") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "bad csrf token"})
			return
		}
		next(w, r)
	}
}

// --- auth handlers ----------------------------------------------------------

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request) {
	var in struct{ User, Pass, TOTP string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	set := s.st.Snapshot().Settings
	if in.User != set.AdminUser || !VerifyPassword(in.Pass, set.AdminHash) {
		time.Sleep(600 * time.Millisecond) // throttle guessing
		writeJSON(w, 401, map[string]string{"error": "wrong credentials"})
		return
	}
	if set.TOTPSecret != "" && !verifyTOTP(set.TOTPSecret, in.TOTP) {
		writeJSON(w, 401, map[string]string{"error": "2fa required"})
		return
	}
	sid, csrf := s.sess.create(in.User)
	http.SetCookie(w, &http.Cookie{Name: "rkh_sid", Value: sid, Path: s.base(),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 43200})
	writeJSON(w, 200, map[string]string{"ok": "1", "csrf": csrf})
}

func (s *Server) hLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("rkh_sid"); err == nil {
		s.sess.drop(c.Value)
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) hMe(w http.ResponseWriter, r *http.Request) {
	snap := s.st.Snapshot()
	writeJSON(w, 200, map[string]any{
		"user": r.Header.Get("X-RKH-User"), "csrf": r.Header.Get("X-RKH-CSRF"),
		"role": snap.Role, "pro": license.Valid(snap.Settings.LicenseKey),
		"overall": s.mon.Overall(), "version": store.Version,
	})
}

// --- read handlers ----------------------------------------------------------

func (s *Server) hHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"overall": s.mon.Overall(), "links": s.mon.Links()})
}

func (s *Server) hTunnels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.st.Snapshot().Tunnels)
}
func (s *Server) hNodes(w http.ResponseWriter, r *http.Request)     { writeJSON(w, 200, s.st.Snapshot().Nodes) }
func (s *Server) hPools(w http.ResponseWriter, r *http.Request)     { writeJSON(w, 200, s.st.Snapshot().Pools) }
func (s *Server) hCustomers(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, s.st.Snapshot().Customers) }

func (s *Server) hEngines(w http.ResponseWriter, r *http.Request) {
	licensed := license.Valid(s.st.Snapshot().Settings.LicenseKey)
	var out []map[string]any
	for _, e := range engine.All() {
		out = append(out, map[string]any{
			"id": e.ID(), "pro": e.Pro(), "locked": e.Pro() && !licensed,
			"transports": e.Transports(),
		})
	}
	writeJSON(w, 200, out)
}

// --- mutation handlers ------------------------------------------------------

func (s *Server) hTunnelSave(w http.ResponseWriter, r *http.Request) {
	var t store.Tunnel
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad tunnel"})
		return
	}
	if t.ID == "" {
		t.ID = randToken(5)
		t.CreatedAt = time.Now()
	}
	if t.Token == "" {
		t.Token = randToken(18)
	}
	snap := s.st.Snapshot()
	if eng, err := engine.Get(t.Engine); err == nil && eng.Pro() && !license.Valid(snap.Settings.LicenseKey) {
		writeJSON(w, 402, map[string]string{"error": "این موتور لایسنس Pro می‌خواهد"})
		return
	}
	err := s.st.Update(func(st *store.State) error {
		for i := range st.Tunnels {
			if st.Tunnels[i].ID == t.ID {
				st.Tunnels[i] = t
				return nil
			}
		}
		st.Tunnels = append(st.Tunnels, t)
		return nil
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if t.Enabled {
		if eng, err := engine.Get(t.Engine); err == nil {
			if err := eng.Up(snap.Role, t); err != nil {
				writeJSON(w, 200, map[string]any{"ok": "1", "warn": err.Error(), "tunnel": t})
				return
			}
		}
	}
	writeJSON(w, 200, map[string]any{"ok": "1", "tunnel": t})
}

func (s *Server) hTunnelToggle(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	snap := s.st.Snapshot()
	var tn store.Tunnel
	_ = s.st.Update(func(st *store.State) error {
		for i := range st.Tunnels {
			if st.Tunnels[i].ID == id {
				st.Tunnels[i].Enabled = !st.Tunnels[i].Enabled
				tn = st.Tunnels[i]
			}
		}
		return nil
	})
	if eng, err := engine.Get(tn.Engine); err == nil {
		if tn.Enabled {
			_ = eng.Up(snap.Role, tn)
		} else {
			_ = eng.Down(tn)
		}
	}
	writeJSON(w, 200, map[string]any{"ok": "1", "enabled": tn.Enabled})
}

func (s *Server) hTunnelDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var tn store.Tunnel
	_ = s.st.Update(func(st *store.State) error {
		out := st.Tunnels[:0]
		for _, t := range st.Tunnels {
			if t.ID == id {
				tn = t
				continue
			}
			out = append(out, t)
		}
		st.Tunnels = out
		return nil
	})
	if eng, err := engine.Get(tn.Engine); err == nil {
		_ = eng.Down(tn)
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) hRouteTest(w http.ResponseWriter, r *http.Request) {
	var t store.Tunnel
	_ = json.NewDecoder(r.Body).Decode(&t)
	licensed := license.Valid(s.st.Snapshot().Settings.LicenseKey)
	writeJSON(w, 200, engine.RouteTest(t, licensed))
}

func (s *Server) hBundleMake(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	snap := s.st.Snapshot()
	edge := snap.Settings.PanelSecret // placeholder; real edge IP set below
	_ = edge
	for _, t := range snap.Tunnels {
		if t.ID == id {
			b, err := bundle.Encode(t, edgeIP())
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"bundle": b})
			return
		}
	}
	writeJSON(w, 404, map[string]string{"error": "tunnel not found"})
}

func (s *Server) hBundleApply(w http.ResponseWriter, r *http.Request) {
	var in struct{ Bundle string }
	_ = json.NewDecoder(r.Body).Decode(&in)
	t, _, err := bundle.Decode(in.Bundle)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	t.Enabled = true
	t.LocalIP = edgeIP()
	snap := s.st.Snapshot()
	_ = s.st.Update(func(st *store.State) error {
		for i := range st.Tunnels {
			if st.Tunnels[i].ID == t.ID {
				st.Tunnels[i] = t
				return nil
			}
		}
		st.Tunnels = append(st.Tunnels, t)
		return nil
	})
	if eng, err := engine.Get(t.Engine); err == nil {
		if err := eng.Up(snap.Role, t); err != nil {
			writeJSON(w, 200, map[string]any{"ok": "1", "warn": err.Error()})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": "1", "tunnel": t})
}

func (s *Server) hCarrierNext(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	snap := s.st.Snapshot()
	for _, t := range snap.Tunnels {
		if t.ID == id && len(t.Carriers) > 0 {
			next := t.Carriers[0]
			if old, err := engine.Get(t.Engine); err == nil {
				_ = old.Down(t)
			}
			t.Engine, t.Overlay, t.Transport = next.Engine, next.Overlay, next.Transport
			t.Carriers = append(t.Carriers[1:], next) // rotate
			_ = s.st.Update(func(st *store.State) error {
				for i := range st.Tunnels {
					if st.Tunnels[i].ID == id {
						st.Tunnels[i] = t
					}
				}
				return nil
			})
			if eng, err := engine.Get(t.Engine); err == nil {
				_ = eng.Up(snap.Role, t)
			}
			writeJSON(w, 200, map[string]any{"ok": "1", "engine": t.Engine, "transport": t.Transport})
			return
		}
	}
	writeJSON(w, 400, map[string]string{"error": "no carrier chain"})
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(s.webRoot(), "index.html")
	if err != nil {
		http.Error(w, "dashboard missing", 500)
		return
	}
	html := strings.ReplaceAll(string(b), "__BASE__", s.base())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// edgeIP is overridable; defaults to discovered public IP cached at startup.
var edgeIP = func() string { return cachedEdgeIP }

var cachedEdgeIP string

// SetEdgeIP caches the public IP used in bundles.
func SetEdgeIP(ip string) { cachedEdgeIP = ip }
