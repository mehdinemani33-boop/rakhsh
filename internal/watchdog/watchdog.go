// Package watchdog restarts only the units that are genuinely dead. It never
// touches a tunnel whose service is active, so a busy, healthy hub is left
// alone even while a sick neighbour is being revived.
package watchdog

import (
	"time"

	"rakhsh/internal/store"
	"rakhsh/internal/sysutil"
)

// Units a tunnel can own, by engine.
func units(t store.Tunnel) []string {
	return []string{
		"rakhsh-frps-" + t.ID + ".service",
		"rakhsh-frpc-" + t.ID + ".service",
		"rakhsh-backhaul-" + t.ID + ".service",
		"rakhsh-xray-" + t.ID + ".service",
		"rakhsh-bagher-" + t.ID + ".service",
		"rakhsh-spoof-" + t.ID + ".service",
	}
}

// Watchdog revives dead units for enabled tunnels.
type Watchdog struct{ st *store.Store }

// New builds a Watchdog.
func New(st *store.Store) *Watchdog { return &Watchdog{st: st} }

// Run checks every interval until stop closes. It is a no-op when the setting
// is off.
func (w *Watchdog) Run(stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			w.tick()
		}
	}
}

func (w *Watchdog) tick() {
	snap := w.st.Snapshot()
	if !snap.Settings.Watchdog {
		return
	}
	for _, tn := range snap.Tunnels {
		if !tn.Enabled {
			continue
		}
		for _, u := range units(tn) {
			// Only act on a unit that exists (has a config) but is not active.
			if unitKnown(u) && !sysutil.SystemdActive(u) {
				_, _ = sysutil.Run(15*time.Second, "systemctl", "restart", u)
			}
		}
	}
}

// unitKnown reports whether systemd has ever loaded this unit (so we do not
// try to start units for engines this tunnel never used).
func unitKnown(u string) bool {
	out, _ := sysutil.Run(5*time.Second, "systemctl", "list-unit-files", u)
	return len(out) > 0 && !containsNoFiles(out)
}

func containsNoFiles(s string) bool {
	return len(s) >= 11 && (s[:11] == "0 unit file" || s == "0 unit files listed.")
}
