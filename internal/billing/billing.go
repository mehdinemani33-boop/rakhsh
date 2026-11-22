// Package billing sells tunnels by plan — days, volume and speed — and cuts a
// customer's tunnel off the moment the plan ends or the cap is hit. One
// enforcer loop keeps the live state honest without the panel being open.
package billing

import (
	"time"

	"rakhsh/internal/engine"
	"rakhsh/internal/store"
)

const giB = 1024 * 1024 * 1024

// Enforcer periodically suspends expired/over-cap customers and resumes
// renewed ones, flipping the backing tunnel's Enabled state to match.
type Enforcer struct {
	st   *store.Store
	role store.Role
}

// New builds an Enforcer.
func New(st *store.Store, role store.Role) *Enforcer { return &Enforcer{st: st, role: role} }

// Run checks every interval until stop closes.
func (e *Enforcer) Run(stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	e.tick()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			e.tick()
		}
	}
}

func overCap(c store.Customer) bool {
	if time.Now().After(c.ExpiresAt) {
		return true
	}
	if c.VolumeGB > 0 && c.UsedBytes >= int64(c.VolumeGB)*giB {
		return true
	}
	return false
}

func (e *Enforcer) tick() {
	var toDown, toUp []store.Tunnel
	_ = e.st.Update(func(s *store.State) error {
		byID := map[string]*store.Tunnel{}
		for i := range s.Tunnels {
			byID[s.Tunnels[i].ID] = &s.Tunnels[i]
		}
		for i := range s.Customers {
			c := &s.Customers[i]
			tn := byID[c.TunnelID]
			if tn == nil {
				continue
			}
			switch {
			case overCap(*c) && !c.Suspended:
				c.Suspended = true
				if tn.Enabled {
					tn.Enabled = false
					toDown = append(toDown, *tn)
				}
			case !overCap(*c) && c.Suspended:
				c.Suspended = false
				if !tn.Enabled {
					tn.Enabled = true
					toUp = append(toUp, *tn)
				}
			}
		}
		return nil
	})
	for _, tn := range toDown {
		if eng, err := engine.Get(tn.Engine); err == nil {
			_ = eng.Down(tn)
		}
	}
	for _, tn := range toUp {
		if eng, err := engine.Get(tn.Engine); err == nil {
			_ = eng.Up(e.role, tn)
		}
	}
}

// Create adds a customer with a plan starting now.
func Create(st *store.Store, c store.Customer) store.Customer {
	if c.ID == "" {
		c.ID = time.Now().Format("150405.000")
	}
	c.CreatedAt = time.Now()
	if c.Days > 0 {
		c.ExpiresAt = time.Now().AddDate(0, 0, c.Days)
	}
	_ = st.Update(func(s *store.State) error {
		s.Customers = append(s.Customers, c)
		return nil
	})
	return c
}

// Renew extends a customer by days and clears suspension.
func Renew(st *store.Store, id string, days int) {
	_ = st.Update(func(s *store.State) error {
		for i := range s.Customers {
			if s.Customers[i].ID == id {
				base := s.Customers[i].ExpiresAt
				if base.Before(time.Now()) {
					base = time.Now()
				}
				s.Customers[i].ExpiresAt = base.AddDate(0, 0, days)
				s.Customers[i].UsedBytes = 0
				s.Customers[i].Suspended = false
			}
		}
		return nil
	})
}

// AddUsage increments a customer's counted traffic (fed by the poller).
func AddUsage(st *store.Store, id string, bytes int64) {
	_ = st.Update(func(s *store.State) error {
		for i := range s.Customers {
			if s.Customers[i].ID == id {
				s.Customers[i].UsedBytes += bytes
			}
		}
		return nil
	})
}
