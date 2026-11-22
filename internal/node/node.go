// Package node turns one Rakhsh install into a managed node of a central panel.
// A node runs the same binary headless, sends a heartbeat with live metrics,
// and shows up on the central node map. A join code carries the central URL and
// a shared key so joining is one command.
package node

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"rakhsh/internal/sysutil"
)

// Metrics is the live snapshot a node reports.
type Metrics struct {
	Load    float64 `json:"load"`
	MemPct  float64 `json:"mem_pct"`
	DiskPct float64 `json:"disk_pct"`
	RxBytes int64   `json:"rx_bytes"`
	TxBytes int64   `json:"tx_bytes"`
	PubIP   string  `json:"pub_ip"`
}

// Heartbeat is what a node POSTs to the central panel.
type Heartbeat struct {
	Name    string  `json:"name"`
	JoinKey string  `json:"join_key"`
	Metrics Metrics `json:"metrics"`
	Time    int64   `json:"time"`
}

// Gather reads this host's live metrics from /proc.
func Gather() Metrics {
	m := Metrics{PubIP: sysutil.PublicIP()}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			m.Load, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	m.MemPct = memPct()
	m.DiskPct = diskPct("/")
	m.RxBytes, m.TxBytes = netBytes()
	return m
}

func memPct() float64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	var total, avail float64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(f[1], 64)
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total == 0 {
		return 0
	}
	return (total - avail) / total * 100
}

func diskPct(path string) float64 {
	out, err := sysutil.Run(5*time.Second, "df", "-P", path)
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return 0
	}
	f := strings.Fields(lines[1])
	if len(f) < 5 {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.TrimSuffix(f[4], "%"), 64)
	return v
}

func netBytes() (rx, tx int64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.Contains(line, ":") || strings.Contains(line, "lo:") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		f := strings.Fields(parts[1])
		if len(f) < 9 {
			continue
		}
		r, _ := strconv.ParseInt(f[0], 10, 64)
		t, _ := strconv.ParseInt(f[8], 10, 64)
		rx += r
		tx += t
	}
	return
}

// JoinCode packs the central URL + shared key into one token.
func JoinCode(centralURL, key string) string {
	raw, _ := json.Marshal(map[string]string{"u": centralURL, "k": key})
	return "rkhjoin_" + base64.RawURLEncoding.EncodeToString(raw)
}

// ParseJoinCode unpacks a join code.
func ParseJoinCode(code string) (url, key string, err error) {
	code = strings.TrimSpace(code)
	if !strings.HasPrefix(code, "rkhjoin_") {
		return "", "", fmt.Errorf("not a join code")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, "rkhjoin_"))
	if err != nil {
		return "", "", err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", err
	}
	return m["u"], m["k"], nil
}

// Beat sends one heartbeat to the central panel.
func Beat(centralURL, name, key string) error {
	hb := Heartbeat{Name: name, JoinKey: key, Metrics: Gather(), Time: time.Now().Unix()}
	body, _ := json.Marshal(hb)
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(centralURL, "/")+"/api/node/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("central rejected heartbeat: %d", resp.StatusCode)
	}
	return nil
}

// Agent runs the heartbeat loop from a node to its central panel.
func Agent(centralURL, name, key string, stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	_ = Beat(centralURL, name, key)
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = Beat(centralURL, name, key)
		}
	}
}
