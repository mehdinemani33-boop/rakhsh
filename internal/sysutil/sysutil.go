// Package sysutil wraps the shell-outs Rakhsh needs: ip(8), systemd, and
// small probes. Every command is logged and bounded by a context so a hung
// link can never wedge the daemon.
package sysutil

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// IptAcctEnsure installs idempotent byte-counting iptables rules for the given
// TCP ports, tagged with a comment so they can be read and removed per tunnel.
// INPUT/dport counts client→server (upload); OUTPUT/sport counts server→client
// (download). The rules carry no target, so they only count and fall through.
func IptAcctEnsure(tag string, ports []int) {
	for _, p := range ports {
		ps := strconv.Itoa(p)
		if !RunOK(3*time.Second, "iptables", "-C", "INPUT", "-p", "tcp", "--dport", ps, "-m", "comment", "--comment", tag) {
			_, _ = Run(3*time.Second, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", ps, "-m", "comment", "--comment", tag)
		}
		if !RunOK(3*time.Second, "iptables", "-C", "OUTPUT", "-p", "tcp", "--sport", ps, "-m", "comment", "--comment", tag) {
			_, _ = Run(3*time.Second, "iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", ps, "-m", "comment", "--comment", tag)
		}
	}
}

// IptAcctRead returns (download, upload) bytes summed from the tagged rules.
func IptAcctRead(tag string) (down, up int64) {
	return iptSum("OUTPUT", tag), iptSum("INPUT", tag)
}

func iptSum(chain, tag string) int64 {
	out, _ := Run(3*time.Second, "iptables", "-t", "filter", "-nvxL", chain)
	var sum int64
	for _, ln := range strings.Split(out, "\n") {
		if !strings.Contains(ln, tag) {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		var b int64
		fmt.Sscan(f[1], &b)
		sum += b
	}
	return sum
}

// IptAcctDel removes the tagged counting rules for the given ports.
func IptAcctDel(tag string, ports []int) {
	for _, p := range ports {
		ps := strconv.Itoa(p)
		for RunOK(2*time.Second, "iptables", "-C", "INPUT", "-p", "tcp", "--dport", ps, "-m", "comment", "--comment", tag) {
			_, _ = Run(3*time.Second, "iptables", "-D", "INPUT", "-p", "tcp", "--dport", ps, "-m", "comment", "--comment", tag)
		}
		for RunOK(2*time.Second, "iptables", "-C", "OUTPUT", "-p", "tcp", "--sport", ps, "-m", "comment", "--comment", tag) {
			_, _ = Run(3*time.Second, "iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", ps, "-m", "comment", "--comment", tag)
		}
	}
}

// IfaceBytes returns (rxBytes, txBytes) for one interface from /proc/net/dev,
// or (0,0) if it is absent.
func IfaceBytes(name string) (int64, int64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, ln := range strings.Split(string(b), "\n") {
		i := strings.IndexByte(ln, ':')
		if i < 0 {
			continue
		}
		if strings.TrimSpace(ln[:i]) != name {
			continue
		}
		f := strings.Fields(ln[i+1:])
		if len(f) < 9 {
			return 0, 0
		}
		var rx, tx int64
		fmt.Sscan(f[0], &rx)
		fmt.Sscan(f[8], &tx)
		return rx, tx
	}
	return 0, 0
}

// NetTotals sums rx/tx bytes across real interfaces (skips lo and virtual/
// bridge/veth/docker devices) — the server's live throughput.
func NetTotals() (int64, int64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	var rx, tx int64
	for _, ln := range strings.Split(string(b), "\n") {
		i := strings.IndexByte(ln, ':')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(ln[:i])
		if name == "lo" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") ||
			strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "virbr") {
			continue
		}
		f := strings.Fields(ln[i+1:])
		if len(f) < 9 {
			continue
		}
		var r, t int64
		fmt.Sscan(f[0], &r)
		fmt.Sscan(f[8], &t)
		rx += r
		tx += t
	}
	return rx, tx
}

// Run executes name+args with a timeout and returns combined output.
func Run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, out)
	}
	return out, nil
}

// RunOK is Run that only reports success.
func RunOK(timeout time.Duration, name string, args ...string) bool {
	_, err := Run(timeout, name, args...)
	return err == nil
}

// WriteFile writes data to path with 0600 and parent dirs.
func WriteFile(path string, data string) error {
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		if err := os.MkdirAll(path[:i], 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(data), 0o600)
}

// SystemdInstall writes a unit, reloads, enables and (re)starts it.
func SystemdInstall(unit, contents string) error {
	path := "/etc/systemd/system/" + unit
	if err := WriteFile(path, contents); err != nil {
		return err
	}
	if _, err := Run(10*time.Second, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := Run(10*time.Second, "systemctl", "enable", unit); err != nil {
		return err
	}
	_, err := Run(20*time.Second, "systemctl", "restart", unit)
	return err
}

// SystemdStop stops and disables a unit, ignoring "not found".
func SystemdStop(unit string) {
	_, _ = Run(10*time.Second, "systemctl", "stop", unit)
	_, _ = Run(10*time.Second, "systemctl", "disable", unit)
}

// SystemdActive reports whether a unit is active.
func SystemdActive(unit string) bool {
	out, _ := Run(5*time.Second, "systemctl", "is-active", unit)
	return out == "active"
}

// PingLatency returns round-trip ms to host, or -1 on failure.
func PingLatency(host string) float64 {
	out, err := Run(5*time.Second, "ping", "-c", "2", "-W", "2", host)
	if err != nil {
		return -1
	}
	// parse "rtt min/avg/max/mdev = 1.2/3.4/5.6/0.1 ms"
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "min/avg/max") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				nums := strings.Split(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[1]), "ms")), "/")
				if len(nums) >= 2 {
					var avg float64
					fmt.Sscanf(nums[1], "%f", &avg)
					return avg
				}
			}
		}
	}
	return -1
}

// TCPOpen reports whether host:port accepts a connection within timeout.
func TCPOpen(hostport string, timeout time.Duration) bool {
	return RunOK(timeout+time.Second, "bash", "-c",
		fmt.Sprintf("timeout %d bash -c 'exec 3<>/dev/tcp/%s' 2>/dev/null",
			int(timeout.Seconds())+1, strings.Replace(hostport, ":", "/", 1)))
}

// PublicIP best-effort discovers this host's public IPv4.
func PublicIP() string {
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me"} {
		if out, err := Run(6*time.Second, "curl", "-fsS", "-m", "5", u); err == nil && out != "" {
			return strings.TrimSpace(out)
		}
	}
	out, _ := Run(3*time.Second, "bash", "-c", "hostname -I | awk '{print $1}'")
	return strings.TrimSpace(out)
}
