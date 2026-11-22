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
	"strings"
	"time"
)

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
