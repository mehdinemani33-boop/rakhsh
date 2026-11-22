// Package update swaps the rakhsh binary for a newer one and can always put
// the old one back. It downloads over the chosen channel, verifies the SHA-256
// against the published sum, keeps the current binary as .bak, and rolls back
// if the new binary cannot even print its version.
package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"rakhsh/internal/sysutil"
)

// Base is the release host; channels resolve to base/<channel>/...
var Base = "https://github.com/YOURORG/rakhsh/releases/latest/download"

// BinPath is the installed binary location.
var BinPath = "/opt/rakhsh/rakhsh"

// Apply downloads, verifies and installs the binary for goarch on channel.
func Apply(channel, goarch string) (string, error) {
	if channel == "" {
		channel = "stable"
	}
	name := fmt.Sprintf("rakhsh_%s_linux_%s", channel, goarch)
	url := Base + "/" + name
	tmp := "/tmp/rakhsh.new"

	if _, err := sysutil.Run(120*time.Second, "curl", "-fsSL", url, "-o", tmp); err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	// verify against the published .sha256 (best effort; required if present)
	if sum, err := sysutil.Run(30*time.Second, "curl", "-fsSL", url+".sha256"); err == nil && sum != "" {
		got, err := fileSHA(tmp)
		if err != nil {
			return "", err
		}
		want := strings.Fields(sum)[0]
		if !strings.EqualFold(got, want) {
			_ = os.Remove(tmp)
			return "", fmt.Errorf("checksum mismatch (got %s want %s)", got[:12], want[:12])
		}
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	// smoke the new binary before committing
	if out, err := sysutil.Run(10*time.Second, tmp, "version"); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("new binary failed to run: %w", err)
	} else if !strings.HasPrefix(out, "rakhsh") {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("new binary gave unexpected version: %q", out)
	}
	bak := BinPath + ".bak"
	_ = os.Rename(BinPath, bak)
	if err := os.Rename(tmp, BinPath); err != nil {
		_ = os.Rename(bak, BinPath) // rollback
		return "", err
	}
	// restart and confirm the service comes back; else roll back.
	_, _ = sysutil.Run(20*time.Second, "systemctl", "restart", "rakhsh-panel.service")
	time.Sleep(3 * time.Second)
	if !sysutil.SystemdActive("rakhsh-panel.service") {
		_ = os.Rename(bak, BinPath)
		_, _ = sysutil.Run(20*time.Second, "systemctl", "restart", "rakhsh-panel.service")
		return "", fmt.Errorf("panel did not come up on the new binary — rolled back")
	}
	out, _ := sysutil.Run(5*time.Second, BinPath, "version")
	return strings.TrimSpace(out), nil
}

// Rollback restores the previous binary if a .bak exists.
func Rollback() error {
	bak := BinPath + ".bak"
	if _, err := os.Stat(bak); err != nil {
		return fmt.Errorf("no backup to roll back to")
	}
	if err := os.Rename(bak, BinPath); err != nil {
		return err
	}
	_, _ = sysutil.Run(20*time.Second, "systemctl", "restart", "rakhsh-panel.service")
	return nil
}

func fileSHA(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
