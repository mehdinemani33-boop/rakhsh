// Package license verifies Rakhsh Pro licenses offline with an Ed25519
// signature. The panel embeds only the public key, so a license cannot be
// forged without the issuer's private key — which lives only in the separate
// rakhsh-license issuer app. A license carries an expiry and a feature list;
// Pro features (cluster, DNS switching, the Xray/Backhaul/Bagher/Spoof engines,
// autopilot, benchmark) check it before they unlock.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// pubKeyB64 is the issuer's public key. The matching private seed is held only
// by the license issuer. Replace this to use your own key.
const pubKeyB64 = "UBoJnc5v9lXX41EvInW2Ut5To1FKitlJbYrSP/a0ZM8="

const prefix = "RKHL-"

// License is the signed payload.
type License struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`           // buyer / label
	Plan     string   `json:"plan,omitempty"` // free text, e.g. "pro", "1y"
	Expiry   int64    `json:"exp"`            // unix seconds; 0 = never expires
	Features []string `json:"feat"`           // feature names, or ["*"] for all
	Issued   int64    `json:"iss"`
}

func pub() ed25519.PublicKey {
	b, _ := base64.StdEncoding.DecodeString(pubKeyB64)
	return ed25519.PublicKey(b)
}

// Sign builds a license string from a 32-byte Ed25519 seed (base64) and a
// License. Used only by the issuer app.
func Sign(seedB64 string, lic License) (string, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedB64))
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", errors.New("bad private seed (need base64 of 32 bytes)")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	payload, err := json.Marshal(lic)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return prefix + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify checks the signature and expiry, returning the decoded License. On an
// expired-but-authentic license it returns the License together with an error.
func Verify(s string) (License, error) {
	var zero License
	s = strings.TrimSpace(s)
	if s == "" || !strings.HasPrefix(s, prefix) {
		return zero, errors.New("not a rakhsh license")
	}
	parts := strings.SplitN(strings.TrimPrefix(s, prefix), ".", 2)
	if len(parts) != 2 {
		return zero, errors.New("malformed license")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return zero, errors.New("bad payload encoding")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return zero, errors.New("bad signature encoding")
	}
	if !ed25519.Verify(pub(), payload, sig) {
		return zero, errors.New("invalid license signature")
	}
	var lic License
	if err := json.Unmarshal(payload, &lic); err != nil {
		return zero, errors.New("bad license payload")
	}
	if lic.Expiry != 0 && time.Now().Unix() > lic.Expiry {
		return lic, errors.New("license expired")
	}
	return lic, nil
}

// Valid reports whether s is an authentic, unexpired license.
func Valid(s string) bool {
	_, err := Verify(s)
	return err == nil
}

// Has reports whether an authentic license grants a feature (or "*").
func Has(s, feature string) bool {
	lic, err := Verify(s)
	if err != nil {
		return false
	}
	for _, f := range lic.Features {
		if f == "*" || f == feature {
			return true
		}
	}
	return false
}

// Status is a panel-friendly view of a stored license.
type Status struct {
	Valid    bool     `json:"valid"`
	Name     string   `json:"name,omitempty"`
	Plan     string   `json:"plan,omitempty"`
	Expiry   int64    `json:"expiry,omitempty"`
	Features []string `json:"features,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Describe returns a Status for the panel.
func Describe(s string) Status {
	if strings.TrimSpace(s) == "" {
		return Status{Valid: false}
	}
	lic, err := Verify(s)
	if err != nil {
		return Status{Valid: false, Name: lic.Name, Expiry: lic.Expiry, Error: err.Error()}
	}
	return Status{Valid: true, Name: lic.Name, Plan: lic.Plan, Expiry: lic.Expiry, Features: lic.Features}
}
