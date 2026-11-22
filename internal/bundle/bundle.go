// Package bundle encodes a tunnel definition into a single copy-paste token
// (prefix "rkh1_") that you generate on the Iran edge and paste on the foreign
// server. It carries everything the peer needs to bring the same tunnel up
// from the other side, authenticated by an HMAC over the shared token so a
// mistyped bundle is rejected instead of half-built.
package bundle

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"rakhsh/internal/store"
)

const prefix = "rkh1_"

// Payload is the wire form carried by a bundle.
type Payload struct {
	Tunnel  store.Tunnel `json:"t"`
	EdgeIP  string       `json:"edge_ip"` // the Iran public IP the peer dials
	MAC     string       `json:"mac"`
}

func mac(token string, raw []byte) string {
	h := hmac.New(sha256.New, []byte("rakhsh/"+token))
	h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Encode produces the rkh1_ token for a tunnel as seen from the Iran edge.
func Encode(t store.Tunnel, edgeIP string) (string, error) {
	p := Payload{Tunnel: t, EdgeIP: edgeIP}
	// MAC is over the tunnel+edge with the MAC field blank.
	raw, err := json.Marshal(struct {
		Tunnel store.Tunnel `json:"t"`
		EdgeIP string       `json:"edge_ip"`
	}{t, edgeIP})
	if err != nil {
		return "", err
	}
	p.MAC = mac(t.Token, raw)
	full, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(full), nil
}

// Decode parses and verifies a bundle, returning the tunnel ready to bring up
// on the foreign side (peer/local IPs are flipped to this host's viewpoint).
func Decode(bundleStr string) (store.Tunnel, string, error) {
	var zero store.Tunnel
	bundleStr = strings.TrimSpace(bundleStr)
	if !strings.HasPrefix(bundleStr, prefix) {
		return zero, "", fmt.Errorf("not a rakhsh bundle")
	}
	full, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(bundleStr, prefix))
	if err != nil {
		return zero, "", fmt.Errorf("bad bundle encoding: %w", err)
	}
	var p Payload
	if err := json.Unmarshal(full, &p); err != nil {
		return zero, "", fmt.Errorf("bad bundle json: %w", err)
	}
	raw, _ := json.Marshal(struct {
		Tunnel store.Tunnel `json:"t"`
		EdgeIP string       `json:"edge_ip"`
	}{p.Tunnel, p.EdgeIP})
	if !hmac.Equal([]byte(p.MAC), []byte(mac(p.Tunnel.Token, raw))) {
		return zero, "", fmt.Errorf("bundle failed verification (mistyped or wrong token)")
	}
	// Flip viewpoint for the foreign side.
	t := p.Tunnel
	t.PeerIP = p.EdgeIP
	t.GRELocal, t.GREPeer = p.Tunnel.GREPeer, p.Tunnel.GRELocal
	return t, p.EdgeIP, nil
}
