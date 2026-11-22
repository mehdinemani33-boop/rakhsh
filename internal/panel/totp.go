package panel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// NewTOTPSecret returns a fresh base32 secret for an authenticator app.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
}

// TOTPURI builds the otpauth:// URI for a QR code.
func TOTPURI(secret, account string) string {
	return fmt.Sprintf("otpauth://totp/Rakhsh:%s?secret=%s&issuer=Rakhsh&period=30&digits=6", account, secret)
}

// totpAt computes the 6-digit code for a counter.
func totpAt(secret string, counter uint64) string {
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(pad(secret)))
	if err != nil {
		return ""
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1_000_000)
}

func pad(s string) string {
	if m := len(s) % 8; m != 0 {
		s += strings.Repeat("=", 8-m)
	}
	return s
}

// verifyTOTP checks code against secret with a ±1 step window.
// When secret is empty, 2FA is off and any code passes.
func verifyTOTP(secret, code string) bool {
	if secret == "" {
		return true
	}
	code = strings.TrimSpace(code)
	step := uint64(time.Now().Unix() / 30)
	for _, d := range []uint64{step - 1, step, step + 1} {
		if hmac.Equal([]byte(totpAt(secret, d)), []byte(code)) {
			return true
		}
	}
	return false
}
