package panel

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters — deliberately generous; a panel login is rare.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword returns an encoded argon2id hash.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$%d$%d$%d$%s$%s", argonTime, argonMemory, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks pw against an encoded hash in constant time.
func VerifyPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "argon2id" {
		return false
	}
	var t, mem uint32
	var th uint8
	fmt.Sscanf(parts[1], "%d", &t)
	fmt.Sscanf(parts[2], "%d", &mem)
	fmt.Sscanf(parts[3], "%d", &th)
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, mem, th, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// sessions is a tiny in-memory session table with expiry.
type sessions struct {
	mu   sync.Mutex
	data map[string]session
}

type session struct {
	user    string
	csrf    string
	expires time.Time
}

func newSessions() *sessions { return &sessions{data: map[string]session{}} }

func (s *sessions) create(user string) (sid, csrf string) {
	sid, csrf = randToken(24), randToken(24)
	s.mu.Lock()
	s.data[sid] = session{user: user, csrf: csrf, expires: time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	return
}

func (s *sessions) get(sid string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[sid]
	if !ok || time.Now().After(v.expires) {
		delete(s.data, sid)
		return session{}, false
	}
	return v, true
}

func (s *sessions) drop(sid string) {
	s.mu.Lock()
	delete(s.data, sid)
	s.mu.Unlock()
}
