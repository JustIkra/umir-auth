package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
)

type Preauth struct {
	mu     sync.Mutex
	key    []byte
	clock  application.Clock
	issued map[string]time.Time
}
type PreauthIssued struct {
	CSRFToken    string `json:"csrfToken"`
	PreauthToken string `json:"preauthToken"`
	ExpiresAt    string `json:"expiresAt"`
}

func NewPreauth(key []byte, clock application.Clock) (*Preauth, error) {
	if len(key) != 32 || clock == nil {
		return nil, application.ErrAuthUnavailable
	}
	return &Preauth{key: append([]byte(nil), key...), clock: clock, issued: map[string]time.Time{}}, nil
}
func (p *Preauth) mac(body string) string {
	h := hmac.New(sha256.New, p.key)
	if _, e := h.Write([]byte("preauth-v1:" + body)); e != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func (p *Preauth) Issue(existing string) (PreauthIssued, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if csrf, until, ok := p.validate(existing); ok {
		return PreauthIssued{csrf, existing, until.Format(time.RFC3339Nano)}, nil
	}
	now := p.clock.Now()
	for k, v := range p.issued {
		if !now.Before(v) {
			delete(p.issued, k)
		}
	}
	if len(p.issued) >= 1024 {
		return PreauthIssued{}, application.ErrAuthUnavailable
	}
	var random [32]byte
	if _, e := rand.Read(random[:]); e != nil {
		return PreauthIssued{}, application.ErrAuthUnavailable
	}
	until := now.Add(30 * time.Minute)
	body := strconv.FormatInt(now.Unix(), 10) + "." + hex.EncodeToString(random[:])
	token := body + "." + p.mac(body)
	p.issued[application.TokenDigest(token)] = until
	return PreauthIssued{p.mac("csrf:" + token), token, until.Format(time.RFC3339Nano)}, nil
}
func (p *Preauth) validate(token string) (string, time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[1]) != 64 {
		return "", time.Time{}, false
	}
	body := parts[0] + "." + parts[1]
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(p.mac(body))) != 1 {
		return "", time.Time{}, false
	}
	at, e := strconv.ParseInt(parts[0], 10, 64)
	now := p.clock.Now()
	start := time.Unix(at, 0)
	until := start.Add(30 * time.Minute)
	if e != nil || start.After(now) || !now.Before(until) {
		return "", time.Time{}, false
	}
	return p.mac("csrf:" + token), until, true
}
func (p *Preauth) Verify(token, csrf string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	expected, _, ok := p.validate(token)
	if !ok || csrf == "" || !hmac.Equal([]byte(csrf), []byte(expected)) {
		return application.ErrInvalidCSRFToken
	}
	return nil
}
