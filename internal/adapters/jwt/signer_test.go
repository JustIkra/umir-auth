package jwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

const id = domain.EntityID("11111111-1111-4111-8111-111111111111")

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *clock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.at = c.at.Add(d) }

type ids struct{}

func (ids) NewID() (domain.EntityID, error) { return id, nil }
func key(t *testing.T, kid string) jwt.SigningKey {
	t.Helper()
	_, p, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return jwt.SigningKey{KID: kid, PrivateKey: p}
}
func decision() application.UserToken {
	return application.UserToken{UserID: id, SessionID: id, SessionVersion: "1", CredentialVersion: "1", AccessVersion: "1", OrgID: id, TenantID: id, TimeZone: "Europe/Moscow", SettingsVersion: "1", LifecycleVersion: "1", Operation: "menu", Audiences: []string{"umir-serving", "umir-warehouse"}, Permissions: []string{"menu.read", "consumer.menu.evaluate"}}
}
func TestRealEd25519TokenWindowAndPublicDiscovery(t *testing.T) {
	c := &clock{at: time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))}
	k := key(t, "active")
	s, e := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: k})
	if e != nil {
		t.Fatal(e)
	}
	issued, e := s.SignUser(context.Background(), decision(), c.Now())
	if e != nil {
		t.Fatal(e)
	}
	jwks, e := s.JWKS(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	data, e := json.Marshal(jwks)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(data), base64.RawURLEncoding.EncodeToString(k.PrivateKey)) || strings.Contains(string(data), `"d"`) {
		t.Fatal("private key exported")
	}
	parts := strings.Split(issued.Token, ".")
	pub, e := base64.RawURLEncoding.DecodeString(jwks.Keys[0].X)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		t.Fatal(e)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("not a real signature")
	}
	claims, e := jwt.VerifyUser(issued.Token, jwks, c.Now(), "umir-serving")
	if e != nil {
		t.Fatal(e)
	}
	if claims.ExpiresAt-claims.IssuedAt != 60 || claims.NotBefore != claims.IssuedAt || claims.Issuer != "urn:umir:auth" || claims.AuthorizedParty != "umir-gateway" {
		t.Fatal("frozen claims mismatch")
	}
	if !issued.ExpiresAt.Equal(c.Now().Add(time.Minute)) {
		t.Fatal("expiry not injected owner time")
	}
	for _, at := range []time.Time{c.Now().Add(-time.Nanosecond), c.Now().Add(time.Minute)} {
		if _, e := jwt.VerifyUser(issued.Token, jwks, at, "umir-serving"); e == nil {
			t.Fatal("token accepted outside exact time window")
		}
	}
	if _, e := jwt.VerifyUser(issued.Token, jwks, c.Now(), "umir-feedback"); e == nil {
		t.Fatal("unintended consumer accepted")
	}
}
func TestSignerRejectsBroaderAuthorityAndInvalidKeys(t *testing.T) {
	c := &clock{at: time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))}
	s, e := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: key(t, "active")})
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*application.UserToken){func(d *application.UserToken) { d.Audiences = append(d.Audiences, "umir-gateway") }, func(d *application.UserToken) { d.Operation = "expiry.due" }, func(d *application.UserToken) { d.Permissions = append(d.Permissions, "writeoff.confirm") }, func(d *application.UserToken) { d.SessionVersion = "01" }, func(d *application.UserToken) { d.UserID = "service:auth" }, func(d *application.UserToken) { d.TimeZone = "Local" }} {
		d := decision()
		change(&d)
		if _, e := s.SignUser(context.Background(), d, c.Now()); e == nil {
			t.Fatal("invalid/wider user authority signed")
		}
	}
	bad := key(t, "bad")
	bad.PrivateKey[63] ^= 1
	if _, e := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: bad}); e == nil {
		t.Fatal("inconsistent private key accepted")
	}
	if _, e := jwt.New(jwt.Options{IDs: ids{}, Active: key(t, "active")}); e == nil {
		t.Fatal("host clock fallback")
	}
}
func TestJWTValidationRejectsAlgorithmAndShapeConfusion(t *testing.T) {
	c := &clock{at: time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))}
	k := key(t, "active")
	s, e := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: k})
	if e != nil {
		t.Fatal(e)
	}
	issued, e := s.SignUser(context.Background(), decision(), c.Now())
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.JWKS(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(issued.Token, ".")
	payload, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		t.Fatal(e)
	}
	for _, h := range []string{`{"alg":"none","typ":"JWT","kid":"active"}`, `{"alg":"HS256","typ":"JWT","kid":"active"}`, `{"alg":"EdDSA","alg":"EdDSA","typ":"JWT","kid":"active"}`, `{"alg":"EdDSA","typ":"JWT","kid":"active","jku":"https://invalid.invalid"}`, `{"Alg":"EdDSA","typ":"JWT","kid":"active"}`} {
		raw := base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + parts[1]
		raw += "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.PrivateKey, []byte(raw)))
		if _, e := jwt.VerifyUser(raw, j, c.Now(), "umir-serving"); e == nil {
			t.Fatal("forbidden header accepted")
		}
	}
	for _, p := range []string{strings.Replace(string(payload), `"kind":"user"`, `"kind":"user","kind":"user"`, 1), strings.TrimSuffix(string(payload), "}") + `,"roles":["Admin"]}`, strings.Replace(string(payload), `"sid":`, `"SID":`, 1), strings.Replace(string(payload), `"aud":["umir-serving","umir-warehouse"]`, `"aud":["umir-serving","umir-serving"]`, 1)} {
		raw := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(p))
		raw += "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.PrivateKey, []byte(raw)))
		if _, e := jwt.VerifyUser(raw, j, c.Now(), "umir-serving"); e == nil {
			t.Fatal("invalid claims accepted")
		}
	}
	if _, e := jwt.VerifyUser(strings.Repeat("x", 16385), j, c.Now(), "umir-serving"); e == nil {
		t.Fatal("unbounded token")
	}
}
func TestRotationPublishesBeforeSwitchAndRetainsUntilLastTokenExpires(t *testing.T) {
	c := &clock{at: time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))}
	s, e := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: key(t, "old")})
	if e != nil {
		t.Fatal(e)
	}
	if e := s.PublishNext(key(t, "new")); e != nil {
		t.Fatal(e)
	}
	if e := s.ActivateNext(); !errors.Is(e, jwt.ErrKeyOverlap) {
		t.Fatal("early key switch")
	}
	c.add(59 * time.Second)
	if e := s.ActivateNext(); e == nil {
		t.Fatal("early key switch at 59 seconds")
	}
	last, e := s.SignUser(context.Background(), decision(), c.Now())
	if e != nil {
		t.Fatal(e)
	}
	c.add(time.Second)
	if e := s.ActivateNext(); e != nil {
		t.Fatal(e)
	}
	j, e := s.JWKS(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e := jwt.VerifyUser(last.Token, j, c.Now(), "umir-serving"); e != nil {
		t.Fatal("old token lost during overlap")
	}
	next, e := s.SignUser(context.Background(), decision(), c.Now())
	if e != nil {
		t.Fatal(e)
	}
	if strings.Split(last.Token, ".")[0] == strings.Split(next.Token, ".")[0] {
		t.Fatal("new key not active")
	}
	c.add(59 * time.Second)
	j, e = s.JWKS(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for _, k := range j.Keys {
		if k.KID == "old" {
			t.Fatal("expired previous key retained")
		}
	}
}

func TestJWTRejectsNoncanonicalEncodingAndUnrepresentableExpiry(t *testing.T) {
	c := &clock{at: time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))}
	k := key(t, "active")
	s, e := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: k})
	if e != nil {
		t.Fatal(e)
	}
	issued, e := s.SignUser(context.Background(), decision(), c.Now())
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.JWKS(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(issued.Token, ".")
	raw := parts[0] + "\n." + parts[1]
	raw += "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.PrivateKey, []byte(raw)))
	if _, e := jwt.VerifyUser(raw, j, c.Now(), "umir-serving"); e == nil {
		t.Fatal("noncanonical JWT with whitespace accepted")
	}
	max := &clock{at: time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("Europe/Moscow", 10800))}
	maxSigner, e := jwt.New(jwt.Options{Clock: max, IDs: ids{}, Active: key(t, "last")})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := maxSigner.SignUser(context.Background(), decision(), max.Now()); e == nil {
		t.Fatal("unrepresentable expiry signed")
	}
}

func TestSignerRestoresPublishedAndRetainedKeysAcrossRestart(t *testing.T) {
	c := &clock{at: time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))}
	old, next := key(t, "old"), key(t, "next")
	s, e := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: old})
	if e != nil {
		t.Fatal(e)
	}
	published := c.Now()
	if e := s.PublishNext(next); e != nil {
		t.Fatal(e)
	}
	c.add(59 * time.Second)
	issued, e := s.SignUser(context.Background(), decision(), c.Now())
	if e != nil {
		t.Fatal(e)
	}
	c.add(time.Second)
	if e := s.ActivateNext(); e != nil {
		t.Fatal(e)
	}
	c.add(time.Second)
	last, e := s.SignUser(context.Background(), decision(), c.Now())
	if e != nil {
		t.Fatal(e)
	}
	restored, e := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: next, ActiveLastIssued: c.Now(), Previous: &jwt.RetainedKey{Key: old, RetainUntil: published.Add(119 * time.Second)}})
	if e != nil {
		t.Fatal(e)
	}
	j, e := restored.JWKS(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e := jwt.VerifyUser(last.Token, j, c.Now(), "umir-serving"); e != nil {
		t.Fatal("restart lost current key")
	}
	if _, e := jwt.VerifyUser(issued.Token, j, c.Now(), "umir-serving"); e != nil {
		t.Fatal("restart lost live previous token")
	}
	c.add(58 * time.Second)
	j, e = restored.JWKS(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e := jwt.VerifyUser(issued.Token, j, c.Now(), "umir-serving"); e == nil {
		t.Fatal("restart extended expired token")
	}
	c2 := &clock{at: published.Add(30 * time.Second)}
	beforeSwitch, e := jwt.New(jwt.Options{Clock: c2, IDs: ids{}, Active: old, Next: &jwt.PublishedKey{Key: next, PublishedAt: published}})
	if e != nil {
		t.Fatal(e)
	}
	if e := beforeSwitch.ActivateNext(); !errors.Is(e, jwt.ErrKeyOverlap) {
		t.Fatal("restart reset/removed prepublication barrier")
	}
	c2.add(30 * time.Second)
	if e := beforeSwitch.ActivateNext(); e != nil {
		t.Fatal(e)
	}
}
