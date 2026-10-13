package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

var (
	ErrInvalidToken       = errors.New("invalid internal user token")
	ErrSigningUnavailable = errors.New("auth signing unavailable")
	ErrKeyOverlap         = errors.New("signing key overlap not complete")
)
var keyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var entityID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var zone = regexp.MustCompile(`^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$`)

type SigningKey struct {
	KID        string
	PrivateKey ed25519.PrivateKey
}
type PublishedKey struct {
	Key         SigningKey
	PublishedAt time.Time
}
type RetainedKey struct {
	Key         SigningKey
	RetainUntil time.Time
}
type Options struct {
	ActiveLastIssued time.Time
	Next             *PublishedKey
	Previous         *RetainedKey
	Clock            application.Clock
	IDs              application.IDGenerator
	Active           SigningKey
}
type signingState struct {
	key                                  SigningKey
	publishedAt, lastIssued, retainUntil time.Time
}
type Signer struct {
	mu             sync.Mutex
	clock          application.Clock
	ids            application.IDGenerator
	active         signingState
	next, previous *signingState
	lastClock      time.Time
	used           map[string]bool
}
type PublicKey struct {
	KTY       string `json:"kty"`
	Curve     string `json:"crv"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	KID       string `json:"kid"`
	X         string `json:"x"`
}
type JWKS struct {
	Keys []PublicKey `json:"keys"`
}
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KID       string `json:"kid"`
}
type UserClaims struct {
	Issuer          string          `json:"iss"`
	IssuedAt        int64           `json:"iat"`
	NotBefore       int64           `json:"nbf"`
	ExpiresAt       int64           `json:"exp"`
	TokenID         domain.EntityID `json:"jti"`
	Kind            string          `json:"kind"`
	AuthorizedParty string          `json:"azp"`
	application.UserToken
}

func copyKey(k SigningKey) (SigningKey, error) {
	if !keyID.MatchString(k.KID) || len(k.PrivateKey) != ed25519.PrivateKeySize {
		return SigningKey{}, ErrSigningUnavailable
	}
	expected := ed25519.NewKeyFromSeed(k.PrivateKey[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(expected, k.PrivateKey) != 1 {
		return SigningKey{}, ErrSigningUnavailable
	}
	return SigningKey{KID: k.KID, PrivateKey: slices.Clone(k.PrivateKey)}, nil
}
func validClock(at time.Time) bool { return !at.IsZero() && at.Unix() >= 0 && at.Year() <= 9999 }
func New(o Options) (*Signer, error) {
	if o.Clock == nil || o.IDs == nil {
		return nil, ErrSigningUnavailable
	}
	k, err := copyKey(o.Active)
	if err != nil {
		return nil, err
	}
	at := o.Clock.Now()
	if !validClock(at) {
		return nil, ErrSigningUnavailable
	}
	s := &Signer{clock: o.Clock, ids: o.IDs, active: signingState{key: k, publishedAt: at, lastIssued: o.ActiveLastIssued}, lastClock: at, used: map[string]bool{k.KID: true}}
	if !o.ActiveLastIssued.IsZero() && (!validClock(o.ActiveLastIssued) || o.ActiveLastIssued.After(at)) {
		return nil, ErrSigningUnavailable
	}
	if o.Next != nil {
		if !validClock(o.Next.PublishedAt) || o.Next.PublishedAt.After(at) || s.used[o.Next.Key.KID] {
			return nil, ErrSigningUnavailable
		}
		next, err := copyKey(o.Next.Key)
		if err != nil || subtle.ConstantTimeCompare(next.PrivateKey, k.PrivateKey) == 1 {
			return nil, ErrSigningUnavailable
		}
		s.next = &signingState{key: next, publishedAt: o.Next.PublishedAt}
		s.used[next.KID] = true
	}
	if o.Previous != nil {
		if !validClock(o.Previous.RetainUntil) || o.Previous.RetainUntil.After(at.Add(time.Minute)) || s.used[o.Previous.Key.KID] {
			return nil, ErrSigningUnavailable
		}
		previous, err := copyKey(o.Previous.Key)
		if err != nil || subtle.ConstantTimeCompare(previous.PrivateKey, k.PrivateKey) == 1 {
			return nil, ErrSigningUnavailable
		}
		if s.next != nil && subtle.ConstantTimeCompare(previous.PrivateKey, s.next.key.PrivateKey) == 1 {
			return nil, ErrSigningUnavailable
		}
		s.used[previous.KID] = true
		if at.Before(o.Previous.RetainUntil) {
			s.previous = &signingState{key: previous, retainUntil: o.Previous.RetainUntil}
		}
	}
	return s, nil
}
func (s *Signer) now() (time.Time, error) {
	at := s.clock.Now()
	if !validClock(at) || at.Before(s.lastClock) {
		return time.Time{}, ErrSigningUnavailable
	}
	s.lastClock = at
	if s.previous != nil && !at.Before(s.previous.retainUntil) {
		s.previous = nil
	}
	return at, nil
}
func (s *Signer) SignUser(ctx context.Context, d application.UserToken, at time.Time) (application.IssuedToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return application.IssuedToken{}, err
	}
	now, err := s.now()
	if err != nil || !validClock(at) || !validClock(at.Add(time.Minute)) || at.After(now) || !now.Before(time.Unix(at.Unix()+60, 0)) {
		return application.IssuedToken{}, ErrSigningUnavailable
	}
	if !validDecision(d) {
		return application.IssuedToken{}, ErrInvalidToken
	}
	id, err := s.ids.NewID()
	if err != nil || !entityID.MatchString(string(id)) {
		return application.IssuedToken{}, ErrSigningUnavailable
	}
	iat := at.Unix()
	claims := UserClaims{Issuer: "urn:umir:auth", IssuedAt: iat, NotBefore: iat, ExpiresAt: iat + 60, TokenID: id, Kind: "user", AuthorizedParty: "umir-gateway", UserToken: d}
	header, err := json.Marshal(Header{Algorithm: "EdDSA", Type: "JWT", KID: s.active.key.KID})
	if err != nil {
		return application.IssuedToken{}, ErrSigningUnavailable
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return application.IssuedToken{}, ErrSigningUnavailable
	}
	body := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(s.active.key.PrivateKey, []byte(body))
	if now.After(s.active.lastIssued) {
		s.active.lastIssued = now
	}
	return application.IssuedToken{Token: body + "." + base64.RawURLEncoding.EncodeToString(signature), ExpiresAt: time.Unix(iat+60, 0).In(at.Location())}, nil
}
func validDecision(d application.UserToken) bool {
	for _, id := range []domain.EntityID{d.UserID, d.SessionID, d.OrgID, d.TenantID} {
		if !entityID.MatchString(string(id)) {
			return false
		}
	}
	for _, v := range []domain.Version{d.SessionVersion, d.CredentialVersion, d.AccessVersion, d.SettingsVersion, d.LifecycleVersion} {
		if _, ok := domain.VersionNumber(v); !ok {
			return false
		}
	}
	if len(d.TimeZone) > 128 || d.TimeZone == "Local" || !zone.MatchString(d.TimeZone) {
		return false
	}
	p, ok := application.UserTokenPolicy(d.Operation)
	return ok && application.SameStringSet(d.Audiences, p.Audiences) && application.SameStringSet(d.Permissions, p.Permissions)
}
func (s *Signer) JWKS(ctx context.Context) (JWKS, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return JWKS{}, err
	}
	if _, err := s.now(); err != nil {
		return JWKS{}, err
	}
	keys := []PublicKey{public(s.active.key)}
	if s.next != nil {
		keys = append(keys, public(s.next.key))
	}
	if s.previous != nil {
		keys = append(keys, public(s.previous.key))
	}
	return JWKS{Keys: keys}, nil
}
func public(k SigningKey) PublicKey {
	return PublicKey{KTY: "OKP", Curve: "Ed25519", Algorithm: "EdDSA", Use: "sig", KID: k.KID, X: base64.RawURLEncoding.EncodeToString(k.PrivateKey[ed25519.SeedSize:])}
}
func (s *Signer) PublishNext(k SigningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, err := s.now()
	if err != nil {
		return err
	}
	if s.next != nil || s.used[k.KID] {
		return ErrSigningUnavailable
	}
	next, err := copyKey(k)
	if err != nil {
		return err
	}
	for _, state := range []*signingState{&s.active, s.previous} {
		if state != nil && subtle.ConstantTimeCompare(next.PrivateKey, state.key.PrivateKey) == 1 {
			return ErrSigningUnavailable
		}
	}
	s.next = &signingState{key: next, publishedAt: now}
	s.used[next.KID] = true
	return nil
}
func (s *Signer) ActivateNext() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, err := s.now()
	if err != nil {
		return err
	}
	if s.next == nil {
		return ErrSigningUnavailable
	}
	if now.Before(s.next.publishedAt.Add(time.Minute)) || s.previous != nil {
		return ErrKeyOverlap
	}
	previous := s.active
	last := previous.lastIssued
	if last.IsZero() {
		last = now
	}
	previous.retainUntil = last.Add(time.Minute)
	s.previous = &previous
	s.active = *s.next
	s.next = nil
	return nil
}

type KeyState struct {
	Active             SigningKey
	ActiveLastIssued   time.Time
	Next               *PublishedKey
	Previous           *RetainedKey
	PreviousLastIssued time.Time
}

func (s *Signer) Snapshot(ctx context.Context) (KeyState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return KeyState{}, err
	}
	if _, err := s.now(); err != nil {
		return KeyState{}, err
	}
	active, err := copyKey(s.active.key)
	if err != nil {
		return KeyState{}, err
	}
	out := KeyState{Active: active, ActiveLastIssued: s.active.lastIssued}
	if s.next != nil {
		key, err := copyKey(s.next.key)
		if err != nil {
			return KeyState{}, err
		}
		out.Next = &PublishedKey{Key: key, PublishedAt: s.next.publishedAt}
	}
	if s.previous != nil {
		key, err := copyKey(s.previous.key)
		if err != nil {
			return KeyState{}, err
		}
		out.Previous = &RetainedKey{Key: key, RetainUntil: s.previous.retainUntil}
		out.PreviousLastIssued = s.previous.lastIssued
	}
	return out, nil
}
