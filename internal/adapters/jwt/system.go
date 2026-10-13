package jwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type systemClaims struct {
	Issuer           string          `json:"iss"`
	IssuedAt         int64           `json:"iat"`
	NotBefore        int64           `json:"nbf"`
	ExpiresAt        int64           `json:"exp"`
	TokenID          domain.EntityID `json:"jti"`
	Kind             string          `json:"kind"`
	Subject          string          `json:"sub"`
	AuthorizedParty  string          `json:"azp"`
	Operation        string          `json:"operation"`
	Audiences        []string        `json:"aud"`
	Permissions      []string        `json:"permissions"`
	OrgID            domain.EntityID `json:"org_id,omitempty"`
	TenantID         domain.EntityID `json:"tenant_id,omitempty"`
	RuntimeEpoch     domain.EntityID `json:"runtime_epoch,omitempty"`
	LifecycleVersion domain.Version  `json:"lifecycle_version,omitempty"`
}

func (s *Signer) SignService(ctx context.Context, d application.ServiceDecision, at time.Time) (application.IssuedToken, error) {
	if !entityID.MatchString(string(d.OrgID)) || !entityID.MatchString(string(d.TenantID)) || !entityID.MatchString(string(d.RuntimeEpoch)) || len(d.Audiences) != 1 || !application.SameStringSet(d.Permissions, []string{d.Operation}) {
		return application.IssuedToken{}, ErrInvalidToken
	}
	if _, ok := domain.VersionNumber(d.LifecycleVersion); !ok {
		return application.IssuedToken{}, ErrInvalidToken
	}
	if d.Subject == "service:gateway" {
		if d.AuthorizedParty != "umir-gateway" || d.Operation != "expiry.due" || d.Audiences[0] != "umir-warehouse" {
			return application.IssuedToken{}, ErrInvalidToken
		}
	} else if d.Subject != "service:auth" || d.AuthorizedParty != "umir-auth" || (d.Operation != "runtime.register" && d.Operation != "runtime.close") || (d.Audiences[0] != "umir-warehouse" && d.Audiences[0] != "umir-serving" && d.Audiences[0] != "umir-gateway") {
		return application.IssuedToken{}, ErrInvalidToken
	}
	return s.signSystem(ctx, at, systemClaims{Kind: "service", Subject: d.Subject, AuthorizedParty: d.AuthorizedParty, Operation: d.Operation, Audiences: d.Audiences, Permissions: d.Permissions, OrgID: d.OrgID, TenantID: d.TenantID, RuntimeEpoch: d.RuntimeEpoch, LifecycleVersion: d.LifecycleVersion})
}
func (s *Signer) SignAnonymous(ctx context.Context, at time.Time) (application.IssuedToken, error) {
	return s.signSystem(ctx, at, systemClaims{Kind: "anonymous", Subject: "service:gateway", AuthorizedParty: "umir-gateway", Operation: "feedback.anonymous.submit", Audiences: []string{"umir-feedback"}, Permissions: []string{"feedback.anonymous.submit"}})
}
func (s *Signer) signSystem(ctx context.Context, at time.Time, c systemClaims) (application.IssuedToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return application.IssuedToken{}, e
	}
	now, e := s.now()
	if e != nil || !validClock(at) || at.After(now) || !now.Before(time.Unix(at.Unix()+60, 0)) {
		return application.IssuedToken{}, ErrSigningUnavailable
	}
	id, e := s.ids.NewID()
	if e != nil || !entityID.MatchString(string(id)) {
		return application.IssuedToken{}, ErrSigningUnavailable
	}
	c.Issuer = "urn:umir:auth"
	c.IssuedAt = at.Unix()
	c.NotBefore = c.IssuedAt
	c.ExpiresAt = c.IssuedAt + 60
	c.TokenID = id
	header, e := json.Marshal(Header{Algorithm: "EdDSA", Type: "JWT", KID: s.active.key.KID})
	if e != nil {
		return application.IssuedToken{}, ErrSigningUnavailable
	}
	payload, e := json.Marshal(c)
	if e != nil {
		return application.IssuedToken{}, ErrSigningUnavailable
	}
	body := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(s.active.key.PrivateKey, []byte(body))
	if now.After(s.active.lastIssued) {
		s.active.lastIssued = now
	}
	return application.IssuedToken{Token: body + "." + base64.RawURLEncoding.EncodeToString(sig), ExpiresAt: time.Unix(c.ExpiresAt, 0).In(at.Location())}, nil
}
