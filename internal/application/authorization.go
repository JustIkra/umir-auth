package application

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/JustIkra/umir-auth/internal/domain"
)

type UserToken struct {
	UserID            domain.EntityID `json:"sub"`
	SessionID         domain.EntityID `json:"sid"`
	SessionVersion    domain.Version  `json:"session_version"`
	CredentialVersion domain.Version  `json:"credential_version"`
	AccessVersion     domain.Version  `json:"access_version"`
	OrgID             domain.EntityID `json:"org_id"`
	TenantID          domain.EntityID `json:"tenant_id"`
	TimeZone          string          `json:"time_zone"`
	SettingsVersion   domain.Version  `json:"settings_version"`
	LifecycleVersion  domain.Version  `json:"lifecycle_version"`
	Operation         string          `json:"operation"`
	Audiences         []string        `json:"aud"`
	Permissions       []string        `json:"permissions"`
}
type IssuedToken struct {
	Token     string
	ExpiresAt time.Time
}
type UserTokenIssuer interface {
	SignUser(context.Context, UserToken, time.Time) (IssuedToken, error)
}
type AuthorizationInput struct {
	SessionToken string          `json:"sessionToken"`
	RestaurantID domain.EntityID `json:"restaurantID"`
	Operation    string          `json:"operation"`
	Audiences    []string        `json:"audiences"`
	Activity     string          `json:"activity"`
}
type SessionDeadlines struct {
	ExpiresAt         domain.Instant `json:"expiresAt"`
	IdleExpiresAt     domain.Instant `json:"idleExpiresAt"`
	AbsoluteExpiresAt domain.Instant `json:"absoluteExpiresAt"`
	RememberMe        bool           `json:"rememberMe"`
	CSRFToken         string         `json:"csrfToken"`
}
type AuthorizationResult struct {
	UserID            domain.EntityID  `json:"userID"`
	SessionID         domain.EntityID  `json:"sessionID"`
	SessionVersion    domain.Version   `json:"sessionVersion"`
	CredentialVersion domain.Version   `json:"credentialVersion"`
	AccessVersion     domain.Version   `json:"accessVersion"`
	OrgID             domain.EntityID  `json:"orgID"`
	TenantID          domain.EntityID  `json:"tenantID"`
	Permissions       []string         `json:"permissions"`
	Settings          domain.Settings  `json:"settings"`
	LifecycleVersion  domain.Version   `json:"lifecycleVersion"`
	Token             string           `json:"token"`
	ExpiresAt         domain.Instant   `json:"expiresAt"`
	Session           SessionDeadlines `json:"session"`
}
type TokenPolicy struct {
	Capability             string
	Audiences, Permissions []string
}

func UserTokenPolicy(operation string) (TokenPolicy, bool) {
	var capability string
	var audiences, extra []string
	switch operation {
	case "products", "dishCatalog", "dishDetails":
		capability = "catalog.read"
	case "registerProduct", "defineDish", "suggestID":
		capability = "catalog.write"
	case "receiveDelivery":
		capability = "delivery.create"
	case "inventory", "expiringBatches", "history", "pendingWriteoffs", "productBatches", "supplySuggestions":
		capability = "stock.read"
	case "confirmWriteoff", "resolveWriteoffCommand":
		capability = "writeoff.confirm"
	case "analyticsstock", "analyticsmovements", "orgSummary":
		capability = "analytics.read"
		if operation == "orgSummary" {
			capability = "org.summary.read"
		}
	case "menu", "stopList":
		capability = "menu.read"
		extra = []string{"consumer.menu.evaluate"}
	case "recommendations":
		capability = "recommendations.read"
		extra = []string{"consumer.recommendations.read"}
	case "servingProducts", "servingDishes", "servingDish":
		capability = "menu.read"
		extra = []string{"catalog.read"}
	case "prepareOrder":
		capability = "order.prepare"
		extra = []string{"consumer.order.evaluate"}
	case "confirmOrder":
		capability = "order.confirm"
		extra = []string{"consumer.order.evaluate", "consumer.order.commit", "consumer.order.resolve"}
	case "resolveOrder":
		capability = "order.read"
		extra = []string{"consumer.order.resolve"}
	case "appFeedback":
		capability = "feedback.submit"
		audiences = []string{"umir-feedback"}
	case "publicFeedbackRead":
		capability = "feedback.read"
		audiences = []string{"umir-feedback"}
	case "publicFeedbackExport":
		capability = "feedback.export"
		audiences = []string{"umir-feedback"}
	default:
		return TokenPolicy{}, false
	}
	if len(extra) > 0 {
		audiences = []string{"umir-serving", "umir-warehouse"}
	} else if audiences == nil {
		audiences = []string{"umir-warehouse"}
	}
	return TokenPolicy{Capability: capability, Audiences: audiences, Permissions: append([]string{capability}, extra...)}, true
}
func SameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if !slices.Contains(b, v) || slices.Contains(a[:i], v) {
			return false
		}
	}
	return true
}
func (s *Accounts) AuthorizeToken(ctx context.Context, in AuthorizationInput) (AuthorizationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, ok := UserTokenPolicy(in.Operation)
	if !ok || !SameStringSet(in.Audiences, policy.Audiences) || in.Activity != "foreground" && in.Activity != "background" {
		return AuthorizationResult{}, ErrForbidden
	}
	var observed map[string]RuntimeStatus
	for {
		if err := ctx.Err(); err != nil {
			return AuthorizationResult{}, err
		}
		a, err := s.load(ctx)
		if err != nil {
			return AuthorizationResult{}, err
		}
		now := s.opts.Clock.Now()
		u, _, err := active(a, in.SessionToken, now)
		if err != nil {
			return AuthorizationResult{}, err
		}
		access, err := domain.RestaurantPermissions(a, u.UserID, in.RestaurantID)
		if err != nil || !slices.Contains(access.Permissions, policy.Capability) {
			return AuthorizationResult{}, ErrForbidden
		}
		if _, err := s.runtimeAccess(ctx, a, in.RestaurantID, &observed); err != nil {
			if errors.Is(err, ErrRevisionConflict) {
				continue
			}
			return AuthorizationResult{}, err
		}
		now = s.opts.Clock.Now()
		u, i, err := active(a, in.SessionToken, now)
		if err != nil {
			return AuthorizationResult{}, err
		}
		if err := s.validateZone(access.Settings.TimeZone); err != nil {
			return AuthorizationResult{}, err
		}
		if s.opts.Issuer == nil {
			return AuthorizationResult{}, ErrAuthUnavailable
		}
		var version domain.Version
		for _, m := range a.Memberships {
			if m.UserID == u.UserID && m.OrgID == access.OrgID && m.State == "active" {
				version = m.MembershipVersion
				break
			}
		}
		st := a.Sessions[i]
		if in.Activity == "foreground" && !st.RememberMe {
			idle, err := time.Parse(time.RFC3339Nano, string(st.IdleExpiresAt))
			if err != nil {
				return AuthorizationResult{}, ErrAuthUnavailable
			}
			absolute, err := time.Parse(time.RFC3339Nano, string(st.AbsoluteExpiresAt))
			if err != nil {
				return AuthorizationResult{}, ErrAuthUnavailable
			}
			next := now.Add(30 * time.Minute)
			if next.After(absolute) {
				next = absolute
			}
			if next.After(idle) {
				st.IdleExpiresAt = formatInstant(next)
				st.SessionVersion, err = nextVersion(st.SessionVersion)
				if err != nil {
					return AuthorizationResult{}, err
				}
				a.Sessions[i] = st
				if err := s.commit(ctx, a); err != nil {
					if errors.Is(err, ErrRevisionConflict) {
						continue
					}
					return AuthorizationResult{}, err
				}
			}
		}
		claims := UserToken{UserID: u.UserID, SessionID: st.SessionID, SessionVersion: st.SessionVersion, CredentialVersion: u.CredentialVersion, AccessVersion: version, OrgID: access.OrgID, TenantID: access.RestaurantID, TimeZone: access.Settings.TimeZone, SettingsVersion: access.Settings.SettingsVersion, LifecycleVersion: access.LifecycleVersion, Operation: in.Operation, Audiences: slices.Clone(policy.Audiences), Permissions: slices.Clone(policy.Permissions)}
		issued, err := s.opts.Issuer.SignUser(ctx, claims, now)
		if err != nil {
			return AuthorizationResult{}, errors.Join(ErrAuthUnavailable, err)
		}
		return AuthorizationResult{UserID: u.UserID, SessionID: st.SessionID, SessionVersion: st.SessionVersion, CredentialVersion: u.CredentialVersion, AccessVersion: version, OrgID: access.OrgID, TenantID: access.RestaurantID, Permissions: policy.Permissions, Settings: access.Settings, LifecycleVersion: access.LifecycleVersion, Token: issued.Token, ExpiresAt: formatInstant(issued.ExpiresAt), Session: SessionDeadlines{ExpiresAt: st.IdleExpiresAt, IdleExpiresAt: st.IdleExpiresAt, AbsoluteExpiresAt: st.AbsoluteExpiresAt, RememberMe: st.RememberMe, CSRFToken: sessionCSRF(in.SessionToken)}}, nil
	}
}
