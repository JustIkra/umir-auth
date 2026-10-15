package application

import (
	"context"
	"errors"
	"time"

	"github.com/JustIkra/umir-auth/internal/domain"
)

type ServiceDecision struct {
	Subject          string          `json:"sub"`
	OrgID            domain.EntityID `json:"org_id"`
	TenantID         domain.EntityID `json:"tenant_id"`
	RuntimeEpoch     domain.EntityID `json:"runtime_epoch"`
	LifecycleVersion domain.Version  `json:"lifecycle_version"`
	AuthorizedParty  string          `json:"azp"`
	Operation        string          `json:"operation"`
	Audiences        []string        `json:"aud"`
	Permissions      []string        `json:"permissions"`
}
type SystemIssuer interface {
	SignService(context.Context, ServiceDecision, time.Time) (IssuedToken, error)
	SignAnonymous(context.Context, time.Time) (IssuedToken, error)
}

func (s *Accounts) ServiceToken(ctx context.Context, caller, service string, id, epoch domain.EntityID, operation string) (IssuedToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	issuer, ok := s.opts.Issuer.(SystemIssuer)
	if !ok {
		return IssuedToken{}, ErrAuthUnavailable
	}
	if !runtimeID.MatchString(string(epoch)) {
		return IssuedToken{}, ErrForbidden
	}
	for {
		if err := ctx.Err(); err != nil {
			return IssuedToken{}, err
		}
		a, e := s.load(ctx)
		if e != nil {
			return IssuedToken{}, e
		}
		r, ok := findRestaurant(a, id)
		if !ok {
			return IssuedToken{}, ErrForbidden
		}
		party, subject := "umir-auth", "service:auth"
		switch {
		case caller == "gateway" && service == "warehouse" && operation == "expiry.due":
			statuses, err := s.runtimeAccess(ctx, a, id)
			if errors.Is(err, ErrRevisionConflict) {
				continue
			}
			if err != nil {
				return IssuedToken{}, err
			}
			party, subject = "umir-gateway", "service:gateway"
			st, ok := statuses[service]
			if !ok || st.Epoch != epoch {
				return IssuedToken{}, ErrRuntimeNotReady
			}
		case caller == "auth" && (service == "warehouse" || service == "serving" || service == "gateway") && (operation == "runtime.register" || operation == "runtime.close"):
			if operation == "runtime.close" && r.Lifecycle != "deleting" && r.Lifecycle != "deleted" || operation == "runtime.register" && (r.Lifecycle == "deleted" || r.Lifecycle == "deleting") {
				return IssuedToken{}, ErrForbidden
			}
		default:
			return IssuedToken{}, ErrForbidden
		}
		return issuer.SignService(ctx, ServiceDecision{Subject: subject, OrgID: r.OrgID, TenantID: id, RuntimeEpoch: epoch, LifecycleVersion: r.LifecycleVersion, AuthorizedParty: party, Operation: operation, Audiences: []string{"umir-" + service}, Permissions: []string{operation}}, s.opts.Clock.Now())
	}
}
func (s *Accounts) AnonymousToken(ctx context.Context) (IssuedToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, e := s.load(ctx); e != nil {
		return IssuedToken{}, e
	}
	issuer, ok := s.opts.Issuer.(SystemIssuer)
	if !ok {
		return IssuedToken{}, ErrAuthUnavailable
	}
	return issuer.SignAnonymous(ctx, s.opts.Clock.Now())
}
