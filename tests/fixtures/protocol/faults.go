package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type Faults struct {
	mu    sync.Mutex
	armed *armedFault
}
type armedFault struct {
	ID, Point, Operation, Command, State, Outcome string
	Until                                         time.Time
	Hits                                          int
}

func (f *Faults) Control(operation string, data []byte) (any, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var in struct {
		FaultID       string `json:"faultID"`
		Point         string `json:"point"`
		OperationID   string `json:"operationID"`
		CommandID     string `json:"commandID"`
		ExpireAfterMs int    `json:"expireAfterMs"`
	}
	if json.Unmarshal(data, &in) != nil {
		return nil, "InvalidRequest"
	}
	if f.armed != nil && f.armed.State == "armed" && !time.Now().Before(f.armed.Until) {
		f.armed.State = "expired"
	}
	if operation == "owner.fault.arm" {
		if !supportedFault(in.Point, in.OperationID) {
			return nil, "UnsupportedOperation"
		}
		if f.armed != nil && f.armed.State == "armed" {
			return nil, "FaultConflict"
		}
		f.armed = &armedFault{ID: in.FaultID, Point: in.Point, Operation: in.OperationID, Command: in.CommandID, State: "armed", Outcome: "not-observed", Until: time.Now().Add(time.Duration(in.ExpireAfterMs) * time.Millisecond)}
		return struct {
			FaultID string `json:"faultID"`
			State   string `json:"state"`
		}{in.FaultID, "armed"}, ""
	}
	if f.armed == nil || f.armed.ID != in.FaultID {
		return nil, "NotFound"
	}
	a := f.armed
	if operation == "owner.fault.clear" {
		a.State = "cleared"
		return struct {
			FaultID string `json:"faultID"`
			Cleared bool   `json:"cleared"`
		}{a.ID, true}, ""
	}
	return struct {
		FaultID string `json:"faultID"`
		State   string `json:"state"`
		Hits    int    `json:"hits"`
		Outcome string `json:"ownerOutcome"`
	}{a.ID, a.State, a.Hits, a.Outcome}, ""
}

type FaultRepository struct {
	Store  application.AggregateRepository
	Faults *Faults
}

func (s *FaultRepository) Load(ctx context.Context) (domain.ValidatedAggregate, error) {
	return s.Store.Load(ctx)
}
func (s *FaultRepository) Commit(ctx context.Context, v domain.Version, a domain.ValidatedAggregate) (application.CommitResult, error) {
	fault := s.Faults.take(ctx)
	if fault == nil {
		return s.Store.Commit(ctx, v, a)
	}
	if fault.Point == "before-commit" {
		s.Faults.outcome(fault, "not_committed")
		return application.CommitResult{Outcome: application.NotCommitted, AggregateRevision: v}, application.ErrStorageUnavailable
	}
	result, e := s.Store.Commit(ctx, v, a)
	if e != nil || result.Outcome != application.Committed {
		outcome := "unknown"
		if result.Outcome == application.NotCommitted {
			outcome = "not_committed"
		}
		s.Faults.outcome(fault, outcome)
		return result, e
	}
	s.Faults.outcome(fault, "committed")
	if fault.Point == "after-real-commit-return-unknown" {
		return application.CommitResult{Outcome: application.Unknown, AggregateRevision: result.AggregateRevision}, application.ErrRecoveryRequired
	}
	if selected, ok := ctx.Value(selectionKey{}).(*selectedCommand); ok {
		selected.Drop.Store(true)
	}
	return result, e
}

type selectedCommand struct {
	Operation, Command string
	Drop               atomic.Bool
}
type selectionKey struct{}

func WithCommand(ctx context.Context, operation, command string) context.Context {
	return context.WithValue(ctx, selectionKey{}, &selectedCommand{Operation: operation, Command: command})
}
func (f *Faults) take(ctx context.Context) *armedFault {
	selected, ok := ctx.Value(selectionKey{}).(*selectedCommand)
	if !ok {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.armed
	if a == nil || a.State != "armed" || a.Operation != selected.Operation || a.Command != selected.Command {
		return nil
	}
	if !time.Now().Before(a.Until) {
		a.State = "expired"
		return nil
	}
	a.State = "hit"
	a.Hits = 1
	return a
}
func (f *Faults) outcome(a *armedFault, outcome string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a.Outcome = outcome
}
func (f *Faults) WrapHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if e != nil || len(body) > 1<<20 {
			w.WriteHeader(400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var in struct {
			CommandID string `json:"commandID"`
		}
		if json.Unmarshal(body, &in) != nil || in.CommandID == "" {
			next.ServeHTTP(w, r)
			return
		}
		op := facadeOperation(r.Method, r.URL.Path)
		if op == "" {
			next.ServeHTTP(w, r)
			return
		}
		ctx := WithCommand(r.Context(), op, in.CommandID)
		selected, ok := ctx.Value(selectionKey{}).(*selectedCommand)
		if !ok {
			w.WriteHeader(503)
			return
		}
		capture := httptest.NewRecorder()
		next.ServeHTTP(capture, r.WithContext(ctx))
		if selected.Drop.Load() {
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, e := hj.Hijack()
				if e == nil {
					if e = conn.Close(); e != nil {
						return
					}
					return
				}
			}
			w.WriteHeader(503)
			return
		}
		for k, v := range capture.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(capture.Code)
		if _, e = w.Write(capture.Body.Bytes()); e != nil {
			return
		}
	})
}

type faultRoute struct{ Method, Path, Operation string }

var faultRoutes = []faultRoute{
	{"POST", "/internal/auth/v1/public/session", "login"},
	{"POST", "/internal/auth/v1/public/sessions/logout-all", "logoutAll"},
	{"PATCH", "/internal/auth/v1/public/me/display-name", "displayName"},
	{"PATCH", "/internal/auth/v1/public/me/password", "password"},
	{"POST", "/internal/auth/v1/public/orgs", "createOrganization"},
	{"DELETE", "/internal/auth/v1/public/orgs/{orgID}", "deleteOrganization"},
	{"PATCH", "/internal/auth/v1/public/orgs/{orgID}/settings", "updateSettings"},
	{"POST", "/internal/auth/v1/public/orgs/{orgID}/restaurants", "createRestaurant"},
	{"DELETE", "/internal/auth/v1/public/orgs/{orgID}/restaurants/{restaurantID}", "deleteRestaurant"},
	{"PUT", "/internal/auth/v1/public/orgs/{orgID}/memberships/{membershipID}", "updateMembership"},
	{"DELETE", "/internal/auth/v1/public/orgs/{orgID}/memberships/{membershipID}", "revokeMembership"},
	{"DELETE", "/internal/auth/v1/public/orgs/{orgID}/memberships/{membershipID}/assignments/{assignmentID}", "revokeAssignment"},
	{"POST", "/internal/auth/v1/public/orgs/{orgID}/invitations", "createInvitation"},
	{"POST", "/internal/auth/v1/public/orgs/{orgID}/invitations/{invitationID}/resend", "resendInvitation"},
	{"DELETE", "/internal/auth/v1/public/orgs/{orgID}/invitations/{invitationID}", "cancelInvitation"},
	{"POST", "/internal/auth/v1/public/invitations/{invitationID}/challenges", "beginInvitationChallenge"},
	{"POST", "/internal/auth/v1/public/challenges/{challengeID}/resend", "resendChallenge"},
	{"POST", "/internal/auth/v1/public/challenges/{challengeID}/verify", "verifyChallenge"},
	{"POST", "/internal/auth/v1/public/challenges/{challengeID}/complete", "completeInvitedUser"},
	{"POST", "/internal/auth/v1/public/invitations/{invitationID}/accept", "acceptInvitation"},
	{"POST", "/internal/auth/v1/public/email-challenges", "beginEmailChallenge"},
	{"POST", "/internal/auth/v1/public/email-challenges/{challengeID}/complete", "completeEmailChallenge"},
}

func supportedFault(point, operation string) bool {
	switch point {
	case "before-commit", "after-real-commit-return-unknown", "after-durable-before-reply":
	default:
		return false
	}
	for _, route := range faultRoutes {
		if route.Operation == operation {
			return true
		}
	}
	return false
}

func facadeOperation(method, path string) string {
	segments := strings.Split(path, "/")
	for _, route := range faultRoutes {
		if method != route.Method {
			continue
		}
		expected := strings.Split(route.Path, "/")
		if len(segments) != len(expected) {
			continue
		}
		matches := true
		for i, part := range expected {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				if segments[i] == "" {
					matches = false
					break
				}
			} else if part != segments[i] {
				matches = false
				break
			}
		}
		if matches {
			return route.Operation
		}
	}
	return ""
}
