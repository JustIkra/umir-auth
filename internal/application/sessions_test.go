package application

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestEvictionUsesInstantsAndStableTies(t *testing.T) {
	a := domain.Empty()
	id := domain.EntityID("00000001-1111-4111-8111-111111111111")
	a.Sessions = []domain.Session{{UserID: id, SessionID: "00000002-1111-4111-8111-111111111111", CreatedAt: "2026-10-13T01:00:00+03:00"}, {UserID: id, SessionID: "00000003-1111-4111-8111-111111111111", CreatedAt: "2026-10-12T23:00:00Z"}}
	evictSessions(&a, id, 1)
	if !a.Sessions[0].Revoked || a.Sessions[1].Revoked {
		t.Fatal("oldest by instant was not evicted")
	}
}
func TestVerificationGateQueueAndCancellation(t *testing.T) {
	g := newVerificationGate(2, 8)
	ctx := context.Background()
	r1, err := g.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := g.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	g.waitingLogins = 8
	g.mu.Unlock()
	if _, err := g.acquire(ctx, true); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatal("unbounded login queue")
	}
	g.mu.Lock()
	g.waitingLogins = 0
	g.mu.Unlock()
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := g.acquire(c, true); !errors.Is(err, context.Canceled) {
		t.Fatal("queue cancellation lost")
	}
	r1()
	r2()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.waitingLogins != 0 {
		t.Fatal("queue waiter leaked")
	}
}
func TestRateLimitRollingBoundary(t *testing.T) {
	now := time.Date(2026, 10, 13, 1, 0, 0, 0, time.FixedZone("Europe/Moscow", 3*3600))
	th := failureThrottle{}
	for range 4 {
		if th.fail(now, 5, time.Minute, time.Minute) {
			t.Fatal("early cooldown")
		}
	}
	if th.fail(now.Add(time.Minute), 5, time.Minute, time.Minute) {
		t.Fatal("boundary stale failures kept")
	}
	for range 4 {
		th.fail(now.Add(time.Minute), 5, time.Minute, time.Minute)
	}
	if th.wait(now.Add(time.Minute)) != time.Minute || th.wait(now.Add(2*time.Minute)) != 0 {
		t.Fatal("cooldown duration changed")
	}
}
func TestLegacyRollbackRejectsCredentialsAndDeadlines(t *testing.T) {
	data, err := os.ReadFile("../../tests/testdata/aggregate.json")
	if err != nil {
		t.Fatal(err)
	}
	var a domain.Aggregate
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	original, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*domain.Aggregate){func(a *domain.Aggregate) { a.Users[0].CredentialVersion = "2" }, func(a *domain.Aggregate) { a.Sessions[0].IdleExpiresAt = "2026-10-13T01:31:00+03:00" }, func(a *domain.Aggregate) { a.Sessions[0].Revoked = true }} {
		next := original.Snapshot()
		change(&next)
		current, err := domain.Validate(next)
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(GuardRollback(original, current), ErrUnsafeRollback) {
			t.Fatal("rollback discarded auth changes")
		}
	}
}
func TestCredentialRollbackCannotRestoreOldVerifier(t *testing.T) {
	data, err := os.ReadFile("../../tests/testdata/aggregate.json")
	if err != nil {
		t.Fatal(err)
	}
	var a domain.Aggregate
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	a.Users[0].CredentialVersion = "2"
	original, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	next := a
	next.Users = append([]domain.User(nil), a.Users...)
	next.Users[0].CredentialVersion = "1"
	validated, err := domain.Validate(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := domain.ValidateReplacement(original, validated); err == nil {
		t.Fatal("credential version rollback accepted")
	}
}
