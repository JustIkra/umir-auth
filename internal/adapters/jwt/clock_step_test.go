package jwt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
)

// The signer never trusts a clock that moved backwards (R12): issuing and key
// publication both refuse until the clock is back at the latest instant it has
// seen. There is no iat leeway either: a token is issued for exactly the decision
// instant and not before it. These tests record that behaviour; they passed before
// being written.
func TestClockStepBackwardRefusesIssuingAndDiscoveryUntilItCatchesUp(t *testing.T) {
	c := &clock{at: time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))}
	s, err := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: key(t, "active")})
	if err != nil {
		t.Fatal(err)
	}
	seen := c.Now()
	if _, err := s.SignUser(context.Background(), decision(), seen); err != nil {
		t.Fatal(err)
	}
	c.add(-time.Second)
	if _, err := s.SignUser(context.Background(), decision(), c.Now()); !errors.Is(err, jwt.ErrSigningUnavailable) {
		t.Fatalf("issuing after a step back = %v", err)
	}
	if _, err := s.JWKS(context.Background()); !errors.Is(err, jwt.ErrSigningUnavailable) {
		t.Fatalf("key discovery after a step back = %v", err)
	}
	c.add(time.Second)
	if _, err := s.JWKS(context.Background()); err != nil {
		t.Fatalf("discovery did not recover once the clock caught up: %v", err)
	}
	if _, err := s.SignUser(context.Background(), decision(), c.Now()); err != nil {
		t.Fatalf("issuing did not recover once the clock caught up: %v", err)
	}
}

func TestIssueInstantHasNoLeeway(t *testing.T) {
	c := &clock{at: time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))}
	s, err := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: key(t, "active")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignUser(context.Background(), decision(), c.Now().Add(time.Second)); !errors.Is(err, jwt.ErrSigningUnavailable) {
		t.Fatalf("a decision instant after the clock = %v", err)
	}
	if _, err := s.SignUser(context.Background(), decision(), c.Now().Add(-61*time.Second)); !errors.Is(err, jwt.ErrSigningUnavailable) {
		t.Fatalf("a decision instant over a minute old = %v", err)
	}
	if _, err := s.SignUser(context.Background(), decision(), c.Now()); err != nil {
		t.Fatal(err)
	}
}
