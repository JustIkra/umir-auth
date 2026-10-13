package jwt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
	"github.com/JustIkra/umir-auth/internal/application"
)

func TestSnapshotPreservesIssuanceAndCopiesPrivateKeys(t *testing.T) {
	ctx := context.Background()
	c := &clock{at: time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))}
	s, e := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: key(t, "A")})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.PublishNext(key(t, "B")); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"user", "service", "anonymous"} {
		c.add(time.Second)
		switch kind {
		case "user":
			_, e = s.SignUser(ctx, decision(), c.Now())
		case "anonymous":
			_, e = s.SignAnonymous(ctx, c.Now())
		case "service":
			_, e = s.SignService(ctx, application.ServiceDecision{Subject: "service:gateway", AuthorizedParty: "umir-gateway", Operation: "expiry.due", Audiences: []string{"umir-warehouse"}, Permissions: []string{"expiry.due"}, OrgID: id, TenantID: id, RuntimeEpoch: id, LifecycleVersion: "1"}, c.Now())
		}
		if e != nil {
			t.Fatal(e)
		}
		v, e := s.Snapshot(ctx)
		if e != nil || !v.ActiveLastIssued.Equal(c.Now()) {
			t.Fatal("missing issuance", kind, e)
		}
	}
	v, e := s.Snapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	v.Active.PrivateKey[0] ^= 1
	v.Next.Key.PrivateKey[0] ^= 1
	copy, e := s.Snapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if v.Active.PrivateKey[0] == copy.Active.PrivateKey[0] || v.Next.Key.PrivateKey[0] == copy.Next.Key.PrivateKey[0] {
		t.Fatal("private alias")
	}
	c.add(56 * time.Second)
	if e = s.ActivateNext(); !errors.Is(e, jwt.ErrKeyOverlap) {
		t.Fatal("early activation", e)
	}
	c.add(time.Second)
	if e = s.ActivateNext(); e != nil {
		t.Fatal(e)
	}
	v, e = s.Snapshot(ctx)
	if e != nil || v.Previous == nil || !v.PreviousLastIssued.Equal(c.Now().Add(-57*time.Second)) || !v.Previous.RetainUntil.Equal(v.PreviousLastIssued.Add(time.Minute)) {
		t.Fatal("retention proof lost", e)
	}
	restored, e := jwt.New(jwt.Options{Clock: c, IDs: ids{}, Active: v.Active, ActiveLastIssued: v.ActiveLastIssued, Previous: v.Previous})
	if e != nil {
		t.Fatal(e)
	}
	keys, e := restored.JWKS(ctx)
	if e != nil || len(keys.Keys) != 2 {
		t.Fatal("overlap restore", e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.Snapshot(cancelled); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
