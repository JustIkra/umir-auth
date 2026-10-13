package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestBeforeCommitFaultDoesNotCallRealWriter(t *testing.T) {
	ctx := context.Background()
	a, e := domain.Validate(domain.Empty())
	if e != nil {
		t.Fatal(e)
	}
	store, e := jsonstore.Initialize(ctx, filepath.Join(t.TempDir(), "auth.json"), a)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e = store.Close(); e != nil {
			t.Error(e)
		}
	}()
	f := &Faults{}
	data, e := json.Marshal(map[string]any{"faultID": "11111111-1111-4111-8111-111111111111", "point": "before-commit", "operationID": "createOrganization", "commandID": "create-one", "expireAfterMs": 30000})
	if e != nil {
		t.Fatal(e)
	}
	if _, code := f.Control("owner.fault.arm", data); code != "" {
		t.Fatal(code)
	}
	repo := &FaultRepository{store, f}
	next := a.Snapshot()
	next.AggregateRevision = "2"
	v, e := domain.Validate(next)
	if e != nil {
		t.Fatal(e)
	}
	result, e := repo.Commit(WithCommand(ctx, "createOrganization", "create-one"), "1", v)
	if e == nil || result.Outcome != application.NotCommitted {
		t.Fatal("before-commit fault allowed writer")
	}
	got, e := store.Load(ctx)
	if e != nil || got.Revision() != "1" {
		t.Fatal("real state changed")
	}
}
func TestAfterRealCommitUnknownKeepsActualDurableRevision(t *testing.T) {
	ctx := context.Background()
	a, e := domain.Validate(domain.Empty())
	if e != nil {
		t.Fatal(e)
	}
	store, e := jsonstore.Initialize(ctx, filepath.Join(t.TempDir(), "auth.json"), a)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e = store.Close(); e != nil {
			t.Error(e)
		}
	}()
	f := &Faults{}
	data, e := json.Marshal(map[string]any{"faultID": "11111111-1111-4111-8111-111111111111", "point": "after-real-commit-return-unknown", "operationID": "createOrganization", "commandID": "create-one", "expireAfterMs": 30000})
	if e != nil {
		t.Fatal(e)
	}
	if _, code := f.Control("owner.fault.arm", data); code != "" {
		t.Fatal(code)
	}
	repo := &FaultRepository{store, f}
	next := a.Snapshot()
	next.AggregateRevision = "2"
	v, e := domain.Validate(next)
	if e != nil {
		t.Fatal(e)
	}
	result, e := repo.Commit(WithCommand(ctx, "createOrganization", "create-one"), "1", v)
	if !errors.Is(e, application.ErrRecoveryRequired) || result.Outcome != application.Unknown {
		t.Fatal("adapter did not lose real committed return")
	}
	got, e := store.Load(ctx)
	if e != nil || got.Revision() != "2" {
		t.Fatal("real commit missing")
	}
	f.mu.Lock()
	outcome, hits := f.armed.Outcome, f.armed.Hits
	f.mu.Unlock()
	if outcome != "committed" || hits != 1 {
		t.Fatal("fault observation invented owner outcome")
	}
}
