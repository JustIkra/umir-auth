package integration_test

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/application"
)

// verifyRecorder remembers the stored verifier each Verify was given.
type verifyRecorder struct {
	*mechanisms
	mu        sync.Mutex
	verifiers []string
}

func (v *verifyRecorder) Verify(p, e string) (bool, error) {
	v.mu.Lock()
	v.verifiers = append(v.verifiers, e)
	v.mu.Unlock()
	return v.mechanisms.Verify(p, e)
}

// An unknown login is verified against a dummy verifier made by the selected
// hasher, so its cost does not depend on the parameters stored for whichever
// account happens to be first (L1).
func TestUnknownLoginDoesNotBorrowTheFirstAccountsVerifier(t *testing.T) {
	const heavy = "$argon2id$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU"
	a := fixture(t)
	a.Users[0].Verifier = heavy
	r, err := jsonstore.Initialize(ctx, filepath.Join(t.TempDir(), "auth.json"), validate(t, a))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	m := &mechanisms{}
	recorder := &verifyRecorder{mechanisms: m}
	c := &clock{at: time.Date(2026, 10, 13, 1, 0, 0, 0, time.FixedZone("Europe/Moscow", 3*3600))}
	s, err := application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: recorder, Clock: c, IDs: m, Tokens: m})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, application.LoginInput{Login: "nobody", Password: "password"}); err == nil {
		t.Fatal("unknown login succeeded")
	}
	if len(recorder.verifiers) != 1 {
		t.Fatalf("%d verifications for one unknown login", len(recorder.verifiers))
	}
	if recorder.verifiers[0] == heavy {
		t.Fatal("an unknown login was verified against the first account's verifier")
	}
	if recorder.verifiers[0] != verifier {
		t.Fatalf("unknown login verified against %q; want the selected hasher's own dummy", recorder.verifiers[0])
	}
}
