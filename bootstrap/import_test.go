package bootstrap_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/adapters/password"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestOpenImportedPreservesVerifierAndNormalReopen(t *testing.T) {
	ctx := context.Background()
	o := options(t)
	h, e := password.New(password.Selected, rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := h.Hash(o.Password)
	if e != nil {
		t.Fatal(e)
	}
	a := domain.Empty()
	a.Users = append(a.Users, domain.User{UserID: o.Initial.UserID, Login: o.Initial.Login, DisplayName: o.Initial.DisplayName, CredentialVersion: "1", Verifier: verifier})
	v, e := domain.Validate(a)
	if e != nil {
		t.Fatal(e)
	}
	r, e := bootstrap.OpenImported(ctx, o, v)
	if e != nil {
		t.Fatal(e)
	}
	loaded, e := r.Store.Load(ctx)
	if e != nil || loaded.Snapshot().Users[0].Verifier != verifier {
		t.Fatal("import rehashed", e)
	}
	if _, e := r.Accounts.Login(ctx, application.LoginInput{Login: o.Initial.Login, Password: o.Password}); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if other, e := bootstrap.OpenImported(ctx, o, v); e == nil {
		if e = other.Close(); e != nil {
			t.Error(e)
		}
		t.Fatal("reimport overwrote state")
	}
	r, e = bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	loaded, e = r.Store.Load(ctx)
	if e != nil || loaded.Snapshot().Users[0].Verifier != verifier {
		t.Fatal("reopen changed verifier", e)
	}
}
