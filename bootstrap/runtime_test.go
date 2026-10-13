package bootstrap_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/adapters/timezones"
	"github.com/JustIkra/umir-auth/internal/application"
)

type clock struct{}

func (clock) Now() time.Time {
	return time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Moscow", 10800))
}
func options(t *testing.T) bootstrap.Options {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile("../tests/testdata/zoneinfo.zip")
	if e != nil {
		t.Fatal(e)
	}
	zones, e := timezones.New(data, "2026a")
	if e != nil {
		t.Fatal(e)
	}
	return bootstrap.Options{StateFile: filepath.Join(dir, "auth.json"), SecretsDir: filepath.Join(dir, "secrets"), Password: "0123456789abcdef0123456789abcdef", Initial: &bootstrap.InitialUser{UserID: "11111111-1111-4111-8111-111111111111", Login: "e2e.initial", DisplayName: "E2E Initial Operator", CredentialVersion: "1"}, Clock: clock{}, TimeZones: zones, ServiceKeys: map[string]string{"gateway": string(makeHex('a')), "serving": string(makeHex('b'))}}
}
func makeHex(c byte) []byte {
	v := make([]byte, 64)
	for i := range v {
		v[i] = c
	}
	return v
}
func TestBootstrapRealLoginSingleWriterAndRestart(t *testing.T) {
	ctx := context.Background()
	o := options(t)
	r, e := bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal("valid private bootstrap rejected:", e)
	}
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	v, e := r.Store.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	a := v.Snapshot()
	if len(a.Users) != 1 || len(a.Sessions) != 0 || len(a.Organizations) != 0 || len(a.MailJobs) != 0 {
		t.Fatal("bootstrap seeded unrelated facts")
	}
	if a.Users[0].Verifier == o.Password {
		t.Fatal("password stored without Argon2")
	}
	if second, e := bootstrap.Open(ctx, o); e == nil {
		if e = second.Close(); e != nil {
			t.Error(e)
		}
		t.Fatal("second writer admitted")
	}
	s, e := r.Accounts.Login(ctx, application.LoginInput{Login: o.Initial.Login, Password: o.Password})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Accounts.UpdateDisplayName(ctx, s.Token, "Changed Operator"); e != nil {
		t.Fatal(e)
	}
	binding := r.BindingSHA256
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	o.Password = "another-password"
	r, e = bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	v, e = r.Store.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if v.Snapshot().Users[0].DisplayName != "Changed Operator" || r.BindingSHA256 != binding {
		t.Fatal("restart reseeded real profile or changed binding")
	}
	if _, e = r.Accounts.Peek(ctx, s.Token); e != nil {
		t.Fatal("session lost on restart", e)
	}
}
func TestBootstrapRejectsPartialSecretsAndCorruptState(t *testing.T) {
	ctx := context.Background()
	o := options(t)
	r, e := bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(o.SecretsDir, "owner.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = bootstrap.Open(ctx, o); !errors.Is(e, bootstrap.ErrNotReady) {
		t.Fatalf("missing secrets accepted: %v", e)
	}
	if e = os.WriteFile(o.StateFile, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = bootstrap.Open(ctx, o); e == nil {
		t.Fatal("corrupt state accepted")
	}
}
