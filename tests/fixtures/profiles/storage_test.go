package profiles

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/adapters/timezones"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/tests/fixtures/protocol"
)

func profileOptions(t *testing.T) (bootstrap.Options, *protocol.Clock) {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile("../../testdata/zoneinfo.zip")
	if e != nil {
		t.Fatal(e)
	}
	zones, e := timezones.New(data, "go1.26.9-embedded")
	if e != nil {
		t.Fatal(e)
	}
	clock, e := protocol.NewClock("55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666", "2026-10-13T09:00:00+03:00", "1")
	if e != nil {
		t.Fatal(e)
	}
	return bootstrap.Options{StateFile: dir + "/auth.json", SecretsDir: dir + "/secrets", Initial: &bootstrap.InitialUser{UserID: "11111111-1111-4111-8111-111111111111", Login: "e2e.initial", DisplayName: "E2E Initial Operator", CredentialVersion: "1"}, Password: "0123456789abcdef0123456789abcdef", Clock: clock, TimeZones: zones}, clock
}
func TestActualStorageRefusals(t *testing.T) {
	for _, p := range []Profile{"auth-corrupt-json", "auth-unknown-schema", "auth-invalid-aggregate"} {
		t.Run(string(p), func(t *testing.T) {
			o, c := profileOptions(t)
			if _, e := prepareStorage(context.Background(), p, c, filepath.Dir(o.StateFile), "", o.Password); e != nil {
				t.Fatal(e)
			}
			before, e := os.ReadFile(o.StateFile)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := jsonstore.Open(context.Background(), o.StateFile); !errors.Is(e, application.ErrStorageUnavailable) {
				t.Fatal("constructor did not refuse", e)
			}
			after, e := os.ReadFile(o.StateFile)
			if e != nil || string(after) != string(before) {
				t.Fatal("refusal repaired source", e)
			}
		})
	}
}
func TestRealLegacyImportProofAndReopen(t *testing.T) {
	for _, p := range []Profile{"auth-legacy-v1", "auth-legacy-v2"} {
		t.Run(string(p), func(t *testing.T) {
			ctx := context.Background()
			o, c := profileOptions(t)
			dir := filepath.Dir(o.StateFile)
			prepared, e := prepareStorage(ctx, p, c, dir, "", o.Password)
			if e != nil {
				t.Fatal(e)
			}
			if prepared.Imported == nil {
				t.Fatal("missing real migration")
			}
			r, e := bootstrap.OpenImported(ctx, o, *prepared.Imported)
			if e != nil {
				t.Fatal(e)
			}
			facts, e := observeAuth(ctx, r, "admitted", dir)
			if e != nil {
				t.Fatal(e)
			}
			if facts.VerifierProof != prepared.Legacy.VerifierProof || facts.Login != prepared.Legacy.Identity.OldLogin || facts.TimeZone != "Europe/Moscow" || facts.SettingsVersion != "1" {
				t.Fatal("migration facts differ")
			}
			if len(facts.Sessions) != len(prepared.Legacy.Sessions) {
				t.Fatal("session loss")
			}
			for _, old := range prepared.Legacy.Sessions {
				found := false
				for _, s := range facts.Sessions {
					if s.DigestProof == old.DigestProof {
						found = true
						if s.CreatedAt != old.CreatedAt || s.AbsoluteExpiresAt != old.ExpiresAt || s.RememberMe != old.RememberMe {
							t.Fatal("deadline change")
						}
						last, e := time.Parse(time.RFC3339Nano, old.LastSeenAt)
						if e != nil {
							t.Fatal(e)
						}
						expected := last.Add(30 * time.Minute).Format(time.RFC3339Nano)
						if old.RememberMe {
							expected = old.ExpiresAt
						}
						if s.IdleExpiresAt != expected {
							t.Fatal("idle change")
						}
					}
				}
				if !found {
					t.Fatal("digest mapping lost")
				}
			}
			if e = protocol.ValidateProfile("AuthFacts", mustJSON(t, facts)); e != nil {
				t.Fatal(e)
			}
			if e = protocol.ValidateProfile("AuthLegacy", mustJSON(t, prepared.Legacy)); e != nil {
				t.Fatal(e)
			}
			login, e := r.Accounts.Login(ctx, application.LoginInput{Login: o.Initial.Login, Password: o.Password})
			if e != nil {
				t.Fatal("real credential login", e)
			}
			if e = checkpointStorage(c, dir); e != nil {
				t.Fatal(e)
			}
			if e = r.Close(); e != nil {
				t.Fatal(e)
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
			reopened, e := observeAuth(ctx, r, "reopened", dir)
			if e != nil {
				t.Fatal(e)
			}
			if reopened.VerifierProof != facts.VerifierProof {
				t.Fatal("rehashed verifier")
			}
			for _, mapping := range prepared.Legacy.SessionMap {
				found := false
				for _, s := range reopened.Sessions {
					if s.SessionID == mapping.SessionID && s.DigestProof == mapping.DigestProof {
						found = true
					}
				}
				if !found {
					t.Fatal("mapped session changed")
				}
			}
			if _, e = r.Accounts.Peek(ctx, login.Token); e != nil {
				t.Fatal("new real session lost", e)
			}
			reused, e := prepareStorage(ctx, p, c, dir, "", o.Password)
			if e != nil || !reused.Reopened || reused.Imported != nil {
				t.Fatal("reimport attempt", e)
			}
		})
	}
}
