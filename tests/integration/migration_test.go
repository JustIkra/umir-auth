package integration_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/adapters/legacy"
	"github.com/JustIkra/umir-auth/internal/application"
)

func legacyBytes(version int) []byte {
	sessions := ""
	if version == 2 {
		sessions = fmt.Sprintf(`,"sessions":[{"digest":%q,"rememberMe":false,"credentialVersion":7,"createdAt":"2026-10-12T22:00:00Z","lastSeenAt":"2026-10-12T22:10:00Z","expiresAt":"2026-10-13T06:00:00Z"}]`, application.TokenDigest("legacy-token"))
	}
	return []byte(fmt.Sprintf(`{"schemaVersion":%d,"profileID":"legacy-opaque-profile","login":"owner","displayName":"Owner","passwordHash":%q,"credentialVersion":7%s}`, version, verifier, sessions))
}
func selection() application.LegacySelection {
	return application.LegacySelection{UserID: uid(1), OrgID: uid(2), RestaurantID: uid(3), MembershipID: uid(4), OrganizationName: "Legacy org", RestaurantName: "Legacy restaurant"}
}
func TestLegacySchemasPreserveCredentialsDeadlinesAndRollback(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			old, err := legacy.Decode(legacyBytes(version))
			if err != nil {
				t.Fatal(err)
			}
			imported, err := application.MigrateLegacy(old, selection(), &mechanisms{}, &mechanisms{})
			if err != nil {
				t.Fatal(err)
			}
			a := imported.Snapshot()
			if a.Users[0].Verifier != verifier || a.Users[0].CredentialVersion != "7" || a.Users[0].Login != "owner" || a.Users[0].Email != "" {
				t.Fatal("legacy identity altered")
			}
			if a.Organizations[0].Settings.TimeZone != "Europe/Moscow" || a.Organizations[0].Settings.SettingsVersion != "1" || a.Restaurants[0].Lifecycle != "registering" || a.Memberships[0].OrgRoles[0] != "Admin" {
				t.Fatal("explicit legacy scope/settings missing")
			}
			if len(a.Sessions) != version-1 {
				t.Fatal("sessions fabricated/lost")
			}
			if err := application.GuardRollback(imported, imported); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(t.TempDir(), "auth.json")
			r, err := jsonstore.Initialize(ctx, p, imported)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			r, err = jsonstore.Open(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			}()
			c := &clock{at: time.Date(2026, 10, 13, 1, 15, 0, 0, time.FixedZone("Europe/Moscow", 3*3600))}
			s := service(t, r, c, &mechanisms{})
			if version == 2 {
				stored := a.Sessions[0]
				if stored.Digest != application.TokenDigest("legacy-token") || stored.CreatedAt != "2026-10-12T22:00:00Z" || stored.AbsoluteExpiresAt != "2026-10-13T06:00:00Z" || stored.IdleExpiresAt != "2026-10-12T22:40:00Z" {
					t.Fatal("immutable instant/digest migration")
				}
				csrf, err := s.SessionCSRF(ctx, "legacy-token")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.Authorize(ctx, "legacy-token", csrf, false); err != nil {
					t.Fatal("migrated csrf unusable")
				}
				if err := s.Logout(ctx, "legacy-token"); err != nil {
					t.Fatal(err)
				}
				current, err := r.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if !errors.Is(application.GuardRollback(imported, current), application.ErrUnsafeRollback) {
					t.Fatal("rollback could resurrect logout")
				}
			}
		})
	}
}
func TestLegacyStrictBoundaryAndExplicitSelection(t *testing.T) {
	data := string(legacyBytes(2))
	for _, bad := range []string{data + ` {}`, strings.Replace(data, `"login":"owner"`, `"LOGIN":"owner"`, 1), strings.Replace(data, `"login":"owner"`, `"login":"owner","login":"owner"`, 1), strings.Replace(data, `"sessions":[`, `"sessions":null,"other":[`, 1), strings.Replace(data, `"schemaVersion":2`, `"schemaVersion":3`, 1), strings.Replace(data, `"rememberMe":false`, `"rememberMe":null`, 1), strings.Replace(data, `"displayName":"Owner"`, `"displayName":"\ud800"`, 1)} {
		if _, err := legacy.Decode([]byte(bad)); err == nil {
			t.Fatal("legacy malformed accepted")
		}
	}
	old, err := legacy.Decode(legacyBytes(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.MigrateLegacy(old, application.LegacySelection{}, &mechanisms{}, &mechanisms{}); err == nil {
		t.Fatal("implicit tenant created")
	}
	for _, bad := range []string{strings.Replace(data, `"credentialVersion":7`, `"credentialVersion":0`, 1), strings.Replace(data, "2026-10-13T06:00:00Z", "2026-10-13T07:00:00Z", 1)} {
		old, err := legacy.Decode([]byte(bad))
		if err == nil {
			_, err = application.MigrateLegacy(old, selection(), &mechanisms{}, &mechanisms{})
		}
		if err == nil {
			t.Fatal("invalid legacy credentials/deadlines accepted")
		}
	}
}
func TestMigrationDoesNotModifyLegacyBackup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "backup.json")
	data := legacyBytes(2)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := legacy.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.MigrateLegacy(old, selection(), &mechanisms{}, &mechanisms{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != string(data) {
		t.Fatal("migration wrote legacy backup")
	}
}
func TestLegacyProfilePolicyIsNotRelaxed(t *testing.T) {
	for _, pair := range [][2]string{{`"login":"owner"`, `"login":" owner"`}, {`"displayName":"Owner"`, `"displayName":" Owner "`}, {`"login":"owner"`, `"login":"own\ter"`}} {
		old, err := legacy.Decode([]byte(strings.Replace(string(legacyBytes(1)), pair[0], pair[1], 1)))
		if err == nil {
			_, err = application.MigrateLegacy(old, selection(), &mechanisms{}, &mechanisms{})
		}
		if err == nil {
			t.Fatal("legacy profile policy relaxed")
		}
	}
}
