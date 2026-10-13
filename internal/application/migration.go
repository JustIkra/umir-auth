package application

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/JustIkra/umir-auth/internal/domain"
)

var (
	ErrInvalidLegacy  = errors.New("invalid legacy account")
	ErrUnsafeRollback = errors.New("rollback would discard auth changes")
)

type LegacySession struct {
	Digest                           string
	RememberMe                       bool
	CredentialVersion                int64
	CreatedAt, LastSeenAt, ExpiresAt domain.Instant
}
type LegacyAccount struct {
	SchemaVersion                               int
	ProfileID, Login, DisplayName, PasswordHash string
	CredentialVersion                           int64
	Sessions                                    []LegacySession
}
type LegacySelection struct {
	UserID, OrgID, RestaurantID, MembershipID domain.EntityID
	OrganizationName, RestaurantName          string
}

type VerifierChecker interface{ Check(string) error }

func MigrateLegacy(old LegacyAccount, target LegacySelection, ids IDGenerator, checker VerifierChecker) (domain.ValidatedAggregate, error) {
	fail := func() (domain.ValidatedAggregate, error) { return domain.ValidatedAggregate{}, ErrInvalidLegacy }
	if ids == nil || checker == nil || old.SchemaVersion != 1 && old.SchemaVersion != 2 || old.SchemaVersion == 1 && len(old.Sessions) != 0 || old.CredentialVersion < 1 || old.ProfileID == "" || len(old.Sessions) > 32 {
		return fail()
	}
	if err := checker.Check(old.PasswordHash); err != nil {
		return fail()
	}
	name, err := CanonicalDisplayName(old.DisplayName)
	if err != nil || name != old.DisplayName || old.Login == "" || strings.TrimFunc(old.Login, unicode.IsSpace) != old.Login || strings.ContainsFunc(old.Login, unicode.IsControl) {
		return fail()
	}
	a := domain.Empty()
	cv := domain.Version(strconv.FormatInt(old.CredentialVersion, 10))
	a.Users = append(a.Users, domain.User{UserID: target.UserID, Login: old.Login, DisplayName: old.DisplayName, Verifier: old.PasswordHash, CredentialVersion: cv})
	a.Organizations = append(a.Organizations, domain.Organization{OrgID: target.OrgID, Name: target.OrganizationName, Settings: domain.Settings{TimeZone: "Europe/Moscow", SettingsVersion: "1"}, Lifecycle: "active", LifecycleVersion: "1"})
	a.Restaurants = append(a.Restaurants, domain.Restaurant{RestaurantID: target.RestaurantID, OrgID: target.OrgID, Name: target.RestaurantName, Lifecycle: "registering", LifecycleVersion: "1"})
	a.Memberships = append(a.Memberships, domain.Membership{MembershipID: target.MembershipID, MembershipVersion: "1", UserID: target.UserID, OrgID: target.OrgID, OrgRoles: []string{"Admin"}, Assignments: []domain.Assignment{}, State: "active"})
	for _, st := range old.Sessions {
		created, err := time.Parse(time.RFC3339Nano, string(st.CreatedAt))
		if err != nil {
			return fail()
		}
		last, err := time.Parse(time.RFC3339Nano, string(st.LastSeenAt))
		if err != nil || last.Before(created) {
			return fail()
		}
		expires, err := time.Parse(time.RFC3339Nano, string(st.ExpiresAt))
		if err != nil {
			return fail()
		}
		idle := expires
		if !st.RememberMe {
			idle = last.Add(30 * time.Minute)
			if idle.After(expires) {
				idle = expires
			}
		}
		id, err := ids.NewID()
		if err != nil {
			return fail()
		}
		a.Sessions = append(a.Sessions, domain.Session{SessionID: id, UserID: target.UserID, SessionVersion: "1", CredentialVersion: domain.Version(strconv.FormatInt(st.CredentialVersion, 10)), Digest: st.Digest, CSRFTokenDigest: "", LegacyCSRF: true, CreatedAt: st.CreatedAt, IdleExpiresAt: domain.Instant(idle.Format(time.RFC3339Nano)), AbsoluteExpiresAt: st.ExpiresAt, RememberMe: st.RememberMe})
	}
	v, err := domain.Validate(a)
	if err != nil {
		return fail()
	}
	return v, nil
}
func GuardRollback(imported, current domain.ValidatedAggregate) error {
	if _, err := domain.Validate(imported.Snapshot()); err != nil {
		return ErrUnsafeRollback
	}
	if _, err := domain.Validate(current.Snapshot()); err != nil {
		return ErrUnsafeRollback
	}
	a, err := json.Marshal(imported.Snapshot())
	if err != nil {
		return ErrUnsafeRollback
	}
	b, err := json.Marshal(current.Snapshot())
	if err != nil || !bytes.Equal(a, b) {
		return ErrUnsafeRollback
	}
	return nil
}
