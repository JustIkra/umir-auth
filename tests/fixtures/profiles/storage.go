package profiles

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/adapters/legacy"
	"github.com/JustIkra/umir-auth/internal/adapters/password"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
	"github.com/JustIkra/umir-auth/tests/fixtures/protocol"
)

type Profile string
type Phase string
type AuthFacts = protocol.ProfileAuthFacts
type PreparedFacts struct {
	Legacy   *protocol.ProfileAuthLegacy
	Imported *domain.ValidatedAggregate
	Reopened bool
}
type storageMetadata struct {
	Profile       string
	Project       string
	Contract      string
	Clock         protocol.ProfileClock
	PreparedClock protocol.ProfileClock
	ProofKey      []byte
	Legacy        *protocol.ProfileAuthLegacy
	Import        domain.Aggregate
	Admitted      bool
}
type migrationIDs struct{}

func (migrationIDs) NewID() (domain.EntityID, error) {
	s, e := protocol.UUID()
	return domain.EntityID(s), e
}
func proof(key []byte, s string) string {
	h := hmac.New(sha256.New, key)
	_, e := h.Write([]byte(s))
	if e != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
func PrepareStorage(ctx context.Context, p Profile, clock *protocol.Clock) (PreparedFacts, error) {
	password, e := bootstrap.ReadPrivateFile("/run/umir-fixtures/secrets/bootstrap-password", 32)
	if e != nil {
		return PreparedFacts{}, e
	}
	defer clear(password)
	return prepareStorage(ctx, p, clock, ownerDir, "", string(password))
}
func prepareStorage(ctx context.Context, p Profile, c *protocol.Clock, dir, project, secret string) (PreparedFacts, error) {
	if e := ctx.Err(); e != nil {
		return PreparedFacts{}, e
	}
	if !protocol.AuthProfile(string(p)) {
		return PreparedFacts{}, errors.New("unknown profile")
	}
	metaPath := dir + "/profile-state.json"
	var m storageMetadata
	if _, e := os.Lstat(metaPath); e == nil {
		if e = readPrivate(metaPath, &m); e != nil {
			return PreparedFacts{}, e
		}
		if m.Profile != string(p) || m.Project != project || m.Contract != protocol.ProfileIdentity || len(m.ProofKey) != 32 {
			return PreparedFacts{}, errors.New("stored profile mismatch")
		}
		if !m.Admitted {
			return PreparedFacts{Legacy: m.Legacy}, nil
		}
		return PreparedFacts{Legacy: m.Legacy, Reopened: true}, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return PreparedFacts{}, e
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		return PreparedFacts{}, errors.New("profile volume is not fresh")
	}
	m = storageMetadata{Profile: string(p), Project: project, Contract: protocol.ProfileIdentity, Clock: protocol.ProfileClockRead(c), PreparedClock: protocol.ProfileClockRead(c), ProofKey: make([]byte, 32)}
	if _, e = rand.Read(m.ProofKey); e != nil {
		return PreparedFacts{}, e
	}
	var imported *domain.ValidatedAggregate
	switch p {
	case "auth-corrupt-json":
		e = writeBytes(dir+"/auth.json", []byte(`{"schemaVersion":`), true)
	case "auth-unknown-schema":
		a := domain.Empty()
		a.SchemaVersion = 999
		e = writePrivate(dir+"/auth.json", a, true)
	case "auth-invalid-aggregate":
		a := domain.Empty()
		a.Memberships = append(a.Memberships, domain.Membership{MembershipID: "44444444-4444-4444-8444-444444444444", MembershipVersion: "1", UserID: "11111111-1111-4111-8111-111111111111", OrgID: "22222222-2222-4222-8222-222222222222", OrgRoles: []string{"Admin"}, Assignments: []domain.Assignment{}, State: "active"})
		e = writePrivate(dir+"/auth.json", a, true)
	case "auth-legacy-v1", "auth-legacy-v2":
		h, err := password.New(password.Selected, rand.Reader)
		if err != nil {
			return PreparedFacts{}, err
		}
		verifier, err := h.Hash(secret)
		if err != nil {
			return PreparedFacts{}, err
		}
		schema := 1
		if p == "auth-legacy-v2" {
			schema = 2
		}
		identity := protocol.ProfileAuthIdentityMap{OldProfileID: "synthetic-legacy", OldLogin: "e2e.initial", OldDisplayName: "E2E Initial Operator", OldCredentialVersion: "1", UserID: "11111111-1111-4111-8111-111111111111", OrgID: "22222222-2222-4222-8222-222222222222", RestaurantID: "33333333-3333-4333-8333-333333333333", MembershipID: "44444444-4444-4444-8444-444444444444"}
		old := struct {
			SchemaVersion     int             `json:"schemaVersion"`
			ProfileID         string          `json:"profileID"`
			Login             string          `json:"login"`
			DisplayName       string          `json:"displayName"`
			PasswordHash      string          `json:"passwordHash"`
			CredentialVersion int64           `json:"credentialVersion"`
			Sessions          []legacySession `json:"sessions,omitempty"`
		}{schema, identity.OldProfileID, identity.OldLogin, identity.OldDisplayName, verifier, 1, nil}
		m.Legacy = &protocol.ProfileAuthLegacy{SchemaVersion: schema, Identity: identity, VerifierProof: proof(m.ProofKey, verifier), Sessions: []protocol.ProfileAuthPreparedSession{}, SessionMap: []protocol.ProfileAuthSessionMap{}, TimeZone: "Europe/Moscow", SettingsVersion: "1", PreparedClock: m.PreparedClock}
		if schema == 2 {
			for _, remember := range []bool{false, true} {
				raw := make([]byte, 32)
				if _, err = rand.Read(raw); err != nil {
					return PreparedFacts{}, err
				}
				digest := application.TokenDigest(hex.EncodeToString(raw))
				clear(raw)
				created, last := c.Now().Add(-10*time.Minute), c.Now().Add(-5*time.Minute)
				expires := created.Add(8 * time.Hour)
				if remember {
					created = c.Now().Add(-time.Hour)
					last = c.Now().Add(-time.Minute)
					expires = created.Add(30 * 24 * time.Hour)
				}
				session := legacySession{Digest: digest, RememberMe: remember, CredentialVersion: 1, CreatedAt: created.Format(time.RFC3339Nano), LastSeenAt: last.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano)}
				old.Sessions = append(old.Sessions, session)
				m.Legacy.Sessions = append(m.Legacy.Sessions, protocol.ProfileAuthPreparedSession{DigestProof: proof(m.ProofKey, digest), CreatedAt: session.CreatedAt, LastSeenAt: session.LastSeenAt, ExpiresAt: session.ExpiresAt, RememberMe: remember, CredentialVersion: "1"})
			}
		}
		b, err := json.Marshal(old)
		if err != nil {
			return PreparedFacts{}, err
		}
		defer clear(b)
		if err = writeBytes(dir+"/legacy.json", b, true); err != nil {
			return PreparedFacts{}, err
		}
		decoded, err := legacy.Decode(b)
		if err != nil {
			return PreparedFacts{}, err
		}
		v, err := application.MigrateLegacy(decoded, application.LegacySelection{UserID: domain.EntityID(identity.UserID), OrgID: domain.EntityID(identity.OrgID), RestaurantID: domain.EntityID(identity.RestaurantID), MembershipID: domain.EntityID(identity.MembershipID), OrganizationName: "Synthetic Legacy Organization", RestaurantName: "Synthetic Legacy Restaurant"}, migrationIDs{}, h)
		if err != nil {
			return PreparedFacts{}, err
		}
		m.Import = v.Snapshot()
		imported = &v
		for _, s := range m.Import.Sessions {
			m.Legacy.SessionMap = append(m.Legacy.SessionMap, protocol.ProfileAuthSessionMap{DigestProof: proof(m.ProofKey, s.Digest), SessionID: string(s.SessionID)})
		}
	}
	if e != nil {
		return PreparedFacts{}, e
	}
	if p == "auth-corrupt-json" || p == "auth-unknown-schema" || p == "auth-invalid-aggregate" {
		if e = os.Mkdir(dir+"/secrets", 0700); e != nil {
			return PreparedFacts{}, e
		}
	}
	if e = writePrivate(metaPath, m, true); e != nil {
		return PreparedFacts{}, e
	}
	return PreparedFacts{Legacy: m.Legacy, Imported: imported}, nil
}

type legacySession struct {
	Digest            string `json:"digest"`
	RememberMe        bool   `json:"rememberMe"`
	CredentialVersion int64  `json:"credentialVersion"`
	CreatedAt         string `json:"createdAt"`
	LastSeenAt        string `json:"lastSeenAt"`
	ExpiresAt         string `json:"expiresAt"`
}

func CheckpointStorage(clock *protocol.Clock) error { return checkpointStorage(clock, ownerDir) }
func checkpointStorage(clock *protocol.Clock, dir string) error {
	var m storageMetadata
	if e := readPrivate(dir+"/profile-state.json", &m); e != nil {
		return e
	}
	m.Clock = protocol.ProfileClockRead(clock)
	m.Admitted = true
	return writePrivate(dir+"/profile-state.json", m, false)
}
func ObserveAuth(ctx context.Context, r *bootstrap.Runtime, phase Phase) (AuthFacts, error) {
	return observeAuth(ctx, r, phase, ownerDir)
}
func observeAuth(ctx context.Context, r *bootstrap.Runtime, phase Phase, dir string) (AuthFacts, error) {
	var m storageMetadata
	if e := readPrivate(dir+"/profile-state.json", &m); e != nil {
		return AuthFacts{}, e
	}
	v, e := r.Store.Load(ctx)
	if e != nil {
		return AuthFacts{}, e
	}
	a := v.Snapshot()
	out := AuthFacts{Phase: string(phase), Revision: string(v.Revision()), Sessions: []protocol.ProfileSession{}}
	for _, u := range a.Users {
		if u.UserID == "11111111-1111-4111-8111-111111111111" {
			out.UserID = string(u.UserID)
			out.Login = u.Login
			out.DisplayName = u.DisplayName
			out.CredentialVersion = string(u.CredentialVersion)
			out.VerifierProof = proof(m.ProofKey, u.Verifier)
		}
	}
	for _, s := range a.Sessions {
		if string(s.UserID) == out.UserID {
			out.Sessions = append(out.Sessions, protocol.ProfileSession{SessionID: string(s.SessionID), DigestProof: proof(m.ProofKey, s.Digest), CreatedAt: string(s.CreatedAt), IdleExpiresAt: string(s.IdleExpiresAt), AbsoluteExpiresAt: string(s.AbsoluteExpiresAt), RememberMe: s.RememberMe, CredentialVersion: string(s.CredentialVersion)})
		}
	}
	for _, org := range a.Organizations {
		if org.OrgID == "22222222-2222-4222-8222-222222222222" {
			out.OrgID = string(org.OrgID)
			out.TimeZone = org.Settings.TimeZone
			out.SettingsVersion = string(org.Settings.SettingsVersion)
		}
	}
	for _, restaurant := range a.Restaurants {
		if string(restaurant.OrgID) == out.OrgID {
			out.RestaurantID = string(restaurant.RestaurantID)
		}
	}
	for _, membership := range a.Memberships {
		if string(membership.UserID) == out.UserID && string(membership.OrgID) == out.OrgID {
			out.MembershipID = string(membership.MembershipID)
		}
	}
	commands, e := json.Marshal(a.Idempotency)
	if e != nil {
		return AuthFacts{}, e
	}
	out.CommandFactsSHA256 = protocol.SHA(commands)
	tombstones, e := json.Marshal(a.Tombstones)
	if e != nil {
		return AuthFacts{}, e
	}
	out.TombstoneFactsSHA256 = protocol.SHA(tombstones)
	if _, e = strconv.ParseInt(out.CredentialVersion, 10, 64); e != nil {
		return AuthFacts{}, e
	}
	return out, nil
}
