package domain_test

import (
	"errors"
	"testing"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestCompleteAggregateValidatesAndCopies(t *testing.T) {
	a := fixture(t)
	v, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	a.Memberships[0].Assignments[0].Roles[0] = "Waiter"
	a.Users[0].DisplayName = "changed"
	snapshot := v.Snapshot()
	if snapshot.Users[0].DisplayName != "Owner" || snapshot.Memberships[0].Assignments[0].Roles[0] != "Warehouse" {
		t.Fatal("input alias published")
	}
	snapshot.Memberships[0].Assignments[0].Roles[0] = "Waiter"
	if v.Snapshot().Memberships[0].Assignments[0].Roles[0] != "Warehouse" {
		t.Fatal("output alias published")
	}
	if v.Revision() != "1" {
		t.Fatal("revision lost")
	}
}

func TestEmptyAggregateIsExplicitAndValid(t *testing.T) {
	if _, err := domain.Validate(domain.Empty()); err != nil {
		t.Fatal(err)
	}
	if _, err := domain.Validate(domain.Aggregate{}); !errors.Is(err, domain.ErrInvalidAggregate) {
		t.Fatalf("zero aggregate accepted: %v", err)
	}
}

func TestAggregateRejectsBrokenAuthority(t *testing.T) {
	cases := map[string]func(*domain.Aggregate){
		"schema":                func(a *domain.Aggregate) { a.SchemaVersion = 2 },
		"noncanonical revision": func(a *domain.Aggregate) { a.AggregateRevision = "01" },
		"overflow revision":     func(a *domain.Aggregate) { a.AggregateRevision = "9223372036854775808" },
		"null collection":       func(a *domain.Aggregate) { a.Sessions = nil },
		"duplicate identity":    func(a *domain.Aggregate) { a.Users = append(a.Users, a.Users[0]) },
		"duplicate login": func(a *domain.Aggregate) {
			u := a.Users[0]
			u.UserID = id(99)
			a.Users = append(a.Users, u)
		},
		"missing user":         func(a *domain.Aggregate) { a.Memberships[0].UserID = id(99) },
		"cross org assignment": func(a *domain.Aggregate) { a.Restaurants[0].OrgID = id(99) },
		"duplicate restaurant assignment": func(a *domain.Aggregate) {
			a.Memberships[0].Assignments = append(a.Memberships[0].Assignments, a.Memberships[0].Assignments[0])
		},
		"role":                         func(a *domain.Aggregate) { a.Memberships[0].Assignments[0].Roles = []string{"Admin"} },
		"last admin":                   func(a *domain.Aggregate) { a.Memberships[0].OrgRoles = []string{} },
		"unknown lifecycle":            func(a *domain.Aggregate) { a.Restaurants[0].Lifecycle = "active" },
		"empty zone":                   func(a *domain.Aggregate) { a.Organizations[0].Settings.TimeZone = "" },
		"bad instant":                  func(a *domain.Aggregate) { a.Sessions[0].AbsoluteExpiresAt = "2026-02-30T00:00:00+03:00" },
		"deadline inversion":           func(a *domain.Aggregate) { a.Sessions[0].IdleExpiresAt = "2026-10-14T00:00:00+03:00" },
		"credential future":            func(a *domain.Aggregate) { a.Sessions[0].CredentialVersion = "2" },
		"raw session":                  func(a *domain.Aggregate) { a.Sessions[0].Digest = "raw-token" },
		"orphan invitation":            func(a *domain.Aggregate) { a.Invitations[0].OrgID = id(99) },
		"challenge binding":            func(a *domain.Aggregate) { a.Challenges[0].InvitationID = id(99) },
		"orphan mail":                  func(a *domain.Aggregate) { a.MailJobs[0].ChallengeID = id(99) },
		"duplicate idempotency":        func(a *domain.Aggregate) { a.Idempotency = append(a.Idempotency, a.Idempotency[0]) },
		"wrong idempotency restaurant": func(a *domain.Aggregate) { a.Idempotency[0].RestaurantID = id(99) },
		"future result revision":       func(a *domain.Aggregate) { a.Idempotency[0].AggregateRevision = "2" },
		"incomplete peer pairs":        func(a *domain.Aggregate) { a.LifecycleIntents[0].Services = a.LifecycleIntents[0].Services[:1] },
		"peer scope mismatch":          func(a *domain.Aggregate) { a.LifecycleIntents[0].Services[0].RestaurantID = id(99) },
		"tombstone resurrection": func(a *domain.Aggregate) {
			a.Tombstones = []domain.Tombstone{{EntityID: a.Restaurants[0].RestaurantID, Kind: "restaurant", OrgID: a.Organizations[0].OrgID, LifecycleVersion: "1", DeletedAt: fixtureInstant}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := fixture(t)
			mutate(&a)
			_, err := domain.Validate(a)
			if !errors.Is(err, domain.ErrInvalidAggregate) {
				t.Fatalf("broken authority accepted: %v", err)
			}
		})
	}
}
