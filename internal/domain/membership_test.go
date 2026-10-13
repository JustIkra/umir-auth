package domain_test

import (
	"errors"
	"testing"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestMembershipReplacementKeepsIdentityAndMonotonicVersions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*domain.Aggregate)
	}{
		{"changed roles without membership version", func(a *domain.Aggregate) { a.Memberships[0].Assignments[0].Roles = []string{"Waiter"} }},
		{"changed roles without assignment version", func(a *domain.Aggregate) {
			a.Memberships[0].MembershipVersion = "2"
			a.Memberships[0].Assignments[0].Roles = []string{"Waiter"}
		}},
		{"assignment retargeted", func(a *domain.Aggregate) {
			r := a.Restaurants[0]
			r.RestaurantID = id(80)
			a.Restaurants = append(a.Restaurants, r)
			a.Memberships[0].MembershipVersion = "2"
			a.Memberships[0].Assignments[0].AssignmentVersion = "2"
			a.Memberships[0].Assignments[0].RestaurantID = r.RestaurantID
		}},
		{"membership removed", func(a *domain.Aggregate) {
			m := a.Memberships[0]
			m.MembershipID = id(81)
			a.Memberships = []domain.Membership{m}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := fixture(t)
			before, err := domain.Validate(a)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&a)
			a.AggregateRevision = "2"
			after, err := domain.Validate(a)
			if err != nil {
				t.Fatal(err)
			}
			if err := domain.ValidateReplacement(before, after); !errors.Is(err, domain.ErrInvalidAggregate) {
				t.Fatalf("unsafe membership replacement accepted: %v", err)
			}
		})
	}
}

func TestAssignmentIdentityCannotMoveBetweenMemberships(t *testing.T) {
	a := fixture(t)
	before, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	old := a.Memberships[0].Assignments[0]
	u := a.Users[0]
	u.UserID = id(90)
	u.Login = "second"
	u.Email = ""
	a.Users = append(a.Users, u)
	a.Memberships[0].Assignments = []domain.Assignment{}
	a.Memberships[0].MembershipVersion = "2"
	a.Memberships = append(a.Memberships, domain.Membership{MembershipID: id(91), MembershipVersion: "1", UserID: u.UserID, OrgID: a.Organizations[0].OrgID, OrgRoles: []string{}, Assignments: []domain.Assignment{old}, State: "active"})
	a.AggregateRevision = "2"
	after, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := domain.ValidateReplacement(before, after); !errors.Is(err, domain.ErrInvalidAggregate) {
		t.Fatalf("assignment ID migrated to different membership: %v", err)
	}
}
