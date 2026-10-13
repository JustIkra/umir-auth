package domain_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestPermissionsMatchFrozenRoleCapabilities(t *testing.T) {
	warehouse := []string{"catalog.read", "catalog.write", "stock.read", "delivery.create", "analytics.read", "writeoff.confirm", "menu.read", "recommendations.read", "feedback.submit"}
	waiter := []string{"menu.read", "recommendations.read", "order.prepare", "order.confirm", "order.read", "feedback.submit"}
	union := append(slices.Clone(warehouse), "order.prepare", "order.confirm", "order.read")
	admin := append(slices.Clone(union), "org.read", "org.settings.write", "restaurant.create", "restaurant.delete", "org.delete", "membership.manage", "invitation.manage", "org.summary.read", "feedback.read", "feedback.export")
	for _, tc := range []struct {
		name                  string
		roles, orgRoles, want []string
	}{
		{"Warehouse", []string{"Warehouse"}, []string{}, warehouse},
		{"Waiter", []string{"Waiter"}, []string{}, waiter},
		{"union", []string{"Warehouse", "Waiter"}, []string{}, union},
		{"Admin", []string{}, []string{"Admin"}, admin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := fixture(t)
			a.Restaurants[0].Lifecycle = "ready"
			a.Memberships[0].OrgRoles = tc.orgRoles
			a.Memberships[0].Assignments[0].Roles = tc.roles
			if len(tc.roles) == 0 {
				a.Memberships[0].Assignments = []domain.Assignment{}
			}
			result, err := domain.RestaurantPermissions(a, a.Users[0].UserID, a.Restaurants[0].RestaurantID)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(result.Permissions, tc.want) {
				t.Fatalf("permissions=%v want=%v", result.Permissions, tc.want)
			}
			for _, p := range []string{"runtime.register", "runtime.close", "expiry.due", "consumer.order.commit", "feedback.anonymous.submit"} {
				if slices.Contains(result.Permissions, p) {
					t.Fatal("non-user capability leaked", p)
				}
			}
		})
	}
}
func TestPermissionsFailClosedForInactiveMissingAndWildcardScope(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*domain.Aggregate)
		scope  domain.EntityID
	}{
		{"registering", func(a *domain.Aggregate) { a.Restaurants[0].Lifecycle = "registering" }, ""},
		{"deleting", func(a *domain.Aggregate) { a.Restaurants[0].Lifecycle = "deleting" }, ""},
		{"deleted", func(a *domain.Aggregate) { a.Restaurants[0].Lifecycle = "deleted" }, ""},
		{"org deleted", func(a *domain.Aggregate) { a.Organizations[0].Lifecycle = "deleted" }, ""},
		{"revoked", func(a *domain.Aggregate) { a.Memberships[0].State = "revoked" }, ""},
		{"missing", func(*domain.Aggregate) {}, id(999)},
		{"wildcard", func(*domain.Aggregate) {}, "*"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := fixture(t)
			a.Restaurants[0].Lifecycle = "ready"
			tc.mutate(&a)
			scope := tc.scope
			if scope == "" {
				scope = a.Restaurants[0].RestaurantID
			}
			if _, err := domain.RestaurantPermissions(a, a.Users[0].UserID, scope); !errors.Is(err, domain.ErrAccessDenied) {
				t.Fatalf("inactive scope allowed: %v", err)
			}
		})
	}
}
