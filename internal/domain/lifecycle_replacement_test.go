package domain_test

import (
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestA6LifecycleVersionsCannotRollBack(t *testing.T) {
	for _, entity := range []string{"organization", "restaurant"} {
		t.Run(entity, func(t *testing.T) {
			a := fixture(t)
			a.Organizations[0].LifecycleVersion = "2"
			a.Restaurants[0].LifecycleVersion = "2"
			before, err := domain.Validate(a)
			if err != nil {
				t.Fatal(err)
			}
			next := before.Snapshot()
			if entity == "organization" {
				next.Organizations[0].LifecycleVersion = "1"
			} else {
				next.Restaurants[0].LifecycleVersion = "1"
			}
			after, err := domain.Validate(next)
			if err != nil {
				t.Fatal(err)
			}
			if domain.ValidateReplacement(before, after) == nil {
				t.Fatal("lifecycle version rollback accepted")
			}
		})
	}
}

func TestA6LifecycleAcceptsOpaqueLongCommand(t *testing.T) {
	a := fixture(t)
	a.LifecycleIntents = []domain.LifecycleIntent{}
	r := a.Restaurants[0]
	a.LifecycleIntents = append(a.LifecycleIntents, domain.LifecycleIntent{OperationID: "77777777-7777-4777-8777-777777777777", CommandID: strings.Repeat("opaque", 100), ActorID: a.Users[0].UserID, OrgID: r.OrgID, RestaurantIDs: []domain.EntityID{r.RestaurantID}, Lifecycle: "registering", LifecycleVersion: r.LifecycleVersion, Cleanup: "not_required", Services: []domain.PeerReadiness{}})
	for _, service := range []string{"warehouse", "serving", "gateway"} {
		a.LifecycleIntents[0].Services = append(a.LifecycleIntents[0].Services, domain.PeerReadiness{RestaurantID: r.RestaurantID, Service: service, State: "pending", LifecycleVersion: r.LifecycleVersion})
	}
	if _, err := domain.Validate(a); err != nil {
		t.Fatal("frozen opaque command rejected", err)
	}
}

func TestA6IntentVersionAndPurposeStayImmutable(t *testing.T) {
	a := fixture(t)
	before, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"version", "purpose"} {
		t.Run(kind, func(t *testing.T) {
			next := before.Snapshot()
			if kind == "version" {
				next.LifecycleIntents[0].LifecycleVersion = "2"
				for i := range next.LifecycleIntents[0].Services {
					next.LifecycleIntents[0].Services[i].LifecycleVersion = "2"
				}
			} else {
				next.LifecycleIntents[0].Lifecycle = "deleting"
				next.LifecycleIntents[0].Cleanup = "pending"
			}
			after, err := domain.Validate(next)
			if err != nil {
				t.Fatal(err)
			}
			if domain.ValidateReplacement(before, after) == nil {
				t.Fatal("accepted intent authority was rewritten")
			}
		})
	}
}
