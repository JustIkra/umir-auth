package storecontract

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func Run[T application.Store](t *testing.T, newStore func() T) {
	t.Helper()
	t.Run("rollback failed transaction", func(t *testing.T) {
		checkFailedTransactionRollsBack(t, newStore())
	})
	t.Run("normalized email login uniqueness", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		for _, login := range []string{"owner@EXAMPLE.invalid", "owner@example.invalid"} {
			_, err := store.InTx(ctx, application.Scope{Actor: application.ActorSystem}, func(tx application.Tx) error {
				return tx.Users().Insert(ctx, domain.User{UserID: domain.EntityID(login), Login: login})
			})
			if login == "owner@EXAMPLE.invalid" && err != nil {
				t.Fatal(err)
			}
			if login == "owner@example.invalid" && !errors.Is(err, application.ErrEntityConflict) {
				t.Fatalf("case alias was not rejected: %v", err)
			}
		}
		if err := store.View(ctx, application.Scope{Actor: application.ActorSystem}, func(reader application.Reader) error {
			user, found, err := reader.Users().Get(ctx, "owner@EXAMPLE.invalid")
			if err != nil {
				return err
			}
			if !found || user.Login != "owner@EXAMPLE.invalid" {
				t.Fatal("committed user is not visible")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("session user reference and digest uniqueness", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorSystem}
		user := domain.User{UserID: "user-1", Login: "owner@example.invalid"}
		session := domain.Session{SessionID: "session-1", UserID: user.UserID, Digest: "digest-1"}
		if _, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			if err := tx.Users().Insert(ctx, user); err != nil {
				return err
			}
			return tx.Sessions().Insert(ctx, session)
		}); err != nil {
			t.Fatal(err)
		}
		_, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			return tx.Sessions().Insert(ctx, domain.Session{SessionID: "session-2", UserID: user.UserID, Digest: "digest-1"})
		})
		if !errors.Is(err, application.ErrEntityConflict) {
			t.Fatalf("duplicate session digest was accepted: %v", err)
		}
	})
	t.Run("command identity uniqueness", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorAnonymous}
		command := domain.IdempotencyRecord{PreauthDigest: "preauth", OperationID: "login", CommandID: "command-1", Fingerprint: "first"}
		if _, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			return tx.Commands().Insert(ctx, command)
		}); err != nil {
			t.Fatal(err)
		}
		command.Fingerprint = "different"
		_, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			return tx.Commands().Insert(ctx, command)
		})
		if !errors.Is(err, application.ErrEntityConflict) {
			t.Fatalf("command key reused with a different fingerprint: %v", err)
		}
	})
	t.Run("restaurant organization reference", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorSystem}
		org := domain.Organization{OrgID: "org-1", Name: "Organization", Lifecycle: "active", LifecycleVersion: "1"}
		restaurant := domain.Restaurant{RestaurantID: "restaurant-1", OrgID: org.OrgID, Name: "Restaurant", Lifecycle: "registering", LifecycleVersion: "1"}
		if _, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			if err := tx.Organizations().Insert(ctx, org); err != nil {
				return err
			}
			return tx.Restaurants().Insert(ctx, restaurant)
		}); err != nil {
			t.Fatal(err)
		}
		_, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			return tx.Restaurants().Insert(ctx, domain.Restaurant{RestaurantID: "restaurant-2", OrgID: "missing-org", Lifecycle: "registering", LifecycleVersion: "1"})
		})
		if !errors.Is(err, application.ErrReferenceMissing) {
			t.Fatalf("restaurant without organization was accepted: %v", err)
		}
		if err := store.View(ctx, scope, func(reader application.Reader) error {
			restaurants, err := reader.Restaurants().ForOrganization(ctx, org.OrgID)
			if err != nil {
				return err
			}
			if len(restaurants) != 1 || restaurants[0].RestaurantID != restaurant.RestaurantID {
				t.Fatal("organization restaurant query returned an unexpected scope")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("membership assignment organization scope", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorSystem}
		orgA := domain.Organization{OrgID: "org-a", Name: "A", Lifecycle: "active", LifecycleVersion: "1"}
		orgB := domain.Organization{OrgID: "org-b", Name: "B", Lifecycle: "active", LifecycleVersion: "1"}
		restaurantB := domain.Restaurant{RestaurantID: "restaurant-b", OrgID: orgB.OrgID, Name: "B", Lifecycle: "ready", LifecycleVersion: "1"}
		membership := domain.Membership{MembershipID: "membership-a", MembershipVersion: "1", UserID: "user-a", OrgID: orgA.OrgID, Assignments: []domain.Assignment{{RestaurantID: restaurantB.RestaurantID, AssignmentID: "assignment-a", AssignmentVersion: "1", Roles: []string{"Waiter"}}}, State: "active"}
		_, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			if err := tx.Organizations().Insert(ctx, orgA); err != nil {
				return err
			}
			if err := tx.Organizations().Insert(ctx, orgB); err != nil {
				return err
			}
			if err := tx.Restaurants().Insert(ctx, restaurantB); err != nil {
				return err
			}
			if err := tx.Users().Insert(ctx, domain.User{UserID: membership.UserID, Login: "owner@example.invalid"}); err != nil {
				return err
			}
			return tx.Memberships().Insert(ctx, membership)
		})
		if !errors.Is(err, application.ErrScopeMismatch) {
			t.Fatalf("cross-organization assignment was accepted: %v", err)
		}
	})
	t.Run("one pending invitation per email and organization", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorSystem}
		org := domain.Organization{OrgID: "org-1", Name: "Organization", Lifecycle: "active", LifecycleVersion: "1"}
		first := domain.Invitation{InvitationID: "invitation-1", OrgID: org.OrgID, Email: "Bob@example.invalid", ComparisonEmail: "Bob@example.invalid", State: "pending", Version: "1"}
		if _, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			if err := tx.Organizations().Insert(ctx, org); err != nil {
				return err
			}
			return tx.Invitations().Insert(ctx, first)
		}); err != nil {
			t.Fatal(err)
		}
		second := domain.Invitation{InvitationID: "invitation-2", OrgID: org.OrgID, Email: "bob@example.invalid", ComparisonEmail: "bob@example.invalid", State: "pending", Version: "1"}
		_, err := store.InTx(ctx, scope, func(tx application.Tx) error { return tx.Invitations().Insert(ctx, second) })
		if !errors.Is(err, application.ErrEntityConflict) {
			t.Fatalf("duplicate pending invite was accepted: %v", err)
		}
	})
	t.Run("proof is consumed once under concurrency", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorSystem}
		challenge := domain.Challenge{ChallengeID: "challenge-1", Purpose: "password_reset", ProofDigest: "proof-digest", EncryptedProof: "proof", ProofExpiresAt: "2026-10-17T00:00:00Z", ExpiresAt: "2026-10-17T00:00:00Z", ResendAvailableAt: "2026-10-16T00:00:00Z", State: "verified", IssueCount: 1}
		if _, err := store.InTx(ctx, scope, func(tx application.Tx) error { return tx.Challenges().Insert(ctx, challenge) }); err != nil {
			t.Fatal(err)
		}
		var winners atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := store.InTx(ctx, scope, func(tx application.Tx) error {
					used, err := tx.Challenges().ConsumeProof(ctx, challenge.ChallengeID, "proof-digest")
					if used {
						winners.Add(1)
					}
					return err
				})
				if err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("proof consumption winners = %d, want 1", winners.Load())
		}
	})
}

func checkFailedTransactionRollsBack(t *testing.T, store application.Store) {
	t.Helper()
	ctx := context.Background()
	user := domain.User{UserID: "user-1", Login: "owner@example.invalid"}
	_, err := store.InTx(ctx, application.Scope{Actor: application.ActorSystem}, func(tx application.Tx) error {
		if err := tx.Users().Insert(ctx, user); err != nil {
			return err
		}
		return errors.New("abort transaction")
	})
	if err == nil {
		t.Fatal("failed transaction committed")
	}
	if err := store.View(ctx, application.Scope{Actor: application.ActorSystem}, func(reader application.Reader) error {
		_, found, err := reader.Users().Get(ctx, user.UserID)
		if err != nil {
			return err
		}
		if found {
			t.Fatal("rolled back user is visible")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
