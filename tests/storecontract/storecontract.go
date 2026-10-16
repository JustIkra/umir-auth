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
	t.Run("mail job claim is fenced", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorSystem}
		job := domain.MailJob{JobID: "job-1", State: "queued", EncryptedPayload: "payload", AcceptedAt: "2026-10-16T00:00:00Z", NextAttemptAt: "2026-10-16T00:00:00Z"}
		if _, err := store.InTx(ctx, scope, func(tx application.Tx) error { return tx.MailJobs().Insert(ctx, job) }); err != nil {
			t.Fatal(err)
		}
		var winners atomic.Int32
		var attempt atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := store.InTx(ctx, scope, func(tx application.Tx) error {
					claimed, result, err := tx.MailJobs().Claim(ctx, job.JobID, "worker-a", "2026-10-16T00:01:00Z", "2026-10-16T00:01:15Z")
					if claimed {
						winners.Add(1)
						attempt.Store(int32(result.Attempts))
					}
					return err
				})
				if err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if winners.Load() != 1 || attempt.Load() != 1 {
			t.Fatalf("claim winners=%d attempt=%d", winners.Load(), attempt.Load())
		}
		_, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			return tx.MailJobs().Finish(ctx, job.JobID, "worker-old", 1, "delivered", "")
		})
		if !errors.Is(err, application.ErrLeaseLost) {
			t.Fatalf("stale owner finished mail job: %v", err)
		}
		_, err = store.InTx(ctx, scope, func(tx application.Tx) error {
			return tx.MailJobs().Finish(ctx, job.JobID, "worker-a", 1, "delivered", "")
		})
		if err != nil {
			t.Fatalf("current owner could not finish mail job: %v", err)
		}
	})
	t.Run("budget events use a rolling cutoff", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorSystem}
		if _, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			return tx.Budgets().Record(ctx, application.BudgetEvent{Kind: "login", KeyDigest: "digest", At: "2026-10-16T00:00:00Z"})
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.View(ctx, scope, func(reader application.Reader) error {
			count, err := reader.Budgets().CountSince(ctx, "login", "digest", "2026-10-16T00:00:00Z")
			if err != nil {
				return err
			}
			if count != 1 {
				t.Fatalf("boundary count = %d, want 1", count)
			}
			count, err = reader.Budgets().CountSince(ctx, "login", "digest", "2026-10-16T00:00:01Z")
			if err != nil {
				return err
			}
			if count != 0 {
				t.Fatalf("expired count = %d, want 0", count)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("outbox rows commit with the transaction", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorSystem}
		event := application.OutboxEvent{ID: "outbox-1", Exchange: "umir.auth", RoutingKey: "auth.restaurant.deleted", Body: []byte(`{"eventID":"event-1","schemaVersion":1,"generation":"generation-1"}`)}
		_, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			if _, err := tx.Outbox().Insert(ctx, event); err != nil {
				return err
			}
			return errors.New("abort business transaction")
		})
		if err == nil {
			t.Fatal("failed business transaction committed")
		}
		if err := store.View(ctx, scope, func(reader application.Reader) error {
			_, found, err := reader.Outbox().Get(ctx, event.ID)
			if err != nil {
				return err
			}
			if found {
				t.Fatal("outbox row survived its rolled back business transaction")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.InTx(ctx, scope, func(tx application.Tx) error { _, err := tx.Outbox().Insert(ctx, event); return err }); err != nil {
			t.Fatal(err)
		}
		if err := store.View(ctx, scope, func(reader application.Reader) error {
			_, found, err := reader.Outbox().Get(ctx, event.ID)
			if err != nil {
				return err
			}
			if !found {
				t.Fatal("committed outbox row is missing")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("lifecycle intent and tombstone are isolated", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorSystem}
		org := domain.Organization{OrgID: "org-1", Name: "Organization", Lifecycle: "deleting", LifecycleVersion: "2"}
		restaurant := domain.Restaurant{RestaurantID: "restaurant-1", OrgID: org.OrgID, Name: "Restaurant", Lifecycle: "deleting", LifecycleVersion: "2"}
		intent := domain.LifecycleIntent{OperationID: "operation-1", CommandID: "command-1", OrgID: org.OrgID, RestaurantIDs: []domain.EntityID{restaurant.RestaurantID}, Lifecycle: "deleting", LifecycleVersion: "2", Cleanup: "pending"}
		tombstone := domain.Tombstone{EntityID: restaurant.RestaurantID, Kind: "restaurant", OrgID: org.OrgID, LifecycleVersion: "2", DeletedAt: "2026-10-16T00:00:00Z"}
		if _, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			if err := tx.Organizations().Insert(ctx, org); err != nil {
				return err
			}
			if err := tx.Restaurants().Insert(ctx, restaurant); err != nil {
				return err
			}
			if err := tx.Lifecycle().InsertIntent(ctx, intent); err != nil {
				return err
			}
			return tx.Lifecycle().InsertTombstone(ctx, tombstone)
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.View(ctx, scope, func(reader application.Reader) error {
			stored, ok, err := reader.Lifecycle().Intent(ctx, intent.OperationID)
			if err != nil {
				return err
			}
			if !ok || len(stored.RestaurantIDs) != 1 {
				t.Fatal("lifecycle intent missing")
			}
			stored.RestaurantIDs[0] = "mutated"
			reloaded, ok, err := reader.Lifecycle().Intent(ctx, intent.OperationID)
			if err != nil {
				return err
			}
			if !ok || reloaded.RestaurantIDs[0] != restaurant.RestaurantID {
				t.Fatal("lifecycle intent leaked mutable slice")
			}
			deleted, ok, err := reader.Lifecycle().Tombstone(ctx, tombstone.EntityID)
			if err != nil {
				return err
			}
			if !ok || deleted != tombstone {
				t.Fatal("tombstone missing or changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("registry pages are bounded and keyset ordered", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		scope := application.Scope{Actor: application.ActorSystem}
		org := domain.Organization{OrgID: "org-1", Name: "Organization", Settings: domain.Settings{TimeZone: "Europe/Moscow", SettingsVersion: "1"}, Lifecycle: "active", LifecycleVersion: "1"}
		if _, err := store.InTx(ctx, scope, func(tx application.Tx) error {
			if err := tx.Organizations().Insert(ctx, org); err != nil {
				return err
			}
			for _, id := range []domain.EntityID{"restaurant-b", "restaurant-a"} {
				if err := tx.Restaurants().Insert(ctx, domain.Restaurant{RestaurantID: id, OrgID: org.OrgID, Name: string(id), Lifecycle: "registering", LifecycleVersion: "1"}); err != nil {
					return err
				}
			}
			_, err := tx.Registry().Touch(ctx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.View(ctx, scope, func(reader application.Reader) error {
			first, err := reader.Registry().Page(ctx, 1, "")
			if err != nil {
				return err
			}
			if first.Revision != "2" || first.Complete || first.NextAfter != "restaurant-a" || len(first.Entries) != 1 {
				t.Fatalf("unexpected first registry page: %#v", first)
			}
			second, err := reader.Registry().Page(ctx, 1, first.NextAfter)
			if err != nil {
				return err
			}
			if !second.Complete || second.NextAfter != "" || len(second.Entries) != 1 || second.Entries[0].Restaurant.RestaurantID != "restaurant-b" {
				t.Fatalf("unexpected second registry page: %#v", second)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("system transactions require a reason", func(t *testing.T) {
		store := newStore()
		ctx := context.Background()
		if _, err := store.InSystemTx(ctx, "", func(application.Tx) error { return nil }); !errors.Is(err, application.ErrInvalidScope) {
			t.Fatalf("system transaction without a reason was accepted: %v", err)
		}
		if _, err := store.InSystemTx(ctx, "auth.cleanup", func(tx application.Tx) error {
			return tx.Budgets().Record(ctx, application.BudgetEvent{Kind: "worker", KeyDigest: "digest", At: "2026-10-16T00:00:00Z"})
		}); err != nil {
			t.Fatalf("system transaction with a reason failed: %v", err)
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
