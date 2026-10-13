package integration_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestA6ReviewMissingProviderCannotAuthorizeMigratedScope(t *testing.T) {
	f, _ := lifecycleSetup(t)
	f.opts.Runtimes = nil
	resetAccounts(t, f)
	if _, err := f.accounts.RestaurantAccess(ctx, f.owner.Token, f.r1); !errors.Is(err, application.ErrRuntimeNotReady) {
		t.Errorf("migrated ready Restaurant access without any peer provider: got %v, want RuntimeNotReady", err)
	}
	result, err := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.owner.Token, RestaurantID: f.r1, Operation: "inventory", Audiences: []string{"umir-warehouse"}, Activity: "foreground"})
	if err == nil || result.Token != "" {
		t.Errorf("minted business JWT without current epoch acknowledgments: error=%v tokenIssued=%t", err, result.Token != "")
	}
}

func TestA6ReviewRestaurantCleanupRemainsIndependentOfLaterOrgCascade(t *testing.T) {
	f, p := lifecycleSetup(t)
	prior, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.r1, "review-prior-delete")
	if err != nil {
		t.Fatal(err)
	}
	if !reconcile(t, f) || pollLifecycle(t, f, prior).Cleanup != "complete" {
		t.Fatal("prior cleanup failed")
	}
	p.mu.Lock()
	p.hook = func(service string, id domain.EntityID, closing bool) {
		if closing && id == f.r2 {
			p.mu.Lock()
			p.fail[service] = true
			p.mu.Unlock()
		}
	}
	p.mu.Unlock()
	later, err := f.accounts.DeleteOrganization(ctx, f.owner.Token, f.owner.CSRFToken, f.org, "review-org-delete")
	if err != nil {
		t.Fatal(err)
	}
	if reconcile(t, f) {
		t.Fatal("later cascade should remain pending")
	}
	if pollLifecycle(t, f, later).Cleanup != "pending" {
		t.Fatal("later cascade did not remain pending")
	}
	current := pollLifecycle(t, f, prior)
	for _, peer := range current.Services {
		if peer.State != "closed" {
			t.Fatalf("prior operation's own current peers not closed: %+v", peer)
		}
	}
	if current.Cleanup != "complete" || current.Lifecycle != "deleted" {
		t.Errorf("earlier completed Restaurant operation became %s/%s solely due to unrelated Restaurant cleanup", current.Lifecycle, current.Cleanup)
	}
	replay, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.r1, "review-prior-delete")
	if err != nil || !reflect.DeepEqual(replay, prior) {
		t.Fatal("original accepted replay changed", err)
	}
}

func TestA6ReviewPendingRestaurantCompletesWithoutSiblingCleanup(t *testing.T) {
	f, p := lifecycleSetup(t)
	prior, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.r1, "review-pending-prior")
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.hook = func(service string, id domain.EntityID, closing bool) {
		if closing && id == f.r2 {
			p.mu.Lock()
			p.fail[service] = true
			p.mu.Unlock()
		}
	}
	p.mu.Unlock()
	if _, err = f.accounts.DeleteOrganization(ctx, f.owner.Token, f.owner.CSRFToken, f.org, "review-pending-org"); err != nil {
		t.Fatal(err)
	}
	if reconcile(t, f) {
		t.Fatal("Organization cascade unexpectedly complete")
	}
	for _, l := range f.snapshot(t).LifecycleIntents {
		if l.OperationID != prior.OperationID {
			continue
		}
		for _, peer := range l.Services {
			if peer.State != "closed" {
				t.Fatal("prior operation has unclosed own peer")
			}
		}
		if l.Cleanup != "complete" || l.Lifecycle != "deleted" {
			t.Errorf("prior Restaurant all-current-closed operation remains durably %s/%s because sibling cleanup failed", l.Lifecycle, l.Cleanup)
		}
	}
}

func readyMembershipRuntimes(t *testing.T, f *membershipFixture) {
	t.Helper()
	f.opts.Runtimes = newRuntimeDouble()
	resetAccounts(t, f)
	if !reconcile(t, f) {
		t.Fatal("test membership runtimes did not reconcile")
	}
}

func TestA6RepairScopeIdentitySurvivesSharedCommandVersionAndRestart(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "completed"}[completed], func(t *testing.T) {
			f, p := lifecycleSetup(t)
			prior, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.r1, "shared-delete")
			if err != nil {
				t.Fatal(err)
			}
			if completed && !reconcile(t, f) {
				t.Fatal("prior cleanup failed")
			}
			p.mu.Lock()
			p.hook = func(service string, id domain.EntityID, closing bool) {
				if closing && id == f.r2 {
					p.mu.Lock()
					p.fail[service] = true
					p.mu.Unlock()
				}
			}
			p.mu.Unlock()
			later, err := f.accounts.DeleteOrganization(ctx, f.owner.Token, f.owner.CSRFToken, f.org, "shared-delete")
			if err != nil {
				t.Fatal(err)
			}
			if prior.LifecycleVersion != later.LifecycleVersion || prior.OperationID == later.OperationID {
				t.Fatal("test did not exercise shared command and cutoff version with distinct operations")
			}
			if reconcile(t, f) {
				t.Fatal("sibling failure did not hold Organization cleanup")
			}
			reopenLifecycle(t, f)
			current := pollLifecycle(t, f, prior)
			if current.Cleanup != "complete" || current.Lifecycle != "deleted" || !reflect.DeepEqual(current.RestaurantIDs, prior.RestaurantIDs) {
				t.Fatal("Restaurant completion or immutable scope lost after reopen", current)
			}
			for _, l := range f.snapshot(t).LifecycleIntents {
				if l.OperationID == prior.OperationID && (l.Cleanup != "complete" || l.Lifecycle != "deleted") {
					t.Fatal("Restaurant completion was not durable")
				}
			}
			if pollLifecycle(t, f, later).Cleanup != "pending" {
				t.Fatal("Organization did not retain sibling dependency")
			}
			replay, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.r1, "shared-delete")
			if err != nil || !reflect.DeepEqual(replay, prior) {
				t.Fatal("immutable Restaurant acceptance changed", err)
			}
			p.mu.Lock()
			p.hook = nil
			p.fail = map[string]bool{}
			p.mu.Unlock()
			if !reconcile(t, f) || pollLifecycle(t, f, later).Cleanup != "complete" {
				t.Fatal("Organization failed to complete after all own and earlier peers closed")
			}
		})
	}
}

func TestA6RepairMigratedAdmissionRequiresCurrentIntentAndProvider(t *testing.T) {
	f, p := lifecycleSetup(t)
	in := application.AuthorizationInput{SessionToken: f.owner.Token, RestaurantID: f.r1, Operation: "inventory", Audiences: []string{"umir-warehouse"}, Activity: "foreground"}
	deny := func() {
		t.Helper()
		before := f.snapshot(t)
		if _, err := f.accounts.RestaurantAccess(ctx, f.owner.Token, f.r1); !errors.Is(err, application.ErrRuntimeNotReady) {
			t.Fatal("unreconciled Restaurant admitted", err)
		}
		result, err := f.accounts.AuthorizeToken(ctx, in)
		if !errors.Is(err, application.ErrRuntimeNotReady) || result.Token != "" || !reflect.DeepEqual(before, f.snapshot(t)) {
			t.Fatal("unready admission issued a token or changed durable state", err)
		}
	}
	deny()
	if !reconcile(t, f) {
		t.Fatal("migration did not reconcile")
	}
	if result, err := f.accounts.AuthorizeToken(ctx, in); err != nil || result.Token == "" {
		t.Fatal("current reconciled peers failed admission", err)
	}
	p.mu.Lock()
	p.epochs["warehouse"] = uid(980)
	p.mu.Unlock()
	deny()
	if !reconcile(t, f) {
		t.Fatal("new epoch did not reconcile")
	}
	f.opts.Runtimes = nil
	resetAccounts(t, f)
	deny()
}
