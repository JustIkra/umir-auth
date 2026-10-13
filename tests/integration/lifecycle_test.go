package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type runtimeDouble struct {
	mu          sync.Mutex
	epochs      map[string]domain.EntityID
	unavailable map[string]bool
	fail        map[string]bool
	ack         map[string]domain.PeerReadiness
	installed   map[string]domain.EntityID
	calls       int
	hook        func(string, domain.EntityID, bool)
	corrupt     bool
}

func newRuntimeDouble() *runtimeDouble {
	return &runtimeDouble{epochs: map[string]domain.EntityID{"warehouse": uid(800), "serving": uid(801), "gateway": uid(802)}, unavailable: map[string]bool{}, fail: map[string]bool{}, ack: map[string]domain.PeerReadiness{}, installed: map[string]domain.EntityID{}}
}
func (p *runtimeDouble) Status(ctx context.Context, service string) (application.RuntimeStatus, error) {
	if err := ctx.Err(); err != nil {
		return application.RuntimeStatus{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unavailable[service] {
		return application.RuntimeStatus{}, errors.New("test unavailable")
	}
	return application.RuntimeStatus{Service: service, Epoch: p.epochs[service], Ready: true, TZDataVersion: "test-zone-data"}, nil
}
func (p *runtimeDouble) Register(ctx context.Context, service string, id domain.EntityID, in application.RegisterRuntime) (domain.PeerReadiness, error) {
	return p.apply(ctx, service, id, in.ExpectedEpoch, in.LifecycleVersion, false)
}
func (p *runtimeDouble) Close(ctx context.Context, service string, id domain.EntityID, in application.CloseRuntime) (domain.PeerReadiness, error) {
	return p.apply(ctx, service, id, in.ExpectedEpoch, in.LifecycleVersion, true)
}
func (p *runtimeDouble) apply(ctx context.Context, service string, id, epoch domain.EntityID, version domain.Version, closing bool) (domain.PeerReadiness, error) {
	if err := ctx.Err(); err != nil {
		return domain.PeerReadiness{}, err
	}
	p.mu.Lock()
	hook := p.hook
	p.mu.Unlock()
	if hook != nil {
		hook(service, id, closing)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.fail[service] || epoch != p.epochs[service] {
		return domain.PeerReadiness{}, errors.New("test peer refusal")
	}
	key := service + ":" + string(id)
	state := "ready"
	if closing {
		state = "closed"
	} else if old := p.ack[key]; old.State == "closed" && old.Epoch == epoch {
		return domain.PeerReadiness{}, errors.New("test local tombstone")
	}
	result := domain.PeerReadiness{RestaurantID: id, Service: service, Epoch: epoch, State: state, LifecycleVersion: version}
	p.ack[key] = result
	if closing {
		delete(p.installed, key)
	} else {
		p.installed[key] = epoch
	}
	if p.corrupt {
		result.RestaurantID = uid(999)
	}
	return result, nil
}
func lifecycleSetup(t *testing.T) (*membershipFixture, *runtimeDouble) {
	t.Helper()
	f, _ := a5UnreconciledSetup(t)
	p := newRuntimeDouble()
	f.opts.Runtimes = p
	resetAccounts(t, f)
	return f, p
}
func resetAccounts(t *testing.T, f *membershipFixture) {
	t.Helper()
	s, err := application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	f.accounts = s
}
func reopenLifecycle(t *testing.T, f *membershipFixture) {
	t.Helper()
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := jsonstore.Open(ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.store = r
	f.opts.Repository = r
	resetAccounts(t, f)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
}
func reconcile(t *testing.T, f *membershipFixture) bool {
	t.Helper()
	complete, err := f.accounts.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return complete
}
func createRestaurant(t *testing.T, f *membershipFixture, command string) application.LifecycleResult {
	t.Helper()
	v, err := f.accounts.CreateRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, application.CreateRestaurantInput{CommandID: command, Name: "New Restaurant"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func pollLifecycle(t *testing.T, f *membershipFixture, v application.LifecycleResult) application.LifecycleResult {
	t.Helper()
	r, err := f.accounts.Lifecycle(ctx, f.owner.Token, v.OrgID, v.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestA6CreationAtomicAcceptanceReplayAndCurrentEpoch(t *testing.T) {
	f, p := lifecycleSetup(t)
	in := application.CreateOrganizationInput{CommandID: strings.Repeat("opaque", 100), Name: "New Organization", TimeZone: "America/New_York", FirstRestaurantName: "First"}
	accepted, err := f.accounts.CreateOrganization(ctx, f.worker.Token, f.worker.CSRFToken, in)
	if err != nil {
		t.Fatal(err)
	}
	a := f.snapshot(t)
	if len(a.Organizations) != 3 || len(a.Restaurants) != 4 || len(a.Memberships) != 6 || len(a.LifecycleIntents) != 1 || len(a.Idempotency) != 1 || accepted.Lifecycle != "registering" || accepted.Cleanup != "not_required" || len(accepted.Services) != 3 {
		t.Fatal("creation was not one complete admission")
	}
	if accepted.OperationID == domain.EntityID(in.CommandID) || accepted.OperationID == accepted.OrgID {
		t.Fatal("operation identity not independent")
	}
	if !domain.IsOrgAdmin(a, f.worker.User.UserID, accepted.OrgID) {
		t.Fatal("creator admin missing")
	}
	if _, err := f.accounts.RestaurantAccess(ctx, f.worker.Token, accepted.RestaurantIDs[0]); err == nil {
		t.Fatal("partial registration admitted business")
	}
	p.fail["serving"] = true
	if reconcile(t, f) {
		t.Fatal("partial registration completed")
	}
	if _, err := f.accounts.RestaurantAccess(ctx, f.worker.Token, accepted.RestaurantIDs[0]); err == nil {
		t.Fatal("partial peer admitted business")
	}
	before := f.snapshot(t)
	reopenLifecycle(t, f)
	same, err := f.accounts.CreateOrganization(ctx, f.worker.Token, f.worker.CSRFToken, in)
	if err != nil || !reflect.DeepEqual(same, accepted) || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("restart acceptance replay changed authority")
	}
	p.fail["serving"] = false
	if !reconcile(t, f) {
		t.Fatal("reconciliation incomplete")
	}
	if _, err := f.accounts.RestaurantAccess(ctx, f.worker.Token, accepted.RestaurantIDs[0]); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.epochs["warehouse"] = uid(810)
	p.mu.Unlock()
	if _, err := f.accounts.RestaurantAccess(ctx, f.worker.Token, accepted.RestaurantIDs[0]); err == nil {
		t.Fatal("old epoch readiness authorized")
	}
	if !reconcile(t, f) {
		t.Fatal("restart not reconciled")
	}
	if _, err := f.accounts.RestaurantAccess(ctx, f.worker.Token, accepted.RestaurantIDs[0]); err != nil {
		t.Fatal(err)
	}
	same, err = f.accounts.CreateOrganization(ctx, f.worker.Token, f.worker.CSRFToken, in)
	if err != nil || !reflect.DeepEqual(same, accepted) {
		t.Fatal("ready state replaced accepted result")
	}
	in.Name = "Different"
	if _, err = f.accounts.CreateOrganization(ctx, f.worker.Token, f.worker.CSRFToken, in); !errors.Is(err, application.ErrCommandConflict) {
		t.Fatal("changed creation input did not conflict")
	}
}
func TestA6CascadeCutoffSuppressionRestartAndDeletionReplay(t *testing.T) {
	e := enrollmentSetup(t)
	p := newRuntimeDouble()
	e.opts.Runtimes = p
	resetAccounts(t, e.membershipFixture)
	if !reconcile(t, e.membershipFixture) {
		t.Fatal("initial reconciliation failed")
	}
	challenge := e.begin(t)
	code := e.code(t, challenge.ChallengeID)
	accepted, err := e.accounts.DeleteRestaurant(ctx, e.owner.Token, e.owner.CSRFToken, e.org, e.r1, "delete-once")
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Lifecycle != "deleting" || accepted.Cleanup != "pending" || accepted.LifecycleVersion != "2" {
		t.Fatal("delete not accepted separately")
	}
	a := e.snapshot(t)
	if len(a.Tombstones) != 1 || a.Invitations[0].State != "revoked" || a.MailJobs[0].State != "suppressed" || a.MailJobs[0].EncryptedPayload != "" {
		t.Fatal("cutoff or scoped outbox suppression not atomic")
	}
	if _, err = e.accounts.RestaurantAccess(ctx, e.worker.Token, e.r1); err == nil {
		t.Fatal("cutoff admitted business")
	}
	if _, err = e.accounts.RestaurantAccess(ctx, e.worker.Token, e.r3); err != nil {
		t.Fatal("neighbor/global session revoked")
	}
	if _, err = e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "verify-after-delete", ChallengeID: challenge.ChallengeID, Code: code}); err == nil {
		t.Fatal("deleted invitation accepted")
	}
	p.fail["gateway"] = true
	if reconcile(t, e.membershipFixture) {
		t.Fatal("cleanup reported complete during failure")
	}
	before := e.snapshot(t)
	e.reopen(t)
	same, err := e.accounts.DeleteRestaurant(ctx, e.owner.Token, e.owner.CSRFToken, e.org, e.r1, "delete-once")
	if err != nil || !reflect.DeepEqual(same, accepted) || !reflect.DeepEqual(before, e.snapshot(t)) {
		t.Fatal("delete replay changed original acceptance")
	}
	p.fail["gateway"] = false
	if !reconcile(t, e.membershipFixture) {
		t.Fatal("cleanup retry incomplete")
	}
	current := pollLifecycle(t, e.membershipFixture, accepted)
	if current.Lifecycle != "deleted" || current.Cleanup != "complete" {
		t.Fatal("cleanup not completed")
	}
	p.mu.Lock()
	p.epochs["gateway"] = uid(811)
	p.mu.Unlock()
	current = pollLifecycle(t, e.membershipFixture, accepted)
	if current.Lifecycle != "deleting" || current.Cleanup != "pending" {
		t.Fatal("historical closed epoch counted as complete")
	}
	if !reconcile(t, e.membershipFixture) {
		t.Fatal("tombstone not reconciled on restart")
	}
	same, err = e.accounts.DeleteRestaurant(ctx, e.owner.Token, e.owner.CSRFToken, e.org, e.r1, "delete-once")
	if err != nil || !reflect.DeepEqual(same, accepted) {
		t.Fatal("completed replay not original")
	}
	if _, err = e.accounts.Lifecycle(ctx, e.worker.Token, e.org, accepted.OperationID); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("noninitiator employee polled deleted operation")
	}
	orgDelete, err := e.accounts.DeleteOrganization(ctx, e.owner.Token, e.owner.CSRFToken, e.org, "delete-org")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.accounts.RestaurantAccess(ctx, e.worker.Token, e.r2); err == nil {
		t.Fatal("org cutoff admitted sibling")
	}
	if _, err = e.accounts.RestaurantAccess(ctx, e.worker.Token, e.r3); err != nil {
		t.Fatal("org cascade harmed neighboring scope")
	}
	if !reconcile(t, e.membershipFixture) {
		t.Fatal("org cleanup incomplete")
	}
	if pollLifecycle(t, e.membershipFixture, orgDelete).Cleanup != "complete" {
		t.Fatal("org cleanup not complete")
	}
	if _, err = e.accounts.DeleteOrganization(ctx, e.second.Token, e.second.CSRFToken, e.org, "delete-org"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("foreign actor borrowed deletion exception")
	}
	same, err = e.accounts.DeleteOrganization(ctx, e.owner.Token, e.owner.CSRFToken, e.org, "delete-org")
	if err != nil || !reflect.DeepEqual(same, orgDelete) {
		t.Fatal("global-session initiator exception missing")
	}
}
func TestA6RegisterDeleteRaceDoesNotPublishLateReadiness(t *testing.T) {
	f, p := lifecycleSetup(t)
	v := createRestaurant(t, f, "create-race")
	id := v.RestaurantIDs[0]
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	p.hook = func(service string, rid domain.EntityID, closing bool) {
		if service == "warehouse" && rid == id && !closing {
			once.Do(func() { close(entered); <-release })
		}
	}
	done := make(chan error, 1)
	go func() { _, err := f.accounts.Reconcile(ctx); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("registration not entered")
	}
	accepted, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, id, "delete-race")
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, err = f.accounts.RestaurantAccess(ctx, f.owner.Token, id); err == nil {
		t.Fatal("late register reopened access")
	}
	if !reconcile(t, f) {
		t.Fatal("race cleanup incomplete")
	}
	if pollLifecycle(t, f, accepted).Cleanup != "complete" {
		t.Fatal("race tombstone not complete")
	}
	for _, r := range f.snapshot(t).Restaurants {
		if r.RestaurantID == id && r.Lifecycle != "deleted" {
			t.Fatal("late acknowledgment replaced cutoff")
		}
	}
}
func TestA6CreationFailureUnknownRecoveryAndNoIdentityReuse(t *testing.T) {
	for _, persist := range []bool{false, true} {
		t.Run(map[bool]string{false: "definite", true: "unknown"}[persist], func(t *testing.T) {
			f, _ := lifecycleSetup(t)
			before := f.snapshot(t)
			mode := application.NotCommitted
			if persist {
				mode = application.Unknown
			}
			f.opts.Repository = &faultRepo{AggregateRepository: f.store, mode: mode, persist: persist}
			resetAccounts(t, f)
			in := application.CreateRestaurantInput{CommandID: "failure-create", Name: "New"}
			v, err := f.accounts.CreateRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, in)
			if err == nil || v.OperationID != "" {
				t.Fatal("failure fabricated acceptance")
			}
			if !persist && !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("definite failure mutated")
			}
			if persist && !errors.Is(err, application.ErrUpdateOutcomeUnknown) {
				t.Fatal("unknown misclassified")
			}
			reopenLifecycle(t, f)
			v, err = f.accounts.CreateRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, in)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.snapshot(t).LifecycleIntents) != 1 {
				t.Fatal("recovery created duplicate intent")
			}
			deleted, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, v.RestaurantIDs[0], "delete-for-reuse")
			if err != nil {
				t.Fatal(err)
			}
			f.opts.IDs = fixedID{value: deleted.RestaurantIDs[0]}
			resetAccounts(t, f)
			before = f.snapshot(t)
			if _, err = f.accounts.CreateRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, application.CreateRestaurantInput{CommandID: "recreate", Name: "Recreated"}); err == nil {
				t.Fatal("tombstoned identity reused")
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("ID collision mutated")
			}
		})
	}
}

type fixedID struct{ value domain.EntityID }

func (f fixedID) NewID() (domain.EntityID, error) { return f.value, nil }
func TestA6UnavailableAndMalformedPeerNeverGrantsReadiness(t *testing.T) {
	f, p := lifecycleSetup(t)
	v := createRestaurant(t, f, "bad-peer")
	p.corrupt = true
	if reconcile(t, f) {
		t.Fatal("wrong restaurant acknowledgment accepted")
	}
	if _, err := f.accounts.RestaurantAccess(ctx, f.owner.Token, v.RestaurantIDs[0]); err == nil {
		t.Fatal("malformed peer granted access")
	}
	p.corrupt = false
	if !reconcile(t, f) {
		t.Fatal("correct peer not reconciled")
	}
	p.unavailable["serving"] = true
	if _, err := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.owner.Token, RestaurantID: v.RestaurantIDs[0], Operation: "inventory", Audiences: []string{"umir-warehouse"}, Activity: "foreground"}); err == nil {
		t.Fatal("unavailable peer minted token")
	}
	current := pollLifecycle(t, f, v)
	for _, p := range current.Services {
		if p.Service == "serving" && (p.State != "pending" || p.Epoch != "") {
			t.Fatal("unavailable peer invented readiness")
		}
	}
}

func TestA6CompletedDeletionRestartFailureStaysPending(t *testing.T) {
	f, p := lifecycleSetup(t)
	v := createRestaurant(t, f, "complete-restart-create")
	accepted, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, v.RestaurantIDs[0], "complete-restart-delete")
	if err != nil {
		t.Fatal(err)
	}
	if !reconcile(t, f) || pollLifecycle(t, f, accepted).Cleanup != "complete" {
		t.Fatal("initial cleanup failed")
	}
	p.mu.Lock()
	p.epochs["gateway"] = uid(850)
	p.fail["gateway"] = true
	p.mu.Unlock()
	complete, err := f.accounts.Reconcile(ctx)
	if err != nil {
		t.Fatal("pending restart cleanup must be valid durable state", err)
	}
	if complete || pollLifecycle(t, f, accepted).Cleanup != "pending" {
		t.Fatal("old close claimed restart cleanup")
	}
}

func TestA6LifecycleWireOmitsInternalActor(t *testing.T) {
	f, _ := lifecycleSetup(t)
	v := createRestaurant(t, f, "wire-create")
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 8 || fields["actorID"] != nil {
		t.Fatal("LifecycleResult exposes owner-private actor metadata")
	}
}

func TestA6RegistryIsCompleteCurrentAndTombstoneBound(t *testing.T) {
	f, p := lifecycleSetup(t)
	v := createRestaurant(t, f, "registry-create")
	if !reconcile(t, f) {
		t.Fatal("registration failed")
	}
	r, err := f.accounts.Registry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete || len(r.Entries) != 4 || len(r.Tombstones) != 0 || r.RegistryRevision != f.snapshot(t).AggregateRevision {
		t.Fatal("registry omitted authoritative scope")
	}
	p.mu.Lock()
	p.epochs["serving"] = uid(860)
	p.mu.Unlock()
	r, err = f.accounts.Registry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range r.Entries {
		if e.Restaurant.RestaurantID != v.RestaurantIDs[0] {
			continue
		}
		if e.Restaurant.Lifecycle != "registering" {
			t.Fatal("registry advertises old epoch readiness")
		}
		for _, peer := range e.Services {
			if peer.Service == "serving" && (peer.Epoch != uid(860) || peer.State != "pending") {
				t.Fatal("registry did not bind current pending epoch")
			}
		}
	}
	if _, err = f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, v.RestaurantIDs[0], "registry-delete"); err != nil {
		t.Fatal(err)
	}
	r, err = f.accounts.Registry(ctx)
	if err != nil || len(r.Tombstones) != 1 || r.Tombstones[0].RestaurantID != v.RestaurantIDs[0] {
		t.Fatal("registry lost durable tombstone")
	}
	if !reconcile(t, f) {
		t.Fatal("cleanup failed")
	}
	r, err = f.accounts.Registry(ctx)
	if err != nil || len(r.Entries) != 3 || len(r.Tombstones) != 1 {
		t.Fatal("deleted runtime advertised live")
	}
}

type controlledWaiter struct {
	delays []time.Duration
	stop   context.CancelFunc
}

func (w *controlledWaiter) Wait(ctx context.Context, d time.Duration) error {
	w.delays = append(w.delays, d)
	if len(w.delays) == 8 {
		w.stop()
		return ctx.Err()
	}
	return nil
}
func TestA6WorkerBoundedBackoffAndShutdown(t *testing.T) {
	f, p := lifecycleSetup(t)
	createRestaurant(t, f, "worker-create")
	for _, service := range []string{"warehouse", "serving", "gateway"} {
		p.fail[service] = true
	}
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	w := &controlledWaiter{stop: cancel}
	if err := f.accounts.RunReconciliation(c, w); !errors.Is(err, context.Canceled) {
		t.Fatal("worker did not stop on shutdown")
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
	if !reflect.DeepEqual(w.delays, want) {
		t.Fatal("worker retry delay was unbounded or reset before completion")
	}
	before := f.snapshot(t)
	if _, err := f.accounts.Reconcile(c); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled pass ran")
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("shutdown mutated state")
	}
}
func TestA6SameEpochReconciliationRetainsReadinessAndBusinessState(t *testing.T) {
	f, p := lifecycleSetup(t)
	v := createRestaurant(t, f, "same-epoch")
	if !reconcile(t, f) {
		t.Fatal("initial reconciliation")
	}
	before := f.snapshot(t)
	p.mu.Lock()
	calls := p.calls
	p.mu.Unlock()
	if !reconcile(t, f) {
		t.Fatal("stable reconciliation")
	}
	p.mu.Lock()
	afterCalls := p.calls
	p.mu.Unlock()
	if !reflect.DeepEqual(before, f.snapshot(t)) || calls != afterCalls {
		t.Fatal("same-epoch replay reinstalled runtimes or mutated readiness")
	}
	result := pollLifecycle(t, f, v)
	result.Services[0].State = "closed"
	result.RestaurantIDs[0] = uid(999)
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("poll caller mutated durable readiness")
	}
}
func TestA6VerifiedInvitationCannotCompleteAfterCutoff(t *testing.T) {
	e := enrollmentSetup(t)
	challenge := e.begin(t)
	proof, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "verify-before-cutoff", ChallengeID: challenge.ChallengeID, Code: e.code(t, challenge.ChallengeID)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.accounts.DeleteOrganization(ctx, e.owner.Token, e.owner.CSRFToken, e.org, "verified-cutoff"); err != nil {
		t.Fatal(err)
	}
	before := e.snapshot(t)
	if _, err = e.accounts.CompleteInvitedUser(ctx, e.actor, application.InvitationCompleteInput{CommandID: "complete-after-cutoff", ChallengeID: challenge.ChallengeID, Proof: proof.Proof, Password: "synthetic-password", DisplayName: "Invited"}); err == nil {
		t.Fatal("verified proof recreated deleted membership")
	}
	if !reflect.DeepEqual(before, e.snapshot(t)) {
		t.Fatal("denied completion mutated identity")
	}
}

func TestA6EpochChangeDuringPassInvalidatesSavedAcknowledgment(t *testing.T) {
	f, p := lifecycleSetup(t)
	v := createRestaurant(t, f, "midpass-reset")
	id := v.RestaurantIDs[0]
	var once sync.Once
	p.hook = func(service string, rid domain.EntityID, closing bool) {
		if service == "gateway" && rid == id && !closing {
			once.Do(func() { p.mu.Lock(); p.epochs["warehouse"] = uid(870); p.mu.Unlock() })
		}
	}
	complete, err := f.accounts.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("pass claimed ready despite final epoch change")
	}
	for _, l := range f.snapshot(t).LifecycleIntents {
		if l.OperationID != v.OperationID {
			continue
		}
		for _, p := range l.Services {
			if p.Service == "warehouse" && (p.State != "pending" || p.Epoch != uid(870)) {
				t.Fatal("obsolete acknowledgment persisted as current")
			}
		}
	}
	if !reconcile(t, f) {
		t.Fatal("new epoch did not reconcile")
	}
}

func TestA6DeleteUnknownRecoveryRetainsCutoffAndAcceptance(t *testing.T) {
	f, _ := lifecycleSetup(t)
	v := createRestaurant(t, f, "unknown-delete-create")
	id := v.RestaurantIDs[0]
	f.opts.Repository = &faultRepo{AggregateRepository: f.store, mode: application.Unknown, persist: true}
	resetAccounts(t, f)
	got, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, id, "unknown-delete")
	if !errors.Is(err, application.ErrUpdateOutcomeUnknown) || got.OperationID != "" {
		t.Fatal("unknown deletion advertised acceptance")
	}
	if _, err = f.accounts.RestaurantAccess(ctx, f.worker.Token, f.r3); !errors.Is(err, application.ErrAuthUnavailable) {
		t.Fatal("ambiguous writer authorized another scope")
	}
	a := f.snapshot(t)
	if len(a.Tombstones) != 1 || a.Restaurants[len(a.Restaurants)-1].Lifecycle != "deleting" {
		t.Fatal("real persisted cutoff absent")
	}
	reopenLifecycle(t, f)
	before := f.snapshot(t)
	got, err = f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, id, "unknown-delete")
	if err != nil || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("recovered deletion did not replay original acceptance")
	}
	if got.OperationID != a.LifecycleIntents[len(a.LifecycleIntents)-1].OperationID {
		t.Fatal("recovery invented a new operation")
	}
	if !reconcile(t, f) {
		t.Fatal("recovered cleanup failed")
	}
	if err = f.accounts.Logout(ctx, f.owner.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, id, "unknown-delete"); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("deletion exception revived a revoked session")
	}
}
func TestA6CreationInputAndPrivilegeFailuresDoNotMutate(t *testing.T) {
	f, _ := lifecycleSetup(t)
	before := f.snapshot(t)
	for _, in := range []application.CreateOrganizationInput{
		{CommandID: "bad-zone", Name: "Organization", TimeZone: "Unknown/Zone", FirstRestaurantName: "First"},
		{CommandID: "bad-name", Name: "", TimeZone: "Europe/Moscow", FirstRestaurantName: "First"},
		{CommandID: "expiration/reserved", Name: "Organization", TimeZone: "Europe/Moscow", FirstRestaurantName: "First"},
	} {
		if _, err := f.accounts.CreateOrganization(ctx, f.worker.Token, f.worker.CSRFToken, in); err == nil {
			t.Fatal("invalid creation admitted")
		}
	}
	if _, err := f.accounts.CreateRestaurant(ctx, f.worker.Token, f.worker.CSRFToken, f.org, application.CreateRestaurantInput{CommandID: "employee-create", Name: "Forbidden"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("employee created restaurant")
	}
	if _, err := f.accounts.CreateRestaurant(ctx, f.owner.Token, "wrong-csrf", f.org, application.CreateRestaurantInput{CommandID: "csrf-create", Name: "Forbidden"}); !errors.Is(err, application.ErrInvalidCSRFToken) {
		t.Fatal("missing CSRF created restaurant")
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("refusals mutated authority")
	}
}

func TestA6OrganizationWithEarlierCutoffsPollsCurrentCleanup(t *testing.T) {
	f, p := lifecycleSetup(t)
	for n, id := range []domain.EntityID{f.r1, f.r2} {
		if _, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, id, fmt.Sprintf("prior-delete-%d", n)); err != nil {
			t.Fatal(err)
		}
	}
	if !reconcile(t, f) {
		t.Fatal("prior cleanup failed")
	}
	accepted, err := f.accounts.DeleteOrganization(ctx, f.owner.Token, f.owner.CSRFToken, f.org, "empty-cascade")
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted.RestaurantIDs) != 0 || !reconcile(t, f) || pollLifecycle(t, f, accepted).Cleanup != "complete" {
		t.Fatal("empty remaining cascade did not complete")
	}
	p.mu.Lock()
	p.epochs["gateway"] = uid(890)
	p.fail["gateway"] = true
	p.mu.Unlock()
	current := pollLifecycle(t, f, accepted)
	if current.Cleanup != "pending" || current.Lifecycle != "deleting" {
		t.Fatal("organization poll ignored prior tombstone epoch reset")
	}
	if reconcile(t, f) {
		t.Fatal("organization cleanup accepted old close")
	}
	p.mu.Lock()
	p.fail["gateway"] = false
	p.mu.Unlock()
	if !reconcile(t, f) || pollLifecycle(t, f, accepted).Cleanup != "complete" {
		t.Fatal("retained prior cutoff was not reconciled")
	}
}

func TestA6OrganizationAuthorityStaysDeletingUntilCurrentPriorCleanup(t *testing.T) {
	f, p := lifecycleSetup(t)
	for n, id := range []domain.EntityID{f.r1, f.r2} {
		if _, err := f.accounts.DeleteRestaurant(ctx, f.owner.Token, f.owner.CSRFToken, f.org, id, fmt.Sprintf("authority-prior-%d", n)); err != nil {
			t.Fatal(err)
		}
	}
	if !reconcile(t, f) {
		t.Fatal("prior cleanup failed")
	}
	p.mu.Lock()
	p.epochs["gateway"] = uid(891)
	p.fail["gateway"] = true
	p.mu.Unlock()
	accepted, err := f.accounts.DeleteOrganization(ctx, f.owner.Token, f.owner.CSRFToken, f.org, "authority-empty-cascade")
	if err != nil {
		t.Fatal(err)
	}
	if reconcile(t, f) {
		t.Fatal("pending prior peer cleanup completed")
	}
	for _, o := range f.snapshot(t).Organizations {
		if o.OrgID == f.org && o.Lifecycle != "deleting" {
			t.Fatal("organization authority advertised completion before current close")
		}
	}
	if pollLifecycle(t, f, accepted).Cleanup != "pending" {
		t.Fatal("poll hid pending cleanup")
	}
	p.mu.Lock()
	p.fail["gateway"] = false
	p.mu.Unlock()
	if !reconcile(t, f) {
		t.Fatal("cleanup did not recover")
	}
	for _, o := range f.snapshot(t).Organizations {
		if o.OrgID == f.org && o.Lifecycle != "deleted" {
			t.Fatal("organization completion not recorded")
		}
	}
}
