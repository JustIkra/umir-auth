package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/runtimehttp"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type peerStatusBarrier struct {
	application.RuntimePeers
	entered, released chan struct{}
	first             atomic.Bool
	trigger           func(string) bool
}

func (p *peerStatusBarrier) Status(ctx context.Context, service string) (application.RuntimeStatus, error) {
	if (p.trigger == nil || p.trigger(service)) && p.first.CompareAndSwap(false, true) {
		close(p.entered)
		select {
		case <-p.released:
		case <-ctx.Done():
			return application.RuntimeStatus{}, ctx.Err()
		}
	}
	return p.RuntimePeers.Status(ctx, service)
}

type httpStatusPeers struct {
	application.RuntimePeers
	status *runtimehttp.Peers
}

func (p httpStatusPeers) Status(ctx context.Context, service string) (application.RuntimeStatus, error) {
	return p.status.Status(ctx, service)
}

func slowPeerStatus(t *testing.T, f *membershipFixture, peers *runtimeDouble, trigger func(string) bool) (*peerStatusBarrier, func()) {
	t.Helper()
	gate := &peerStatusBarrier{RuntimePeers: peers, entered: make(chan struct{}), released: make(chan struct{}), trigger: trigger}
	release := sync.OnceFunc(func() { close(gate.released) })
	keys := map[string]string{"warehouse": strings.Repeat("a", 64), "serving": strings.Repeat("b", 64), "gateway": strings.Repeat("c", 64)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if r.Method != http.MethodGet || len(parts) != 5 || parts[1] != "internal" || parts[3] != "v2" || parts[4] != "runtime" || keys[parts[2]] != r.Header.Get("X-Umir-Service-Key") {
			http.Error(w, "invalid test peer request", http.StatusForbidden)
			return
		}
		status, err := gate.Status(r.Context(), parts[2])
		if err != nil {
			http.Error(w, "peer unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := json.NewEncoder(w).Encode(status); err != nil {
			return
		}
	}))
	t.Cleanup(server.Close)
	transport, err := runtimehttp.New(map[string]string{"warehouse": server.URL, "serving": server.URL, "gateway": server.URL}, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(transport.Shutdown)
	t.Cleanup(release)
	f.opts.Runtimes = httpStatusPeers{RuntimePeers: peers, status: transport}
	resetAccounts(t, f)
	return gate, release
}

func TestSlowPeerReadsDoNotBlockIndependentAccounts(t *testing.T) {
	for _, method := range []string{"access", "authorize", "registry", "lifecycle", "scheduler", "reconcile"} {
		t.Run(method, func(t *testing.T) {
			f, peers := lifecycleSetup(t)
			created := createRestaurant(t, f, "slow-peer-restaurant")
			if method != "reconcile" && !reconcile(t, f) {
				t.Fatal("initial registration did not complete")
			}
			var trigger func(string) bool
			if method == "reconcile" {
				acknowledgments := 3 * len(f.snapshot(t).Restaurants)
				trigger = func(service string) bool {
					peers.mu.Lock()
					defer peers.mu.Unlock()
					return service == "warehouse" && len(peers.ack) == acknowledgments
				}
			}
			gate, release := slowPeerStatus(t, f, peers, trigger)
			request, cancel := context.WithTimeout(ctx, 15*time.Second)
			done := make(chan struct{})
			result := make(chan error, 1)
			go func() {
				defer close(done)
				var err error
				id := created.RestaurantIDs[0]
				switch method {
				case "access":
					_, err = f.accounts.RestaurantAccess(request, f.owner.Token, id)
				case "authorize":
					_, err = f.accounts.AuthorizeToken(request, application.AuthorizationInput{SessionToken: f.owner.Token, RestaurantID: id, Operation: "inventory", Audiences: []string{"umir-warehouse"}, Activity: "background"})
				case "registry":
					_, err = f.accounts.Registry(request)
				case "lifecycle":
					_, err = f.accounts.Lifecycle(request, f.owner.Token, created.OrgID, created.OperationID)
				case "scheduler":
					_, err = f.accounts.ServiceToken(request, "gateway", "warehouse", id, uid(800), "expiry.due")
				case "reconcile":
					_, err = f.accounts.Reconcile(request)
				}
				result <- err
			}()
			t.Cleanup(func() { release(); cancel(); <-done })
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not reach the real HTTP peer barrier")
			}
			peek := make(chan error, 1)
			peekDone := make(chan struct{})
			go func() { defer close(peekDone); _, err := f.accounts.Peek(request, f.second.Token); peek <- err }()
			t.Cleanup(func() { release(); <-peekDone })
			select {
			case err := <-peek:
				if err != nil {
					t.Fatal("independent account request failed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("peer IO held the global account mutex")
			}
			release()
			if err := <-result; err != nil {
				t.Fatal("peer recovery did not finish the request", err)
			}
		})
	}
}

func TestPeerObservationCannotGrantStaleAuthority(t *testing.T) {
	for _, change := range []string{"logout", "expiry", "deletion"} {
		t.Run(change, func(t *testing.T) {
			f, peers := lifecycleSetup(t)
			ownerClock, ok := f.opts.Clock.(*clock)
			if !ok {
				t.Fatal("fixture does not expose its injected owner clock")
			}
			if !reconcile(t, f) {
				t.Fatal("initial registration did not complete")
			}
			gate, release := slowPeerStatus(t, f, peers, nil)
			request, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			result := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, err := f.accounts.AuthorizeToken(request, application.AuthorizationInput{SessionToken: f.owner.Token, RestaurantID: f.r1, Operation: "inventory", Audiences: []string{"umir-warehouse"}, Activity: "foreground"})
				result <- err
			}()
			t.Cleanup(func() { release(); cancel(); <-done })
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("authorization did not reach its peer barrier")
			}
			mutation := make(chan error, 1)
			mutationDone := make(chan struct{})
			go func() {
				defer close(mutationDone)
				var err error
				switch change {
				case "logout":
					err = f.accounts.Logout(request, f.owner.Token)
				case "expiry":
					ownerClock.advance(31 * time.Minute)
				case "deletion":
					_, err = f.accounts.DeleteRestaurant(request, f.owner.Token, f.owner.CSRFToken, f.org, f.r1, "delete-during-peer-read")
				}
				mutation <- err
			}()
			t.Cleanup(func() { release(); <-mutationDone })
			select {
			case err := <-mutation:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("peer IO blocked an authority change")
			}
			release()
			want := application.ErrUnauthenticated
			if change == "deletion" {
				want = application.ErrForbidden
			}
			if err := <-result; !errors.Is(err, want) {
				t.Fatal("stale peer observation granted stale authority", err)
			}
		})
	}
}

func TestReconciliationStopsOnAuthorityCommitFailure(t *testing.T) {
	for _, outcome := range []application.CommitOutcome{application.NotCommitted, application.Unknown} {
		t.Run(string(outcome), func(t *testing.T) {
			f, _ := lifecycleSetup(t)
			f.opts.Repository = &faultRepo{AggregateRepository: f.store, mode: outcome}
			resetAccounts(t, f)
			work, cancel := context.WithCancel(ctx)
			defer cancel()
			waiter := &controlledWaiter{stop: cancel}
			err := f.accounts.RunReconciliation(work, waiter)
			want := application.ErrStorageUnavailable
			if outcome == application.Unknown {
				want = application.ErrUpdateOutcomeUnknown
			}
			if !errors.Is(err, want) || len(waiter.delays) != 0 {
				t.Fatal("authority failure was treated as a retryable peer outage", err)
			}
		})
	}
}

func TestReconciliationDiscardsAcknowledgmentForOldSettings(t *testing.T) {
	f, peers := lifecycleSetup(t)
	created := createRestaurant(t, f, "settings-during-registration")
	changed := false
	peers.hook = func(service string, id domain.EntityID, closing bool) {
		if changed || service != "warehouse" || id != created.RestaurantIDs[0] || closing {
			return
		}
		changed = true
		if _, err := f.accounts.UpdateSettings(ctx, f.owner.Token, f.owner.CSRFToken, created.OrgID, application.UpdateSettingsInput{CommandID: "settings-during-peer-io", ExpectedSettingsVersion: "1", TimeZone: "America/New_York"}); err != nil {
			t.Fatal(err)
		}
	}
	if complete := reconcile(t, f); complete || !changed {
		t.Fatal("an acknowledgment for old settings made the restaurant ready")
	}
	if !reconcile(t, f) {
		t.Fatal("registration did not recover against the current settings")
	}
}
