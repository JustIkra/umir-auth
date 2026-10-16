package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
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

// countingPeers counts Status calls per service and can hold every Status
// response until released, like a slow peer.
type countingPeers struct {
	application.RuntimePeers
	mu      sync.Mutex
	calls   map[string]int
	entered chan string
	release chan struct{}
}

func newCountingPeers(inner application.RuntimePeers, hold bool) *countingPeers {
	p := &countingPeers{RuntimePeers: inner, calls: map[string]int{}, entered: make(chan string, 1024)}
	if hold {
		p.release = make(chan struct{})
	}
	return p
}
func (p *countingPeers) Status(ctx context.Context, service string) (application.RuntimeStatus, error) {
	p.mu.Lock()
	p.calls[service]++
	p.mu.Unlock()
	select {
	case p.entered <- service:
	default:
	}
	if p.release != nil {
		select {
		case <-p.release:
		case <-ctx.Done():
			return application.RuntimeStatus{}, ctx.Err()
		}
	}
	return p.RuntimePeers.Status(ctx, service)
}
func (p *countingPeers) total() (n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.calls {
		n += c
	}
	return n
}
func (p *countingPeers) perService(service string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[service]
}

// countingRepo counts loads and commits of the repository under test.
type countingRepo struct {
	application.AggregateRepository
	loads, commits atomic.Int64
}

func (r *countingRepo) Load(c context.Context) (domain.ValidatedAggregate, error) {
	r.loads.Add(1)
	return r.AggregateRepository.Load(c)
}
func (r *countingRepo) Commit(c context.Context, v domain.Version, n domain.ValidatedAggregate) (application.CommitResult, error) {
	r.commits.Add(1)
	return r.AggregateRepository.Commit(c, v, n)
}

func waitForStatus(t *testing.T, p *countingPeers, services ...string) {
	t.Helper()
	pending := map[string]bool{}
	for _, s := range services {
		pending[s] = true
	}
	timeout := time.After(5 * time.Second)
	for len(pending) > 0 {
		select {
		case s := <-p.entered:
			delete(pending, s)
		case <-timeout:
			t.Fatalf("peers %v never asked for status", pending)
		}
	}
}

// Concurrent authorizations share one Status call per service (H3). The
// responses are held, so every caller is inside the observation when it ends; the
// foreground session is stale, so the first caller also changes the revision under
// the others, which used to send each of them around the whole loop again.
func TestConcurrentAuthorizationsCoalescePeerStatus(t *testing.T) {
	f, peers := lifecycleSetup(t)
	ownerClock, ok := f.opts.Clock.(*clock)
	if !ok {
		t.Fatal("fixture does not expose its injected owner clock")
	}
	if !reconcile(t, f) {
		t.Fatal("initial registration did not complete")
	}
	ownerClock.advance(10 * time.Minute)
	counting := newCountingPeers(peers, true)
	repo := &countingRepo{AggregateRepository: f.store}
	f.opts.Runtimes, f.opts.Repository = counting, repo
	resetAccounts(t, f)
	const callers = 24
	baseLoads := repo.loads.Load()
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			_, err := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.owner.Token, RestaurantID: f.r1, Operation: "inventory", Audiences: []string{"umir-warehouse"}, Activity: "foreground"})
			errs <- err
		})
	}
	waitForStatus(t, counting, "warehouse", "serving", "gateway")
	deadline := time.Now().Add(5 * time.Second)
	for repo.loads.Load()-baseLoads < callers && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	for range 10000 { // let every caller that has loaded join the held observation
		runtime.Gosched()
	}
	close(counting.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := counting.total(); n > 3 {
		t.Fatalf("%d Status calls for %d concurrent authorizations; want at most 3", n, callers)
	}
}

func TestRevisionChangeDuringPeerReadDoesNotRepeatStatus(t *testing.T) {
	f, peers := lifecycleSetup(t)
	if !reconcile(t, f) {
		t.Fatal("initial registration did not complete")
	}
	counting := newCountingPeers(peers, true)
	f.opts.Runtimes = counting
	resetAccounts(t, f)
	result := make(chan error, 1)
	go func() {
		_, err := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.owner.Token, RestaurantID: f.r1, Operation: "inventory", Audiences: []string{"umir-warehouse"}, Activity: "background"})
		result <- err
	}()
	waitForStatus(t, counting, "warehouse", "serving", "gateway")
	before := f.snapshot(t).AggregateRevision
	if err := f.accounts.Logout(ctx, f.second.Token); err != nil {
		t.Fatal(err)
	}
	if f.snapshot(t).AggregateRevision == before {
		t.Fatal("the unrelated change did not move the revision")
	}
	close(counting.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if n := counting.total(); n != 3 {
		t.Fatalf("%d Status calls after a revision change; want 3", n)
	}
}

// A pass over many ready restaurants after a peer changed its epoch asks every
// peer for status a bounded number of times and commits the readiness of one
// restaurant at most once (H5).
func TestReconciliationPassIsBoundedAfterPeerEpochChange(t *testing.T) {
	f, peers := lifecycleSetup(t)
	if !reconcile(t, f) {
		t.Fatal("initial registration did not complete")
	}
	a := f.snapshot(t)
	const restaurants = 1000
	owner := a.Memberships[0].UserID
	for i := 0; i < restaurants; i++ {
		id := uid(700000 + i)
		a.Restaurants = append(a.Restaurants, domain.Restaurant{RestaurantID: id, OrgID: f.org, Name: "Seeded", Lifecycle: "ready", LifecycleVersion: "1"})
		intent := domain.LifecycleIntent{OperationID: uid(800000 + i), CommandID: fmt.Sprintf("seed-%d", i), ActorID: owner, OrgID: f.org, RestaurantIDs: []domain.EntityID{id}, Lifecycle: "ready", LifecycleVersion: "1", Cleanup: "not_required"}
		for _, service := range []string{"warehouse", "serving", "gateway"} {
			intent.Services = append(intent.Services, domain.PeerReadiness{RestaurantID: id, Service: service, Epoch: peers.epochs[service], State: "ready", LifecycleVersion: "1"})
		}
		a.LifecycleIntents = append(a.LifecycleIntents, intent)
	}
	validated, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	repo := &countingRepo{AggregateRepository: &memoryRepo{current: validated, clock: f.opts.Clock}}
	counting := newCountingPeers(peers, false)
	f.opts.Runtimes, f.opts.Repository = counting, repo
	resetAccounts(t, f)
	if !reconcile(t, f) {
		t.Fatal("a pass over ready restaurants was not complete")
	}
	peers.mu.Lock()
	peers.epochs["warehouse"] = uid(900)
	peers.mu.Unlock()
	services := []string{"warehouse", "serving", "gateway"}
	statusBefore := map[string]int{}
	for _, service := range services {
		statusBefore[service] = counting.perService(service)
	}
	commitsBefore := repo.commits.Load()
	if !reconcile(t, f) {
		t.Fatal("the pass after the epoch change did not complete")
	}
	for _, service := range services {
		if n := counting.perService(service) - statusBefore[service]; n > 2 {
			t.Fatalf("service %s: Status called %d times in one pass; want at most 2", service, n)
		}
	}
	if n := repo.commits.Load() - commitsBefore; n > int64(len(a.Restaurants))+3 {
		t.Fatalf("%d commits for %d restaurants; want one per restaurant and a few for the pass", n, len(a.Restaurants))
	}
}
