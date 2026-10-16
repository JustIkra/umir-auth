package application

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/JustIkra/umir-auth/internal/domain"
)

var ErrRuntimeNotReady = errors.New("runtime not ready")
var runtimeServices = []string{"warehouse", "serving", "gateway"}
var runtimeID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type RuntimeStatus struct {
	Service       string          `json:"service"`
	Epoch         domain.EntityID `json:"epoch"`
	Ready         bool            `json:"ready"`
	TZDataVersion string          `json:"tzdataVersion"`
}
type RegisterRuntime struct {
	OperationID      domain.EntityID `json:"operationID"`
	ExpectedEpoch    domain.EntityID `json:"expectedEpoch"`
	LifecycleVersion domain.Version  `json:"lifecycleVersion"`
	Settings         domain.Settings `json:"settings"`
}
type CloseRuntime struct {
	OperationID      domain.EntityID `json:"operationID"`
	ExpectedEpoch    domain.EntityID `json:"expectedEpoch"`
	LifecycleVersion domain.Version  `json:"lifecycleVersion"`
}
type RuntimePeers interface {
	Status(context.Context, string) (RuntimeStatus, error)
	Register(context.Context, string, domain.EntityID, RegisterRuntime) (domain.PeerReadiness, error)
	Close(context.Context, string, domain.EntityID, CloseRuntime) (domain.PeerReadiness, error)
}
type ReconciliationWaiter interface {
	Wait(context.Context, time.Duration) error
}

// statusFlight is one Status call to a peer that concurrent callers share.
type statusFlight struct {
	done chan struct{}
	st   RuntimeStatus
	ok   bool
}

// statusFlights coalesces concurrent Status calls to the same service into one.
type statusFlights struct {
	mu      sync.Mutex
	flights map[string]*statusFlight
}

// runtimeStatus asks a peer for its status. Callers that arrive while a call to
// the same service is in flight wait for it instead of starting another. The call
// runs on its own five-second deadline, detached from the first caller's
// cancellation, so one cancelled request does not fail the callers sharing it.
func (s *Accounts) runtimeStatus(ctx context.Context, service string) (RuntimeStatus, bool) {
	if s.opts.Runtimes == nil {
		return RuntimeStatus{}, false
	}
	f := &s.statusFlights
	f.mu.Lock()
	flight := f.flights[service]
	if flight == nil {
		flight = &statusFlight{done: make(chan struct{})}
		if f.flights == nil {
			f.flights = map[string]*statusFlight{}
		}
		f.flights[service] = flight
		go func() {
			attempt, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			st, err := s.opts.Runtimes.Status(attempt, service)
			flight.st = st
			flight.ok = err == nil && st.Service == service && runtimeID.MatchString(string(st.Epoch)) && st.TZDataVersion != ""
			f.mu.Lock()
			delete(f.flights, service)
			f.mu.Unlock()
			close(flight.done)
		}()
	}
	f.mu.Unlock()
	select {
	case <-flight.done:
		return flight.st, flight.ok
	case <-ctx.Done():
		return RuntimeStatus{}, false
	}
}

// runtimeStatuses asks every runtime service at once; services that do not answer
// are absent from the result.
func (s *Accounts) runtimeStatuses(ctx context.Context) map[string]RuntimeStatus {
	var mu sync.Mutex
	statuses := map[string]RuntimeStatus{}
	var wg sync.WaitGroup
	for _, service := range runtimeServices {
		wg.Go(func() {
			if st, ok := s.runtimeStatus(ctx, service); ok {
				mu.Lock()
				statuses[service] = st
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return statuses
}

// The caller holds mu. Return with it held after observing peers without it.
// *observed carries the statuses across the caller's retry loop: once peers have
// been asked, a retry after a revision change re-evaluates the freshly loaded
// aggregate against the same answers instead of asking again. ErrRevisionConflict
// means the aggregate moved during the observation; the caller reloads and
// evaluates again.
func (s *Accounts) observeRuntimeStatuses(ctx context.Context, revision domain.Version, observed *map[string]RuntimeStatus) (map[string]RuntimeStatus, error) {
	if *observed != nil {
		return *observed, nil
	}
	s.mu.Unlock()
	statuses := s.runtimeStatuses(ctx)
	s.mu.Lock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*observed = statuses
	current, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	if current.AggregateRevision != revision {
		return nil, ErrRevisionConflict
	}
	return statuses, nil
}

func latestIntent(a domain.Aggregate, r domain.Restaurant) int {
	for i := len(a.LifecycleIntents) - 1; i >= 0; i-- {
		l := a.LifecycleIntents[i]
		if l.LifecycleVersion == r.LifecycleVersion && slices.Contains(l.RestaurantIDs, r.RestaurantID) {
			return i
		}
	}
	return -1
}
func (s *Accounts) runtimeAccess(ctx context.Context, a domain.Aggregate, id domain.EntityID, observed *map[string]RuntimeStatus) (map[string]RuntimeStatus, error) {
	r, ok := findRestaurant(a, id)
	if !ok || r.Lifecycle != "ready" {
		return nil, ErrRuntimeNotReady
	}
	i := latestIntent(a, r)
	if s.opts.Runtimes == nil || i < 0 {
		return nil, ErrRuntimeNotReady
	}
	l := a.LifecycleIntents[i]
	statuses, err := s.observeRuntimeStatuses(ctx, a.AggregateRevision, observed)
	if err != nil {
		return nil, err
	}
	for _, service := range runtimeServices {
		st, ok := statuses[service]
		if !ok || !st.Ready {
			return nil, ErrRuntimeNotReady
		}
		found := false
		for _, p := range l.Services {
			if p.RestaurantID == id && p.Service == service && p.State == "ready" && p.Epoch == st.Epoch && p.LifecycleVersion == r.LifecycleVersion {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrRuntimeNotReady
		}
	}
	return statuses, nil
}
func observedLifecycle(l domain.LifecycleIntent, statuses map[string]RuntimeStatus) domain.LifecycleIntent {
	l.Services = slices.Clone(l.Services)
	complete := true
	for i := range l.Services {
		p := &l.Services[i]
		st, ok := statuses[p.Service]
		if !ok {
			p.State = "pending"
			p.Epoch = ""
		} else if p.Epoch != st.Epoch || p.State == "ready" && !st.Ready {
			p.State = "pending"
			p.Epoch = st.Epoch
		}
		complete = complete && p.State != "pending"
	}
	if !complete {
		if l.Cleanup == "not_required" {
			l.Lifecycle = "registering"
		} else {
			l.Lifecycle = "deleting"
			l.Cleanup = "pending"
		}
	}
	return l
}
func (s *Accounts) Reconcile(ctx context.Context) (bool, error) {
	select {
	case s.reconciling <- struct{}{}:
		defer func() { <-s.reconciling }()
	case <-ctx.Done():
		return false, ctx.Err()
	}
	if s.opts.Runtimes == nil {
		return false, ErrRuntimeNotReady
	}
	if err := s.prepareReconciliation(ctx); err != nil {
		return false, err
	}
	s.mu.Lock()
	a, err := s.load(ctx)
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	complete := true
	// One Status per service for the whole pass; the final observation in
	// finishReconciliation catches a peer that restarted meanwhile.
	statuses := s.runtimeStatuses(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	for _, r := range a.Restaurants {
		i := latestIntent(a, r)
		if i < 0 {
			complete = false
			continue
		}
		l := a.LifecycleIntents[i]
		expectedState := "ready"
		if r.Lifecycle == "deleting" || r.Lifecycle == "deleted" {
			expectedState = "closed"
		}
		var updates []readinessUpdate
		var current domain.Restaurant
		var settings domain.Settings
		allowed, loaded := false, false
		for _, service := range runtimeServices {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			st, known := statuses[service]
			pending := domain.PeerReadiness{RestaurantID: r.RestaurantID, Service: service, State: "pending", LifecycleVersion: r.LifecycleVersion}
			if known {
				pending.Epoch = st.Epoch
			}
			already := false
			for _, old := range l.Services {
				if known && old.RestaurantID == r.RestaurantID && old.Service == service && old.Epoch == st.Epoch && old.State == expectedState {
					already = true
				}
			}
			if already {
				continue
			}
			updates = append(updates, readinessUpdate{peer: pending})
			if !known {
				complete = false
				continue
			}
			if !loaded {
				var err error
				current, settings, allowed, err = s.currentLifecycle(ctx, r.RestaurantID, l.OperationID, r.LifecycleVersion)
				if err != nil {
					return false, err
				}
				loaded = true
			}
			if !allowed {
				complete = false
				continue
			}
			attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
			var ack domain.PeerReadiness
			var err error
			if current.Lifecycle == "deleting" || current.Lifecycle == "deleted" {
				ack, err = s.opts.Runtimes.Close(attempt, service, r.RestaurantID, CloseRuntime{OperationID: l.OperationID, ExpectedEpoch: st.Epoch, LifecycleVersion: r.LifecycleVersion})
			} else {
				ack, err = s.opts.Runtimes.Register(attempt, service, r.RestaurantID, RegisterRuntime{OperationID: l.OperationID, ExpectedEpoch: st.Epoch, LifecycleVersion: r.LifecycleVersion, Settings: settings})
			}
			cancel()
			expected := "ready"
			if current.Lifecycle == "deleting" || current.Lifecycle == "deleted" {
				expected = "closed"
			}
			if err != nil || ack.RestaurantID != r.RestaurantID || ack.Service != service || ack.Epoch != st.Epoch || ack.LifecycleVersion != r.LifecycleVersion || ack.State != expected {
				complete = false
				continue
			}
			updates[len(updates)-1] = readinessUpdate{peer: ack, settings: &settings}
		}
		if len(updates) > 0 {
			if err := s.recordReadiness(ctx, l.OperationID, updates); err != nil {
				return false, err
			}
		}
	}
	if err := s.finishReconciliation(ctx); err != nil {
		return false, err
	}
	s.mu.Lock()
	final, err := s.load(ctx)
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	for _, r := range final.Restaurants {
		li := latestIntent(final, r)
		if li < 0 || r.Lifecycle == "registering" || r.Lifecycle == "deleting" {
			complete = false
			continue
		}
		for _, p := range final.LifecycleIntents[li].Services {
			if p.RestaurantID == r.RestaurantID && p.State == "pending" {
				complete = false
			}
		}
	}
	return complete, nil
}
func (s *Accounts) currentLifecycle(ctx context.Context, id, operation domain.EntityID, version domain.Version) (domain.Restaurant, domain.Settings, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.load(ctx)
	if err != nil {
		return domain.Restaurant{}, domain.Settings{}, false, err
	}
	r, ok := findRestaurant(a, id)
	i := latestIntent(a, r)
	if !ok || i < 0 || a.LifecycleIntents[i].OperationID != operation || r.LifecycleVersion != version {
		return r, domain.Settings{}, false, nil
	}
	for _, o := range a.Organizations {
		if o.OrgID == r.OrgID {
			return r, o.Settings, true, nil
		}
	}
	return r, domain.Settings{}, false, ErrAuthUnavailable
}
func (s *Accounts) prepareReconciliation(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a, err := s.load(ctx)
		if err != nil {
			return err
		}
		changed := false
		for i := range a.Restaurants {
			r := &a.Restaurants[i]
			if latestIntent(a, *r) >= 0 {
				continue
			}
			if r.Lifecycle == "deleting" || r.Lifecycle == "deleted" {
				return ErrAuthUnavailable
			}
			var actor domain.EntityID
			for _, m := range a.Memberships {
				if domain.IsOrgAdmin(a, m.UserID, r.OrgID) {
					actor = m.UserID
					break
				}
			}
			if actor == "" {
				return ErrAuthUnavailable
			}
			l, err := s.newLifecycleIntent(actor, r.OrgID, []domain.EntityID{r.RestaurantID}, "reconcile/"+string(r.RestaurantID), r.LifecycleVersion, false)
			if err != nil {
				return err
			}
			a.LifecycleIntents = append(a.LifecycleIntents, l)
			r.Lifecycle = "registering"
			changed = true
		}
		if !changed {
			return nil
		}
		if err := s.commit(ctx, a); err != nil {
			if errors.Is(err, ErrRevisionConflict) {
				continue
			}
			return err
		}
		return nil
	}
}

// readinessUpdate is one peer state to record. A non-nil settings means an
// acknowledgment that is only valid while the organization still has them.
type readinessUpdate struct {
	peer     domain.PeerReadiness
	settings *domain.Settings
}

// recordReadiness records the updates of one restaurant in a single commit. An
// update whose restaurant, lifecycle version, intent or settings changed since it
// was observed is dropped.
func (s *Accounts) recordReadiness(ctx context.Context, operation domain.EntityID, updates []readinessUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a, err := s.load(ctx)
		if err != nil {
			return err
		}
		changed := false
		for _, u := range updates {
			peer := u.peer
			r, ok := findRestaurant(a, peer.RestaurantID)
			i := latestIntent(a, r)
			if !ok || i < 0 || a.LifecycleIntents[i].OperationID != operation || r.LifecycleVersion != peer.LifecycleVersion {
				continue
			}
			if u.settings != nil {
				current := false
				for _, org := range a.Organizations {
					if org.OrgID == r.OrgID && org.Settings == *u.settings {
						current = true
						break
					}
				}
				if !current {
					continue
				}
			}
			l := &a.LifecycleIntents[i]
			for j := range l.Services {
				p := &l.Services[j]
				if p.RestaurantID != peer.RestaurantID || p.Service != peer.Service {
					continue
				}
				if *p == peer {
					break
				}
				*p = peer
				changed = true
				if peer.State == "pending" {
					if l.Cleanup == "not_required" {
						l.Lifecycle = "registering"
						for n := range a.Restaurants {
							if a.Restaurants[n].RestaurantID == peer.RestaurantID && a.Restaurants[n].Lifecycle == "ready" {
								a.Restaurants[n].Lifecycle = "registering"
							}
						}
					} else {
						l.Lifecycle = "deleting"
						l.Cleanup = "pending"
					}
				}
				break
			}
		}
		if !changed {
			return nil
		}
		if err := s.commit(ctx, a); err != nil {
			if errors.Is(err, ErrRevisionConflict) {
				continue
			}
			return err
		}
		return nil
	}
}
func (s *Accounts) finishReconciliation(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var observed map[string]RuntimeStatus
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a, err := s.load(ctx)
		if err != nil {
			return err
		}
		changed := false
		statuses, err := s.observeRuntimeStatuses(ctx, a.AggregateRevision, &observed)
		if errors.Is(err, ErrRevisionConflict) {
			continue
		}
		if err != nil {
			return err
		}
		for i := range a.Restaurants {
			r := &a.Restaurants[i]
			li := latestIntent(a, *r)
			if li < 0 {
				continue
			}
			l := &a.LifecycleIntents[li]
			complete := true
			expected := "ready"
			if r.Lifecycle == "deleting" || r.Lifecycle == "deleted" {
				expected = "closed"
			}
			for j := range l.Services {
				p := &l.Services[j]
				if p.RestaurantID != r.RestaurantID {
					continue
				}
				st, ok := statuses[p.Service]
				if !ok || st.Epoch != p.Epoch || expected == "ready" && !st.Ready {
					pending := *p
					pending.State = "pending"
					pending.Epoch = ""
					if ok {
						pending.Epoch = st.Epoch
					}
					if *p != pending {
						*p = pending
						changed = true
					}
				}
				if p.State != expected {
					complete = false
				}
			}
			if !complete {
				state := "registering"
				cleanup := "not_required"
				if expected == "closed" {
					state = "deleting"
					cleanup = "pending"
				}
				if l.Lifecycle != state || l.Cleanup != cleanup {
					l.Lifecycle = state
					l.Cleanup = cleanup
					changed = true
				}
				if expected == "ready" && r.Lifecycle == "ready" {
					r.Lifecycle = "registering"
					changed = true
				}
			}
			if complete {
				state := "ready"
				if expected == "closed" {
					state = "deleted"
				}
				if r.Lifecycle != state {
					r.Lifecycle = state
					changed = true
				}
			}
		}
		for i := range a.LifecycleIntents {
			l := &a.LifecycleIntents[i]
			all := true
			current := false
			for _, id := range l.RestaurantIDs {
				r, ok := findRestaurant(a, id)
				li := latestIntent(a, r)
				if !ok || li != i {
					all = false
					continue
				}
				current = true
				all = all && (r.Lifecycle == "ready" || r.Lifecycle == "deleted")
				for _, p := range l.Services {
					if p.RestaurantID == id && p.State == "pending" {
						all = false
					}
				}
			}
			if !current && len(l.RestaurantIDs) > 0 {
				continue
			}
			if l.Cleanup == "not_required" {
				if all && l.Lifecycle != "ready" {
					l.Lifecycle = "ready"
					changed = true
				}
				continue
			}
			organization, err := s.organizationDeletion(a, *l)
			if err != nil {
				return err
			}
			for _, o := range a.Organizations {
				if o.OrgID != l.OrgID || o.Lifecycle == "active" || !organization {
					continue
				}
				for _, r := range a.Restaurants {
					if r.OrgID == o.OrgID && !scopeClosed(a, r) {
						all = false
					}
				}
			}
			if all && (l.Lifecycle != "deleted" || l.Cleanup != "complete") {
				l.Lifecycle = "deleted"
				l.Cleanup = "complete"
				changed = true
			}
		}
		for i := range a.Organizations {
			o := &a.Organizations[i]
			if o.Lifecycle != "deleting" {
				continue
			}
			all := true
			for _, r := range a.Restaurants {
				if r.OrgID == o.OrgID && !scopeClosed(a, r) {
					all = false
				}
			}
			if all {
				o.Lifecycle = "deleted"
				changed = true
			}
		}
		if !changed {
			return nil
		}
		if err := s.commit(ctx, a); err != nil {
			if errors.Is(err, ErrRevisionConflict) {
				continue
			}
			return err
		}
		return nil
	}
}
func scopeClosed(a domain.Aggregate, r domain.Restaurant) bool {
	if r.Lifecycle != "deleted" {
		return false
	}
	li := latestIntent(a, r)
	if li < 0 {
		return false
	}
	for _, p := range a.LifecycleIntents[li].Services {
		if p.RestaurantID == r.RestaurantID && p.State != "closed" {
			return false
		}
	}
	return true
}
func (s *Accounts) RunReconciliation(ctx context.Context, waiter ReconciliationWaiter) error {
	if waiter == nil {
		return ErrAuthUnavailable
	}
	delays := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	attempt := 0
	for {
		complete, err := s.Reconcile(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil && !errors.Is(err, ErrRuntimeNotReady) {
			return err
		}
		delay := time.Second
		if err != nil || !complete {
			delay = delays[attempt]
			if attempt < len(delays)-1 {
				attempt++
			}
		} else {
			attempt = 0
		}
		if err := waiter.Wait(ctx, delay); err != nil {
			return err
		}
	}
}
