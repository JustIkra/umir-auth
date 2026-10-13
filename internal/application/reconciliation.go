package application

import (
	"context"
	"errors"
	"regexp"
	"slices"
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

func (s *Accounts) runtimeStatus(ctx context.Context, service string) (RuntimeStatus, bool) {
	if s.opts.Runtimes == nil {
		return RuntimeStatus{}, false
	}
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := s.opts.Runtimes.Status(attempt, service)
	return st, err == nil && st.Service == service && runtimeID.MatchString(string(st.Epoch)) && st.TZDataVersion != ""
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
func (s *Accounts) runtimeAccess(ctx context.Context, a domain.Aggregate, id domain.EntityID) error {
	r, ok := findRestaurant(a, id)
	if !ok || r.Lifecycle != "ready" {
		return ErrRuntimeNotReady
	}
	i := latestIntent(a, r)
	if s.opts.Runtimes == nil || i < 0 {
		return ErrRuntimeNotReady
	}
	l := a.LifecycleIntents[i]
	for _, service := range runtimeServices {
		st, ok := s.runtimeStatus(ctx, service)
		if !ok || !st.Ready {
			return ErrRuntimeNotReady
		}
		found := false
		for _, p := range l.Services {
			if p.RestaurantID == id && p.Service == service && p.State == "ready" && p.Epoch == st.Epoch && p.LifecycleVersion == r.LifecycleVersion {
				found = true
				break
			}
		}
		if !found {
			return ErrRuntimeNotReady
		}
	}
	return nil
}
func (s *Accounts) observedLifecycle(ctx context.Context, l domain.LifecycleIntent) domain.LifecycleIntent {
	complete := true
	for i := range l.Services {
		p := &l.Services[i]
		st, ok := s.runtimeStatus(ctx, p.Service)
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
	for _, r := range a.Restaurants {
		i := latestIntent(a, r)
		if i < 0 {
			complete = false
			continue
		}
		l := a.LifecycleIntents[i]
		for _, service := range runtimeServices {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			st, known := s.runtimeStatus(ctx, service)
			pending := domain.PeerReadiness{RestaurantID: r.RestaurantID, Service: service, State: "pending", LifecycleVersion: r.LifecycleVersion}
			if known {
				pending.Epoch = st.Epoch
			}
			expectedState := "ready"
			if r.Lifecycle == "deleting" || r.Lifecycle == "deleted" {
				expectedState = "closed"
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
			if err := s.recordReadiness(ctx, l.OperationID, pending); err != nil {
				return false, err
			}
			if !known {
				complete = false
				continue
			}
			current, settings, allowed, err := s.currentLifecycle(ctx, r.RestaurantID, l.OperationID, r.LifecycleVersion)
			if err != nil {
				return false, err
			}
			if !allowed {
				complete = false
				continue
			}
			attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
			var ack domain.PeerReadiness
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
			after, ok := s.runtimeStatus(ctx, service)
			if err != nil || !ok || after.Epoch != st.Epoch || ack.RestaurantID != r.RestaurantID || ack.Service != service || ack.Epoch != st.Epoch || ack.LifecycleVersion != r.LifecycleVersion || ack.State != expected {
				complete = false
				continue
			}
			if err := s.recordReadiness(ctx, l.OperationID, ack); err != nil {
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
func (s *Accounts) recordReadiness(ctx context.Context, operation domain.EntityID, peer domain.PeerReadiness) error {
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
		r, ok := findRestaurant(a, peer.RestaurantID)
		i := latestIntent(a, r)
		if !ok || i < 0 || a.LifecycleIntents[i].OperationID != operation || r.LifecycleVersion != peer.LifecycleVersion {
			return nil
		}
		l := &a.LifecycleIntents[i]
		for j := range l.Services {
			p := &l.Services[j]
			if p.RestaurantID != peer.RestaurantID || p.Service != peer.Service {
				continue
			}
			if *p == peer {
				return nil
			}
			*p = peer
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
			if err := s.commit(ctx, a); err != nil {
				if errors.Is(err, ErrRevisionConflict) {
					break
				}
				return err
			}
			return nil
		}
	}
}
func (s *Accounts) finishReconciliation(ctx context.Context) error {
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
		statuses := map[string]RuntimeStatus{}
		for _, service := range runtimeServices {
			if st, ok := s.runtimeStatus(ctx, service); ok {
				statuses[service] = st
			}
		}
		if err := ctx.Err(); err != nil {
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
