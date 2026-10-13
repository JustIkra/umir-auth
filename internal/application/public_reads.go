package application

import (
	"context"

	"github.com/JustIkra/umir-auth/internal/domain"
)

type AccessView struct {
	Organizations []domain.Organization `json:"organizations"`
	Restaurants   []domain.Restaurant   `json:"restaurants"`
	Memberships   []domain.Membership   `json:"memberships"`
}

func (s *Accounts) Ready(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, e := s.load(ctx)
	if e != nil {
		return e
	}
	if s.opts.TimeZones == nil || s.opts.Issuer == nil || s.opts.Challenges == nil || s.opts.Results == nil {
		return ErrAuthUnavailable
	}
	_, e = s.opts.TimeZones.Ready()
	return e
}
func (s *Accounts) Access(ctx context.Context, token string) (AccessView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, e := s.load(ctx)
	if e != nil {
		return AccessView{}, e
	}
	u, _, e := active(a, token, s.opts.Clock.Now())
	if e != nil {
		return AccessView{}, e
	}
	v := AccessView{Organizations: []domain.Organization{}, Restaurants: []domain.Restaurant{}, Memberships: []domain.Membership{}}
	orgs := map[domain.EntityID]bool{}
	for _, m := range a.Memberships {
		if m.UserID == u.UserID && m.State == "active" {
			v.Memberships = append(v.Memberships, m)
			orgs[m.OrgID] = true
		}
	}
	for _, o := range a.Organizations {
		if orgs[o.OrgID] && o.Lifecycle == "active" {
			v.Organizations = append(v.Organizations, o)
		}
	}
	for _, r := range a.Restaurants {
		if orgs[r.OrgID] && r.Lifecycle != "deleting" && r.Lifecycle != "deleted" {
			for _, m := range v.Memberships {
				if m.OrgID != r.OrgID {
					continue
				}
				admin := false
				for _, role := range m.OrgRoles {
					admin = admin || role == "Admin"
				}
				assigned := false
				for _, as := range m.Assignments {
					assigned = assigned || as.RestaurantID == r.RestaurantID
				}
				if admin || assigned {
					v.Restaurants = append(v.Restaurants, r)
					break
				}
			}
		}
	}
	if len(v.Organizations) > 500 || len(v.Restaurants) > 500 || len(v.Memberships) > 500 {
		return AccessView{}, ErrAuthUnavailable
	}
	return v, nil
}
func (s *Accounts) Organization(ctx context.Context, token string, id domain.EntityID) (domain.Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, e := s.load(ctx)
	if e != nil {
		return domain.Organization{}, e
	}
	u, _, e := active(a, token, s.opts.Clock.Now())
	if e != nil {
		return domain.Organization{}, e
	}
	if !domain.IsOrgAdmin(a, u.UserID, id) {
		return domain.Organization{}, ErrForbidden
	}
	for _, o := range a.Organizations {
		if o.OrgID == id {
			return o, nil
		}
	}
	return domain.Organization{}, ErrForbidden
}
func (s *Accounts) Acknowledge(ctx context.Context, service string, peer domain.PeerReadiness) (domain.PeerReadiness, error) {
	if peer.Service != service {
		return domain.PeerReadiness{}, ErrForbidden
	}
	status, ok := s.runtimeStatus(ctx, service)
	if !ok || status.Epoch != peer.Epoch {
		return domain.PeerReadiness{}, ErrRuntimeNotReady
	}
	s.mu.Lock()
	a, e := s.load(ctx)
	if e != nil {
		s.mu.Unlock()
		return domain.PeerReadiness{}, e
	}
	r, ok := findRestaurant(a, peer.RestaurantID)
	li := latestIntent(a, r)
	if !ok || li < 0 || r.LifecycleVersion != peer.LifecycleVersion {
		s.mu.Unlock()
		return domain.PeerReadiness{}, ErrForbidden
	}
	want := "ready"
	if r.Lifecycle == "deleted" || r.Lifecycle == "deleting" {
		want = "closed"
	}
	op := a.LifecycleIntents[li].OperationID
	s.mu.Unlock()
	if peer.State != want || peer.State == "ready" && !status.Ready {
		return domain.PeerReadiness{}, ErrForbidden
	}
	if e = s.recordReadiness(ctx, op, peer); e != nil {
		return domain.PeerReadiness{}, e
	}
	return peer, nil
}
