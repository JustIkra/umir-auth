package application

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func (s *Accounts) DeleteRestaurant(ctx context.Context, token, csrf string, org, id domain.EntityID, command string) (LifecycleResult, error) {
	return s.deleteScope(ctx, token, csrf, org, id, command)
}
func (s *Accounts) DeleteOrganization(ctx context.Context, token, csrf string, org domain.EntityID, command string) (LifecycleResult, error) {
	return s.deleteScope(ctx, token, csrf, org, "", command)
}
func (s *Accounts) deleteScope(ctx context.Context, token, csrf string, org, id domain.EntityID, command string) (LifecycleResult, error) {
	operation := "deleteRestaurant"
	if id == "" {
		operation = "deleteOrganization"
	}
	return s.lifecycleCommand(ctx, token, csrf, operation, org, id, command, struct {
		CommandID string `json:"commandID"`
	}{command}, 202,
		func(a domain.Aggregate, u domain.User, replay *domain.LifecycleIntent) error {
			if replay != nil && replay.ActorID == u.UserID {
				return nil
			}
			if !domain.IsOrgAdmin(a, u.UserID, org) {
				return ErrForbidden
			}
			if id != "" {
				r, ok := findRestaurant(a, id)
				if !ok || r.OrgID != org {
					return ErrForbidden
				}
				if r.Lifecycle == "deleting" || r.Lifecycle == "deleted" {
					return ErrScopeDeleted
				}
			}
			return nil
		}, func(a *domain.Aggregate, u domain.User) (domain.LifecycleIntent, error) {
			ids := []domain.EntityID{}
			var version domain.Version
			for _, o := range a.Organizations {
				if o.OrgID == org {
					version = o.LifecycleVersion
				}
			}
			for _, r := range a.Restaurants {
				if r.OrgID == org && (id == "" || r.RestaurantID == id) && r.Lifecycle != "deleting" && r.Lifecycle != "deleted" {
					ids = append(ids, r.RestaurantID)
					v, _ := domain.VersionNumber(r.LifecycleVersion)
					n, _ := domain.VersionNumber(version)
					if v > n {
						version = r.LifecycleVersion
					}
				}
			}
			version, err := nextVersion(version)
			if err != nil {
				return domain.LifecycleIntent{}, err
			}
			intent, err := s.newLifecycleIntent(u.UserID, org, ids, command, version, true)
			if err != nil {
				return domain.LifecycleIntent{}, err
			}
			if id == "" {
				for i := range a.Organizations {
					if a.Organizations[i].OrgID == org {
						a.Organizations[i].Lifecycle = "deleting"
						a.Organizations[i].LifecycleVersion = version
					}
				}
				a.Tombstones = append(a.Tombstones, domain.Tombstone{EntityID: org, Kind: "organization", OrgID: org, LifecycleVersion: version, DeletedAt: formatInstant(s.opts.Clock.Now())})
			}
			for i := range a.Restaurants {
				r := &a.Restaurants[i]
				if slices.Contains(ids, r.RestaurantID) {
					r.Lifecycle = "deleting"
					r.LifecycleVersion = version
					a.Tombstones = append(a.Tombstones, domain.Tombstone{EntityID: r.RestaurantID, Kind: "restaurant", OrgID: org, LifecycleVersion: version, DeletedAt: formatInstant(s.opts.Clock.Now())})
				}
			}
			for i := range a.Memberships {
				m := &a.Memberships[i]
				if m.OrgID != org || m.State != "active" {
					continue
				}
				changed := false
				if id == "" {
					m.State = "revoked"
					changed = true
				} else {
					old := len(m.Assignments)
					m.Assignments = slices.DeleteFunc(m.Assignments, func(as domain.Assignment) bool { return slices.Contains(ids, as.RestaurantID) })
					changed = len(m.Assignments) != old
				}
				if changed {
					m.MembershipVersion, err = nextVersion(m.MembershipVersion)
					if err != nil {
						return domain.LifecycleIntent{}, err
					}
				}
			}
			for i := range a.Invitations {
				in := &a.Invitations[i]
				if in.OrgID != org || in.State != "pending" {
					continue
				}
				affected := id == ""
				for _, as := range in.Assignments {
					affected = affected || slices.Contains(ids, as.RestaurantID)
				}
				if !affected {
					continue
				}
				in.State = "revoked"
				in.Version, err = nextVersion(in.Version)
				if err != nil {
					return domain.LifecycleIntent{}, err
				}
				suppressInvitationJobs(a, in.InvitationID)
				for j := range a.Challenges {
					c := &a.Challenges[j]
					if c.InvitationID == in.InvitationID && c.State == "pending" {
						c.State = "expired"
						c.EncryptedCode = ""
					}
				}
			}
			return intent, nil
		})
}
func (s *Accounts) organizationDeletion(a domain.Aggregate, l domain.LifecycleIntent) (bool, error) {
	for _, r := range a.Idempotency {
		if r.ActorID != l.ActorID || r.OrgID != l.OrgID || r.CommandID != l.CommandID || r.OperationID != "deleteOrganization" || r.RestaurantID != "" {
			continue
		}
		if s.opts.Results == nil {
			return false, ErrAuthUnavailable
		}
		plain, err := s.opts.Results.Open(r.EncryptedResponse)
		if err != nil {
			return false, ErrAuthUnavailable
		}
		var accepted LifecycleResult
		err = json.Unmarshal(plain, &accepted)
		clear(plain)
		if err != nil || r.ResponseSchema != "LifecycleResult" || r.HTTPStatus != 202 {
			return false, ErrAuthUnavailable
		}
		return accepted.OperationID == l.OperationID, nil
	}
	return false, nil
}

func (s *Accounts) Lifecycle(ctx context.Context, token string, org, operation domain.EntityID) (LifecycleResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var observed map[string]RuntimeStatus
retry:
	for {
		if err := ctx.Err(); err != nil {
			return LifecycleResult{}, err
		}
		a, err := s.load(ctx)
		if err != nil {
			return LifecycleResult{}, err
		}
		u, _, err := active(a, token, s.opts.Clock.Now())
		if err != nil {
			return LifecycleResult{}, err
		}
		for _, l := range a.LifecycleIntents {
			if l.OperationID != operation || l.OrgID != org {
				continue
			}
			deleting := l.Cleanup != "not_required"
			if !domain.IsOrgAdmin(a, u.UserID, org) && (!deleting || l.ActorID != u.UserID) {
				return LifecycleResult{}, ErrForbidden
			}
			if !deleting {
				for _, id := range l.RestaurantIDs {
					r, ok := findRestaurant(a, id)
					if !ok || r.Lifecycle == "deleting" || r.Lifecycle == "deleted" {
						return LifecycleResult{}, ErrForbidden
					}
				}
			}
			statuses, err := s.observeRuntimeStatuses(ctx, a.AggregateRevision, &observed)
			if errors.Is(err, ErrRevisionConflict) {
				continue retry
			}
			if err != nil {
				return LifecycleResult{}, err
			}
			if _, _, err := active(a, token, s.opts.Clock.Now()); err != nil {
				return LifecycleResult{}, err
			}
			observed := observedLifecycle(l, statuses)
			organization, err := s.organizationDeletion(a, l)
			if err != nil {
				return LifecycleResult{}, err
			}
			if deleting && organization {
				for _, o := range a.Organizations {
					if o.OrgID != org || o.Lifecycle == "active" {
						continue
					}
					for _, r := range a.Restaurants {
						if r.OrgID != org {
							continue
						}
						li := latestIntent(a, r)
						closed := r.Lifecycle == "deleted" && li >= 0
						if closed {
							prior := observedLifecycle(a.LifecycleIntents[li], statuses)
							for _, p := range prior.Services {
								if p.RestaurantID == r.RestaurantID && p.State != "closed" {
									closed = false
								}
							}
						}
						if !closed {
							observed.Lifecycle = "deleting"
							observed.Cleanup = "pending"
						}
					}
				}
			}
			if err := ctx.Err(); err != nil {
				return LifecycleResult{}, err
			}
			return lifecycleView(observed), nil
		}
		return LifecycleResult{}, ErrForbidden
	}
}
