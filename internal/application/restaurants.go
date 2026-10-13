package application

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/domain"
)

var ErrScopeDeleted = errors.New("scope deleted")

type LifecycleResult struct {
	OperationID      domain.EntityID        `json:"operationID"`
	CommandID        string                 `json:"commandID"`
	OrgID            domain.EntityID        `json:"orgID"`
	RestaurantIDs    []domain.EntityID      `json:"restaurantIDs"`
	Lifecycle        string                 `json:"lifecycle"`
	LifecycleVersion domain.Version         `json:"lifecycleVersion"`
	Cleanup          string                 `json:"cleanup"`
	Services         []domain.PeerReadiness `json:"services"`
}

func lifecycleView(l domain.LifecycleIntent) LifecycleResult {
	return LifecycleResult{OperationID: l.OperationID, CommandID: l.CommandID, OrgID: l.OrgID, RestaurantIDs: l.RestaurantIDs, Lifecycle: l.Lifecycle, LifecycleVersion: l.LifecycleVersion, Cleanup: l.Cleanup, Services: l.Services}
}

type CreateOrganizationInput struct {
	CommandID           string `json:"commandID"`
	Name                string `json:"name"`
	TimeZone            string `json:"timeZone"`
	FirstRestaurantName string `json:"firstRestaurantName"`
}
type CreateRestaurantInput struct {
	CommandID string `json:"commandID"`
	Name      string `json:"name"`
}

func validScopeName(s string) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) >= 1 && utf8.RuneCountInString(s) <= 100 && !strings.ContainsAny(s, "\x00\r\n")
}
func (s *Accounts) CreateOrganization(ctx context.Context, token, csrf string, in CreateOrganizationInput) (LifecycleResult, error) {
	return s.lifecycleCommand(ctx, token, csrf, "createOrganization", "", "", in.CommandID, in, 201,
		func(a domain.Aggregate, u domain.User, old *domain.LifecycleIntent) error {
			if old != nil && !domain.IsOrgAdmin(a, u.UserID, old.OrgID) {
				return ErrForbidden
			}
			return nil
		}, func(a *domain.Aggregate, u domain.User) (domain.LifecycleIntent, error) {
			if len(a.Restaurants) >= 10000 {
				return domain.LifecycleIntent{}, ErrAuthUnavailable
			}
			if !validScopeName(in.Name) || !validScopeName(in.FirstRestaurantName) {
				return domain.LifecycleIntent{}, &FieldError{Field: "name", Code: "InvalidFormat"}
			}
			if err := s.validateZone(in.TimeZone); err != nil {
				return domain.LifecycleIntent{}, err
			}
			org, err := s.newEnrollmentID()
			if err != nil {
				return domain.LifecycleIntent{}, err
			}
			rid, err := s.newEnrollmentID()
			if err != nil {
				return domain.LifecycleIntent{}, err
			}
			mid, err := s.newEnrollmentID()
			if err != nil {
				return domain.LifecycleIntent{}, err
			}
			a.Organizations = append(a.Organizations, domain.Organization{OrgID: org, Name: in.Name, Settings: domain.Settings{TimeZone: in.TimeZone, SettingsVersion: "1"}, Lifecycle: "active", LifecycleVersion: "1"})
			a.Restaurants = append(a.Restaurants, domain.Restaurant{RestaurantID: rid, OrgID: org, Name: in.FirstRestaurantName, Lifecycle: "registering", LifecycleVersion: "1"})
			a.Memberships = append(a.Memberships, domain.Membership{MembershipID: mid, MembershipVersion: "1", UserID: u.UserID, OrgID: org, OrgRoles: []string{"Admin"}, Assignments: []domain.Assignment{}, State: "active"})
			return s.newLifecycleIntent(u.UserID, org, []domain.EntityID{rid}, in.CommandID, "1", false)
		})
}
func (s *Accounts) CreateRestaurant(ctx context.Context, token, csrf string, org domain.EntityID, in CreateRestaurantInput) (LifecycleResult, error) {
	return s.lifecycleCommand(ctx, token, csrf, "createRestaurant", org, "", in.CommandID, in, 201,
		func(a domain.Aggregate, u domain.User, old *domain.LifecycleIntent) error {
			if !domain.IsOrgAdmin(a, u.UserID, org) {
				return ErrForbidden
			}
			if old != nil {
				for _, id := range old.RestaurantIDs {
					r, ok := findRestaurant(a, id)
					if !ok || r.Lifecycle == "deleting" || r.Lifecycle == "deleted" {
						return ErrScopeDeleted
					}
				}
			}
			return nil
		}, func(a *domain.Aggregate, u domain.User) (domain.LifecycleIntent, error) {
			if !validScopeName(in.Name) {
				return domain.LifecycleIntent{}, &FieldError{Field: "name", Code: "InvalidFormat"}
			}
			if len(a.Restaurants) >= 10000 {
				return domain.LifecycleIntent{}, ErrAuthUnavailable
			}
			rid, err := s.newEnrollmentID()
			if err != nil {
				return domain.LifecycleIntent{}, err
			}
			a.Restaurants = append(a.Restaurants, domain.Restaurant{RestaurantID: rid, OrgID: org, Name: in.Name, Lifecycle: "registering", LifecycleVersion: "1"})
			return s.newLifecycleIntent(u.UserID, org, []domain.EntityID{rid}, in.CommandID, "1", false)
		})
}
func (s *Accounts) newLifecycleIntent(actor, org domain.EntityID, ids []domain.EntityID, command string, version domain.Version, deleting bool) (domain.LifecycleIntent, error) {
	op, err := s.newEnrollmentID()
	if err != nil {
		return domain.LifecycleIntent{}, err
	}
	l := domain.LifecycleIntent{OperationID: op, CommandID: command, ActorID: actor, OrgID: org, RestaurantIDs: ids, Lifecycle: "registering", LifecycleVersion: version, Cleanup: "not_required", Services: []domain.PeerReadiness{}}
	if deleting {
		l.Lifecycle = "deleting"
		l.Cleanup = "pending"
	}
	for _, id := range ids {
		for _, service := range runtimeServices {
			l.Services = append(l.Services, domain.PeerReadiness{RestaurantID: id, Service: service, State: "pending", LifecycleVersion: version})
		}
	}
	return l, nil
}
func lifecycleFingerprint(actor, org, restaurant domain.EntityID, operation, command string, input any) (string, error) {
	if command == "" || !utf8.ValidString(command) || strings.HasPrefix(command, "expiration/") || len(command) > 1<<20 {
		return "", &FieldError{Field: "commandID", Code: "InvalidFormat"}
	}
	encoded, err := json.Marshal(struct {
		Version, Operation     string
		Actor, Org, Restaurant domain.EntityID
		Input                  any
	}{"1", operation, actor, org, restaurant, input})
	if err != nil {
		return "", ErrAuthUnavailable
	}
	return TokenDigest(string(encoded)), nil
}
func (s *Accounts) lifecycleCommand(ctx context.Context, token, csrf, operation string, org, restaurant domain.EntityID, command string, input any, status int, access func(domain.Aggregate, domain.User, *domain.LifecycleIntent) error, change func(*domain.Aggregate, domain.User) (domain.LifecycleIntent, error)) (LifecycleResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.opts.Results == nil {
		return LifecycleResult{}, ErrAuthUnavailable
	}
	for {
		if err := ctx.Err(); err != nil {
			return LifecycleResult{}, err
		}
		a, err := s.load(ctx)
		if err != nil {
			return LifecycleResult{}, err
		}
		u, err := s.membershipActor(a, token, csrf)
		if err != nil {
			return LifecycleResult{}, err
		}
		fp, err := lifecycleFingerprint(u.UserID, org, restaurant, operation, command, input)
		if err != nil {
			return LifecycleResult{}, err
		}
		var replay *domain.LifecycleIntent
		for _, r := range a.Idempotency {
			if r.ActorID != u.UserID || r.OperationID != operation || r.OrgID != org || r.RestaurantID != restaurant || r.CommandID != command {
				continue
			}
			if r.Fingerprint != fp {
				return LifecycleResult{}, ErrCommandConflict
			}
			plain, err := s.opts.Results.Open(r.EncryptedResponse)
			if err != nil {
				return LifecycleResult{}, ErrAuthUnavailable
			}
			var saved domain.LifecycleIntent
			err = json.Unmarshal(plain, &saved)
			clear(plain)
			if err != nil || r.HTTPStatus != status || r.ResponseSchema != "LifecycleResult" {
				return LifecycleResult{}, ErrAuthUnavailable
			}
			saved.ActorID = u.UserID
			replay = &saved
			break
		}
		if err := access(a, u, replay); err != nil {
			return LifecycleResult{}, err
		}
		if replay != nil {
			return lifecycleView(*replay), nil
		}
		result, err := change(&a, u)
		if err != nil {
			return LifecycleResult{}, err
		}
		encoded, err := json.Marshal(lifecycleView(result))
		if err != nil {
			return LifecycleResult{}, ErrAuthUnavailable
		}
		sealed, err := s.opts.Results.Seal(encoded)
		clear(encoded)
		if err != nil {
			return LifecycleResult{}, ErrAuthUnavailable
		}
		revision, err := nextVersion(a.AggregateRevision)
		if err != nil {
			return LifecycleResult{}, err
		}
		a.LifecycleIntents = append(a.LifecycleIntents, result)
		a.Idempotency = append(a.Idempotency, domain.IdempotencyRecord{ActorID: u.UserID, OperationID: operation, OrgID: org, RestaurantID: restaurant, CommandID: command, Fingerprint: fp, AggregateRevision: revision, HTTPStatus: status, ResponseSchema: "LifecycleResult", EncryptedResponse: sealed, JobIDs: []domain.EntityID{}, RecordedAt: formatInstant(s.opts.Clock.Now())})
		if err := s.commit(ctx, a); err != nil {
			if errors.Is(err, ErrRevisionConflict) {
				continue
			}
			return LifecycleResult{}, err
		}
		return lifecycleView(result), nil
	}
}
func findRestaurant(a domain.Aggregate, id domain.EntityID) (domain.Restaurant, bool) {
	for _, r := range a.Restaurants {
		if r.RestaurantID == id {
			return r, true
		}
	}
	return domain.Restaurant{}, false
}
