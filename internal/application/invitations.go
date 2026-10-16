package application

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/domain"
	"golang.org/x/text/unicode/norm"
)

var ErrInvitationUnavailable = errors.New("invitation unavailable")
var ErrInvitationConflict = errors.New("active invitation conflict")

type CreateInvitationInput struct {
	CommandID   string                    `json:"commandID"`
	Email       string                    `json:"email"`
	Assignments []domain.InviteAssignment `json:"assignments"`
}

func CanonicalEmail(raw string) (string, string, error) {
	if !utf8.ValidString(raw) || strings.ContainsFunc(raw, unicode.IsControl) {
		return "", "", &FieldError{Field: "email", Code: "InvalidFormat"}
	}
	value := norm.NFC.String(strings.TrimSpace(raw))
	if !domain.ValidEmail(value) {
		return "", "", &FieldError{Field: "email", Code: "InvalidFormat"}
	}
	local, host, ok := strings.Cut(value, "@")
	if !ok || local == "" || host == "" || len(value) > 254 || strings.ContainsAny(value, " \t\r\n<>\"(),:;\\") || strings.Contains(host, "@") || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return "", "", &FieldError{Field: "email", Code: "InvalidFormat"}
	}
	return value, domain.ComparisonEmail(value), nil
}
func canonicalInviteAssignments(input []domain.InviteAssignment) ([]domain.InviteAssignment, error) {
	if len(input) == 0 || len(input) > 500 {
		return nil, &FieldError{Field: "assignments", Code: "InvalidFormat"}
	}
	result := make([]domain.InviteAssignment, len(input))
	for i, x := range input {
		if len(x.Roles) == 0 || len(x.Roles) > 2 {
			return nil, &FieldError{Field: "assignments", Code: "InvalidFormat"}
		}
		r := slices.Clone(x.Roles)
		slices.Sort(r)
		for j, role := range r {
			if role != "Warehouse" && role != "Waiter" || j > 0 && r[j-1] == role {
				return nil, &FieldError{Field: "assignments", Code: "InvalidFormat"}
			}
		}
		result[i] = domain.InviteAssignment{RestaurantID: x.RestaurantID, Roles: r}
	}
	slices.SortFunc(result, func(a, b domain.InviteAssignment) int {
		return strings.Compare(string(a.RestaurantID), string(b.RestaurantID))
	})
	for i := 1; i < len(result); i++ {
		if result[i].RestaurantID == result[i-1].RestaurantID {
			return nil, &FieldError{Field: "assignments", Code: "InvalidFormat"}
		}
	}
	return result, nil
}
func invitationScope(a domain.Aggregate, in domain.Invitation) error {
	if err := publicScope(a, in.OrgID); err != nil {
		return err
	}
	for _, as := range in.Assignments {
		found := false
		for _, r := range a.Restaurants {
			if r.RestaurantID == as.RestaurantID && r.OrgID == in.OrgID && r.Lifecycle == "ready" {
				found = true
				break
			}
		}
		if !found {
			return ErrForbidden
		}
	}
	return nil
}
func invitationIndex(a domain.Aggregate, id domain.EntityID) (int, error) {
	for i, in := range a.Invitations {
		if in.InvitationID == id {
			return i, nil
		}
	}
	return 0, ErrInvitationUnavailable
}
func before(now time.Time, at domain.Instant) bool {
	t, err := time.Parse(time.RFC3339Nano, string(at))
	return err == nil && now.Before(t)
}

func (s *Accounts) CreateInvitation(ctx context.Context, token, csrf string, org domain.EntityID, in CreateInvitationInput) (domain.Invitation, error) {
	email, comparison, err := CanonicalEmail(in.Email)
	if err != nil {
		return domain.Invitation{}, err
	}
	assignments, err := canonicalInviteAssignments(in.Assignments)
	if err != nil {
		return domain.Invitation{}, err
	}
	in.Email, in.Assignments = comparison, assignments
	return enrollmentCommand(s, ctx, ChallengeActor{Token: token, CSRFToken: csrf}, "createInvitation", org, in.CommandID, in, "Invitation", 201,
		func(a domain.Aggregate, who enrollmentActor) error {
			if !domain.IsOrgAdmin(a, who.user.UserID, org) {
				return ErrForbidden
			}
			return invitationScope(a, domain.Invitation{OrgID: org, Assignments: assignments})
		},
		func(a *domain.Aggregate, _ enrollmentActor) (enrollmentChange[domain.Invitation], error) {
			if s.opts.LinkURLs == nil {
				return enrollmentChange[domain.Invitation]{}, ErrDeliveryUnavailable
			}
			if _, err := s.opts.LinkURLs.Origin(s.opts.InvitationMail); err != nil {
				return enrollmentChange[domain.Invitation]{}, err
			}
			now := s.opts.Clock.Now()
			if err := s.issueLimit(*a, comparison, "invitation", now); err != nil {
				return enrollmentChange[domain.Invitation]{}, err
			}
			recent := 0
			for i := range a.Invitations {
				old := &a.Invitations[i]
				if !sameEmail(old.ComparisonEmail, comparison) || old.OrgID != org {
					continue
				}
				if old.State == "pending" && before(now, old.ExpiresAt) {
					return enrollmentChange[domain.Invitation]{}, ErrInvitationConflict
				}
				if old.State == "pending" {
					old.State = "expired"
					old.Version, err = nextVersion(old.Version)
					if err != nil {
						return enrollmentChange[domain.Invitation]{}, err
					}
					suppressInvitationJobs(a, old.InvitationID)
				}
				expires, e := time.Parse(time.RFC3339Nano, string(old.ExpiresAt))
				if e == nil && now.Sub(expires.Add(-7*24*time.Hour)) < 10*time.Minute {
					recent++
				}
			}
			if recent >= 3 {
				return enrollmentChange[domain.Invitation]{}, ErrChallengeRateLimited
			}
			id, err := s.newEnrollmentID()
			if err != nil {
				return enrollmentChange[domain.Invitation]{}, err
			}
			v := domain.Invitation{InvitationID: id, OrgID: org, Email: email, ComparisonEmail: comparison, Assignments: assignments, ExpiresAt: formatInstant(now.Add(7 * 24 * time.Hour)), ResendAvailableAt: formatInstant(now.Add(time.Minute)), State: "pending", Version: "1"}
			a.Invitations = append(a.Invitations, v)
			job, err := s.enqueueInvitationLink(a, v)
			if err != nil {
				return enrollmentChange[domain.Invitation]{}, err
			}
			return enrollmentChange[domain.Invitation]{value: v, jobs: []domain.EntityID{job}}, nil
		})
}
func suppressInvitationJobs(a *domain.Aggregate, id domain.EntityID) {
	for i := range a.MailJobs {
		j := &a.MailJobs[i]
		if j.InvitationID == id && (j.State == "queued" || j.State == "unknown") {
			j.State = "suppressed"
			j.EncryptedPayload = ""
			j.NextAttemptAt = ""
		}
	}
}
func (s *Accounts) CancelInvitation(ctx context.Context, token, csrf string, org, id domain.EntityID, command string) (DurableResult, error) {
	return enrollmentCommand(s, ctx, ChallengeActor{Token: token, CSRFToken: csrf}, "cancelInvitation", org, command, id, "DurableResult", 200,
		func(a domain.Aggregate, who enrollmentActor) error {
			if !domain.IsOrgAdmin(a, who.user.UserID, org) {
				return ErrForbidden
			}
			i, err := invitationIndex(a, id)
			if err != nil || a.Invitations[i].OrgID != org {
				return ErrForbidden
			}
			return nil
		},
		func(a *domain.Aggregate, _ enrollmentActor) (enrollmentChange[DurableResult], error) {
			i, err := invitationIndex(*a, id)
			if err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			v := &a.Invitations[i]
			if v.State != "pending" {
				return enrollmentChange[DurableResult]{}, ErrInvitationUnavailable
			}
			v.State = "revoked"
			v.Version, err = nextVersion(v.Version)
			if err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			suppressInvitationJobs(a, id)
			rev, err := nextVersion(a.AggregateRevision)
			if err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			return enrollmentChange[DurableResult]{value: DurableResult{CommandID: command, Outcome: Committed, AggregateRevision: rev, ResourceID: id, MailJobs: []MailJobView{}}}, nil
		})
}
func (s *Accounts) ResendInvitation(ctx context.Context, token, csrf string, org, id domain.EntityID, command string) (DurableResult, error) {
	return enrollmentCommand(s, ctx, ChallengeActor{Token: token, CSRFToken: csrf}, "resendInvitation", org, command, id, "DurableResult", 200,
		func(a domain.Aggregate, who enrollmentActor) error {
			if !domain.IsOrgAdmin(a, who.user.UserID, org) {
				return ErrForbidden
			}
			i, err := invitationIndex(a, id)
			if err != nil || a.Invitations[i].OrgID != org {
				return ErrForbidden
			}
			return invitationScope(a, a.Invitations[i])
		},
		func(a *domain.Aggregate, _ enrollmentActor) (enrollmentChange[DurableResult], error) {
			i, err := invitationIndex(*a, id)
			if err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			invite := a.Invitations[i]
			now := s.opts.Clock.Now()
			if invite.State != "pending" || !before(now, invite.ExpiresAt) {
				return enrollmentChange[DurableResult]{}, ErrInvitationUnavailable
			}
			if before(now, invite.ResendAvailableAt) {
				return enrollmentChange[DurableResult]{}, ErrChallengeRateLimited
			}
			selected := -1
			for n, c := range a.Challenges {
				if c.InvitationID == id && c.State == "pending" && before(now, c.ExpiresAt) {
					if selected >= 0 {
						return enrollmentChange[DurableResult]{}, ErrInvitationConflict
					}
					selected = n
				}
			}
			if selected < 0 {
				return enrollmentChange[DurableResult]{}, ErrChallengeUnavailable
			}
			c := &a.Challenges[selected]
			if c.IssueCount >= 4 || before(now, c.ResendAvailableAt) {
				return enrollmentChange[DurableResult]{}, ErrChallengeRateLimited
			}
			if err := s.issueLimit(*a, invite.ComparisonEmail, "invitation", now); err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			if s.opts.Challenges == nil {
				return enrollmentChange[DurableResult]{}, ErrAuthUnavailable
			}
			code, err := s.opts.Challenges.Open(codeScope(c.ChallengeID, c.Purpose), c.EncryptedCode)
			if err != nil || !validCode(code) {
				return enrollmentChange[DurableResult]{}, ErrAuthUnavailable
			}
			c.IssueCount++
			expires, err := time.Parse(time.RFC3339Nano, string(c.ExpiresAt))
			if err != nil {
				return enrollmentChange[DurableResult]{}, ErrAuthUnavailable
			}
			next := now.Add(time.Minute)
			if next.After(expires) {
				next = expires
			}
			c.ResendAvailableAt = formatInstant(next)
			saved := *c
			a.Invitations[i].ResendAvailableAt = formatInstant(now.Add(time.Minute))
			if !before(now.Add(time.Minute), invite.ExpiresAt) {
				a.Invitations[i].ResendAvailableAt = invite.ExpiresAt
			}
			a.Invitations[i].Version, err = nextVersion(invite.Version)
			if err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			job, err := s.enqueueChallenge(a, saved, invite.Email, code)
			if err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			rev, err := nextVersion(a.AggregateRevision)
			if err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			last := a.MailJobs[len(a.MailJobs)-1]
			return enrollmentChange[DurableResult]{value: DurableResult{CommandID: command, Outcome: Committed, AggregateRevision: rev, ResourceID: id, MailJobs: []MailJobView{{JobID: job, State: "pending", Attempts: 0, AcceptedAt: last.AcceptedAt, NextAttemptAt: last.NextAttemptAt}}}, jobs: []domain.EntityID{job}}, nil
		})
}
