package application

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/JustIkra/umir-auth/internal/domain"
)

var ErrDeliveryUnavailable = errors.New("invitation delivery unavailable")

type InvitationRateLimitError struct {
	RetryAfter time.Duration
}

func (e *InvitationRateLimitError) Error() string { return ErrChallengeRateLimited.Error() }
func (e *InvitationRateLimitError) Unwrap() error { return ErrChallengeRateLimited }

type InvitationMailOptions struct {
	FrontendOrigin    string `json:"frontendOrigin"`
	AllowLoopbackHTTP bool   `json:"allowLoopbackHTTP,omitempty"`
}

type InvitationURLPolicy interface {
	Origin(InvitationMailOptions) (string, error)
	Link(InvitationMailOptions, domain.EntityID) (string, error)
	Validate(string, domain.EntityID) error
}

type InvitationLinkMail struct {
	InvitationID         domain.EntityID
	Email, URL           string
	CreatedAt, ExpiresAt time.Time
}

type invitationLinkPayload struct {
	Purpose      string          `json:"purpose"`
	InvitationID domain.EntityID `json:"invitationID"`
	Email        string          `json:"email"`
	URL          string          `json:"url"`
	ExpiresAt    domain.Instant  `json:"expiresAt"`
}

func (s *Accounts) enqueueInvitationLink(a *domain.Aggregate, invitation domain.Invitation) (domain.EntityID, error) {
	if s.opts.LinkURLs == nil {
		return "", ErrDeliveryUnavailable
	}
	linkURL, err := s.opts.LinkURLs.Link(s.opts.InvitationMail, invitation.InvitationID)
	if err != nil {
		return "", err
	}
	if s.opts.Challenges == nil || a.SchemaVersion != 2 {
		return "", ErrDeliveryUnavailable
	}
	id, err := s.newEnrollmentID()
	if err != nil {
		return "", err
	}
	payload := invitationLinkPayload{Purpose: "invitation_link", InvitationID: invitation.InvitationID, Email: invitation.Email, URL: linkURL, ExpiresAt: invitation.ExpiresAt}
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", ErrAuthUnavailable
	}
	defer clear(plain)
	sealed, err := s.opts.Challenges.Seal(payloadScope(id), string(plain))
	if err != nil {
		return "", ErrAuthUnavailable
	}
	order := domain.Version("1")
	if len(a.MailJobs) > 0 {
		order, err = nextVersion(a.MailJobs[len(a.MailJobs)-1].EnqueueOrder)
		if err != nil {
			return "", err
		}
	}
	now := formatInstant(s.opts.Clock.Now())
	a.MailJobs = append(a.MailJobs, domain.MailJob{JobID: id, Purpose: "invitation_link", EnqueueOrder: order, OrgID: invitation.OrgID, InvitationID: invitation.InvitationID, State: "queued", EncryptedPayload: sealed, AcceptedAt: now, NextAttemptAt: now})
	return id, nil
}

func (s *Accounts) openInvitationLink(a domain.Aggregate, j domain.MailJob) (InvitationLinkMail, error) {
	i, err := invitationIndex(a, j.InvitationID)
	if err != nil || j.Purpose != "invitation_link" || j.ChallengeID != "" || j.OrgID != a.Invitations[i].OrgID {
		return InvitationLinkMail{}, ErrAuthUnavailable
	}
	plain, err := s.opts.Challenges.Open(payloadScope(j.JobID), j.EncryptedPayload)
	if err != nil {
		return InvitationLinkMail{}, ErrAuthUnavailable
	}
	var payload invitationLinkPayload
	if json.Unmarshal([]byte(plain), &payload) != nil || payload.Purpose != "invitation_link" || payload.InvitationID != j.InvitationID || payload.Email != a.Invitations[i].Email || payload.ExpiresAt != a.Invitations[i].ExpiresAt {
		return InvitationLinkMail{}, ErrAuthUnavailable
	}
	if s.opts.LinkURLs == nil || s.opts.LinkURLs.Validate(payload.URL, j.InvitationID) != nil {
		return InvitationLinkMail{}, ErrAuthUnavailable
	}
	expires, err := time.Parse(time.RFC3339Nano, string(payload.ExpiresAt))
	if err != nil {
		return InvitationLinkMail{}, ErrAuthUnavailable
	}
	created, err := time.Parse(time.RFC3339Nano, string(j.AcceptedAt))
	if err != nil {
		return InvitationLinkMail{}, ErrAuthUnavailable
	}
	return InvitationLinkMail{InvitationID: j.InvitationID, Email: payload.Email, URL: payload.URL, CreatedAt: created, ExpiresAt: expires}, nil
}

func (s *Accounts) ResendInvitationLink(ctx context.Context, token, csrf string, org, id domain.EntityID, command string) (DurableResult, error) {
	return enrollmentCommand(s, ctx, ChallengeActor{Token: token, CSRFToken: csrf}, "resendInvitationLink", org, command, id, "DurableResult", 200,
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
			v := &a.Invitations[i]
			now := s.opts.Clock.Now()
			if v.State != "pending" || !before(now, v.ExpiresAt) {
				return enrollmentChange[DurableResult]{}, ErrInvitationUnavailable
			}
			if before(now, v.ResendAvailableAt) {
				at, err := time.Parse(time.RFC3339Nano, string(v.ResendAvailableAt))
				if err != nil {
					return enrollmentChange[DurableResult]{}, ErrAuthUnavailable
				}
				return enrollmentChange[DurableResult]{}, &InvitationRateLimitError{RetryAfter: at.Sub(now)}
			}
			var accepted []time.Time
			for _, r := range a.Idempotency {
				if r.OperationID != "resendInvitationLink" || len(r.JobIDs) != 1 {
					continue
				}
				for _, j := range a.MailJobs {
					if j.JobID == r.JobIDs[0] && j.InvitationID == id {
						at, err := time.Parse(time.RFC3339Nano, string(r.RecordedAt))
						if err != nil {
							return enrollmentChange[DurableResult]{}, ErrAuthUnavailable
						}
						if now.Sub(at) < time.Hour {
							accepted = append(accepted, at)
						}
					}
				}
			}
			if delay := rollingIssueDelay(accepted, 5, time.Hour, now); delay > 0 {
				return enrollmentChange[DurableResult]{}, &InvitationRateLimitError{RetryAfter: delay}
			}
			if err := s.issueLimit(*a, v.ComparisonEmail, now); err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			job, err := s.enqueueInvitationLink(a, *v)
			if err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			v.Version, err = nextVersion(v.Version)
			if err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			next := now.Add(time.Minute)
			if !before(next, v.ExpiresAt) {
				v.ResendAvailableAt = v.ExpiresAt
			} else {
				v.ResendAvailableAt = formatInstant(next)
			}
			revision, err := nextVersion(a.AggregateRevision)
			if err != nil {
				return enrollmentChange[DurableResult]{}, err
			}
			last := a.MailJobs[len(a.MailJobs)-1]
			return enrollmentChange[DurableResult]{value: DurableResult{CommandID: command, Outcome: Committed, AggregateRevision: revision, ResourceID: id, MailJobs: []MailJobView{safeLinkJob(last)}}, jobs: []domain.EntityID{job}}, nil
		})
}

func safeLinkJob(j domain.MailJob) MailJobView {
	state := j.State
	switch state {
	case "queued":
		state = "pending"
		if j.Attempts > 0 {
			state = "retry"
		}
	case "delivered":
		state = "sent"
	}
	return MailJobView{JobID: j.JobID, State: state, Attempts: j.Attempts, AcceptedAt: j.AcceptedAt, NextAttemptAt: j.NextAttemptAt}
}
