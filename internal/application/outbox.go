package application

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/JustIkra/umir-auth/internal/domain"
)

type CodeMail struct {
	ChallengeID          domain.EntityID
	IssuanceID           domain.EntityID
	Email, Code          string
	CreatedAt, ExpiresAt time.Time
}
type MailDelivery struct {
	JobID domain.EntityID
	Mail  CodeMail
	Link  *InvitationLinkMail
}

func (d MailDelivery) Recipient() string {
	if d.Link != nil {
		return d.Link.Email
	}
	return d.Mail.Email
}

type DeliveryResult struct {
	Success, Permanent, Unknown bool
	Code                        string
}
type MailSender interface {
	Send(context.Context, MailDelivery) DeliveryResult
}
type mailPayload struct{ Email, Code string }

func (s *Accounts) enqueueChallenge(a *domain.Aggregate, c domain.Challenge, email, code string) (domain.EntityID, error) {
	id, err := s.newEnrollmentID()
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(mailPayload{email, code})
	if err != nil {
		return "", ErrAuthUnavailable
	}
	defer clear(plain)
	sealed, err := s.opts.Challenges.Seal(payloadScope(id), string(plain))
	if err != nil {
		return "", ErrAuthUnavailable
	}
	j := domain.MailJob{JobID: id, ChallengeID: c.ChallengeID, InvitationID: c.InvitationID, State: "queued", EncryptedPayload: sealed, AcceptedAt: formatInstant(s.opts.Clock.Now()), NextAttemptAt: formatInstant(s.opts.Clock.Now())}
	if a.SchemaVersion >= 2 {
		j.Purpose = "otp"
		j.EnqueueOrder = "1"
		if len(a.MailJobs) > 0 {
			j.EnqueueOrder, err = nextVersion(a.MailJobs[len(a.MailJobs)-1].EnqueueOrder)
			if err != nil {
				return "", err
			}
		}
	}
	if c.InvitationID != "" {
		i, err := invitationIndex(*a, c.InvitationID)
		if err != nil {
			return "", err
		}
		j.OrgID = a.Invitations[i].OrgID
	}
	if c.RegistrationSuppressed || c.SuppressedEmail != "" {
		j.State = "suppressed"
		j.EncryptedPayload = ""
		j.NextAttemptAt = ""
	}
	a.MailJobs = append(a.MailJobs, j)
	return id, nil
}
func mailDelay(attempts int) time.Duration {
	if attempts <= 1 {
		return time.Minute
	}
	return 5 * time.Minute
}
func (s *Accounts) RecoverMail(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		a, err := s.load(ctx)
		if err != nil {
			return err
		}
		changed := false
		for i := range a.MailJobs {
			j := &a.MailJobs[i]
			if j.State == "sending" {
				j.State = "unknown"
				if j.LastAttemptAt == "" {
					return ErrAuthUnavailable
				}
				last, err := time.Parse(time.RFC3339Nano, string(j.LastAttemptAt))
				if err != nil {
					return ErrAuthUnavailable
				}
				j.NextAttemptAt = formatInstant(last.Add(mailDelay(j.Attempts)))
				if j.Purpose == "invitation_link" && j.Attempts >= 3 {
					j.NextAttemptAt = ""
				}
				changed = true
			}
		}
		if !changed {
			return nil
		}
		err = s.commit(ctx, a)
		if errors.Is(err, ErrRevisionConflict) && !s.recovering {
			continue
		}
		return err
	}
}
func (s *Accounts) ProcessMail(ctx context.Context, sender MailSender) (bool, error) {
	if sender == nil || s.opts.Challenges == nil {
		return false, ErrAuthUnavailable
	}
	if err := s.SweepEnrollment(ctx); err != nil {
		return false, err
	}
	delivery, attempt, worked, err := s.claimMail(ctx)
	if err != nil || !worked || delivery.JobID == "" {
		return worked, err
	}
	result := sender.Send(ctx, delivery)
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		a, err := s.load(ctx)
		if err != nil {
			return true, err
		}
		for i := range a.MailJobs {
			j := &a.MailJobs[i]
			if j.JobID != delivery.JobID {
				continue
			}
			if j.State != "sending" || j.Attempts != attempt {
				return true, ErrAuthUnavailable
			}
			switch {
			case result.Success:
				j.State = "delivered"
			case result.Unknown && j.Purpose == "invitation_link":
				j.State = "unknown"
			case result.Permanent || j.Attempts >= 3:
				j.State = "failed"
			case result.Unknown:
				j.State = "unknown"
			default:
				j.State = "queued"
			}
			if j.State == "delivered" || j.State == "failed" {
				j.EncryptedPayload = ""
				j.NextAttemptAt = ""
			} else if j.Purpose == "invitation_link" && j.State == "unknown" && j.Attempts >= 3 {
				j.NextAttemptAt = ""
			} else {
				last, err := time.Parse(time.RFC3339Nano, string(j.LastAttemptAt))
				if err != nil {
					return true, ErrAuthUnavailable
				}
				j.NextAttemptAt = formatInstant(last.Add(mailDelay(j.Attempts)))
			}
		}
		err = s.commit(ctx, a)
		if errors.Is(err, ErrRevisionConflict) && !s.recovering {
			continue
		}
		return true, err
	}
}
func (s *Accounts) SweepEnrollment(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		a, err := s.load(ctx)
		if err != nil {
			return err
		}
		now := s.opts.Clock.Now()
		changed := false
		for i := range a.Invitations {
			v := &a.Invitations[i]
			if v.State == "pending" && !before(now, v.ExpiresAt) {
				v.State = "expired"
				v.Version, err = nextVersion(v.Version)
				if err != nil {
					return err
				}
				suppressInvitationJobs(&a, v.InvitationID)
				changed = true
			}
		}
		for i := range a.Challenges {
			c := &a.Challenges[i]
			if c.State == "pending" {
				_, admissionErr := challengeEmail(a, *c, now)
				if !before(now, c.ExpiresAt) || admissionErr != nil {
					c.State = "expired"
					c.EncryptedCode = ""
					suppressChallengeJobs(&a, c.ChallengeID)
					changed = true
				}
			}
		}
		if !changed {
			return nil
		}
		err = s.commit(ctx, a)
		if errors.Is(err, ErrRevisionConflict) && !s.recovering {
			continue
		}
		return err
	}
}
func validateEnrollmentSecrets(a domain.Aggregate, secrets ChallengeSecrets, links InvitationURLPolicy) error {
	for _, c := range a.Challenges {
		if c.EncryptedCode != "" {
			code, err := secrets.Open(codeScope(c.ChallengeID, c.Purpose), c.EncryptedCode)
			if err != nil || !validCode(code) || secrets.Digest(codeScope(c.ChallengeID, c.Purpose), code) != c.CodeDigest {
				return ErrAuthUnavailable
			}
		}
		if c.EncryptedProof != "" {
			proof, err := secrets.Open(proofScope(c.ChallengeID, c.Purpose), c.EncryptedProof)
			if err != nil || len(proof) < 32 || len(proof) > 128 || secrets.Digest(proofScope(c.ChallengeID, c.Purpose), proof) != c.ProofDigest {
				return ErrAuthUnavailable
			}
		}
	}
	for _, j := range a.MailJobs {
		if j.EncryptedPayload == "" {
			continue
		}
		if j.Purpose == "invitation_link" {
			s := &Accounts{opts: AccountOptions{Challenges: secrets, LinkURLs: links}}
			if _, err := s.openInvitationLink(a, j); err != nil {
				return err
			}
			continue
		}
		i, err := challengeIndex(a, j.ChallengeID)
		if err != nil {
			return err
		}
		c := a.Challenges[i]
		plain, err := secrets.Open(payloadScope(j.JobID), j.EncryptedPayload)
		if err != nil {
			return ErrAuthUnavailable
		}
		var payload mailPayload
		if json.Unmarshal([]byte(plain), &payload) != nil || !validCode(payload.Code) || secrets.Digest(codeScope(c.ChallengeID, c.Purpose), payload.Code) != c.CodeDigest {
			return ErrAuthUnavailable
		}
		_, comparison, err := CanonicalEmail(payload.Email)
		if err != nil {
			return ErrAuthUnavailable
		}
		expected := ""
		if c.InvitationID != "" {
			ii, err := invitationIndex(a, c.InvitationID)
			if err != nil {
				return err
			}
			expected = a.Invitations[ii].ComparisonEmail
		} else if c.Purpose == "registration" {
			expected = domain.ComparisonEmail(c.RegistrationEmail)
		} else {
			u, ok := findUser(a, c.UserID)
			if !ok {
				return ErrAuthUnavailable
			}
			expected = domain.ComparisonEmail(u.Email)
		}
		if comparison != expected {
			return ErrAuthUnavailable
		}
	}
	return nil
}
func (s *Accounts) claimMail(ctx context.Context) (MailDelivery, int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return MailDelivery{}, 0, false, err
		}
		a, err := s.load(ctx)
		if err != nil {
			return MailDelivery{}, 0, false, err
		}
		now := s.opts.Clock.Now()
		selected := -1
		for i, j := range a.MailJobs {
			if (j.State == "queued" || j.State == "unknown") && (j.NextAttemptAt == "" || !before(now, j.NextAttemptAt)) && (j.Purpose != "invitation_link" || j.State != "unknown" || j.Attempts < 3) {
				if selected < 0 || j.AcceptedAt < a.MailJobs[selected].AcceptedAt {
					selected = i
				}
			}
		}
		if selected < 0 {
			return MailDelivery{}, 0, false, nil
		}
		j := &a.MailJobs[selected]
		if j.Purpose == "invitation_link" {
			delivery, attempt, worked, err := s.claimInvitationLink(ctx, a, selected)
			if errors.Is(err, ErrRevisionConflict) && !s.recovering {
				continue
			}
			return delivery, attempt, worked, err
		}
		ci, err := challengeIndex(a, j.ChallengeID)
		if err != nil {
			return MailDelivery{}, 0, false, err
		}
		c := a.Challenges[ci]
		email, admissionErr := challengeEmail(a, c, now)
		disabled := c.Purpose == "registration" && !s.opts.Registration.Enabled || c.Purpose == "login" && !s.opts.EmailLoginEnabled
		if disabled || c.State != "pending" || !before(now, c.ExpiresAt) || admissionErr != nil || j.Attempts >= 3 {
			j.State = "suppressed"
			if !disabled && j.Attempts >= 3 && admissionErr == nil && c.State == "pending" && before(now, c.ExpiresAt) {
				j.State = "failed"
			}
			j.EncryptedPayload = ""
			j.NextAttemptAt = ""
			if err := s.commit(ctx, a); errors.Is(err, ErrRevisionConflict) && !s.recovering {
				continue
			} else {
				return MailDelivery{}, 0, true, err
			}
		}
		plain, err := s.opts.Challenges.Open(payloadScope(j.JobID), j.EncryptedPayload)
		if err != nil {
			return MailDelivery{}, 0, false, ErrAuthUnavailable
		}
		var payload mailPayload
		if json.Unmarshal([]byte(plain), &payload) != nil || payload.Email != email || !validCode(payload.Code) {
			return MailDelivery{}, 0, false, ErrAuthUnavailable
		}
		digest := s.opts.Challenges.Digest(codeScope(c.ChallengeID, c.Purpose), payload.Code)
		if digest != c.CodeDigest {
			return MailDelivery{}, 0, false, ErrAuthUnavailable
		}
		expires, err := time.Parse(time.RFC3339Nano, string(c.ExpiresAt))
		if err != nil {
			return MailDelivery{}, 0, false, ErrAuthUnavailable
		}
		d := MailDelivery{JobID: j.JobID, Mail: CodeMail{ChallengeID: c.ChallengeID, IssuanceID: j.JobID, Email: payload.Email, Code: payload.Code, CreatedAt: expires.Add(-10 * time.Minute), ExpiresAt: expires}}
		j.State = "sending"
		j.Attempts++
		j.LastAttemptAt = formatInstant(now)
		j.NextAttemptAt = ""
		attempt := j.Attempts
		if err := s.commit(ctx, a); err != nil {
			if errors.Is(err, ErrRevisionConflict) && !s.recovering {
				continue
			}
			return MailDelivery{}, 0, false, err
		}
		return d, attempt, true, nil
	}
}
