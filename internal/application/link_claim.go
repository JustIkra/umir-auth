package application

import (
	"context"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func (s *Accounts) claimInvitationLink(ctx context.Context, a domain.Aggregate, index int) (MailDelivery, int, bool, error) {
	j := &a.MailJobs[index]
	i, err := invitationIndex(a, j.InvitationID)
	if err != nil {
		return MailDelivery{}, 0, false, ErrAuthUnavailable
	}
	invitation := a.Invitations[i]
	now := s.opts.Clock.Now()
	if invitation.State != "pending" || !before(now, invitation.ExpiresAt) || invitationScope(a, invitation) != nil || j.Attempts >= 3 {
		j.State = "suppressed"
		j.EncryptedPayload, j.NextAttemptAt = "", ""
		return MailDelivery{}, 0, true, s.commit(ctx, a)
	}
	mail, err := s.openInvitationLink(a, *j)
	if err != nil {
		return MailDelivery{}, 0, false, err
	}
	j.State = "sending"
	j.Attempts++
	j.LastAttemptAt = formatInstant(now)
	j.NextAttemptAt = ""
	delivery, attempt := MailDelivery{JobID: j.JobID, Link: &mail, Attempt: j.Attempts, Age: jobAge(*j, now)}, j.Attempts
	if err := s.commit(ctx, a); err != nil {
		return MailDelivery{}, 0, false, err
	}
	return delivery, attempt, true, nil
}
