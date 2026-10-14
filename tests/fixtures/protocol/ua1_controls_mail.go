package protocol

import (
	"context"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func (c *UA1MailControls) ProcessMail(ctx context.Context, accounts *application.Accounts, sender application.MailSender) (bool, error) {
	if accounts == nil || sender == nil {
		return false, application.ErrAuthUnavailable
	}
	select {
	case c.worker <- struct{}{}:
		defer func() { <-c.worker }()
	default:
		return false, errUA1Barrier
	}
	attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.gate(attempt, "before-process-mail", application.MailDelivery{}, ""); err != nil {
		return false, err
	}
	return accounts.ProcessMail(attempt, ua1ControlSender{controls: c, sender: sender, cancel: cancel})
}

type ua1ControlSender struct {
	controls *UA1MailControls
	sender   application.MailSender
	cancel   context.CancelFunc
}

func (s ua1ControlSender) Send(ctx context.Context, delivery application.MailDelivery) application.DeliveryResult {
	if err := s.controls.gate(ctx, "after-durable-claim", delivery, ""); err != nil {
		s.cancel()
		return application.DeliveryResult{Unknown: true, Code: "fixture-control-cancelled"}
	}
	ioContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	result := s.sender.Send(ioContext, delivery)
	cancel()
	if err := s.controls.gate(ctx, "after-send-before-result", delivery, ua1SenderResult(result)); err != nil {
		s.cancel()
	}
	return result
}

func ua1SenderResult(r application.DeliveryResult) string {
	switch {
	case r.Success:
		return "success"
	case r.Unknown:
		return "unknown"
	case r.Permanent:
		return "permanent"
	default:
		return "retryable"
	}
}

func (c *UA1MailControls) gate(ctx context.Context, point string, delivery application.MailDelivery, senderResult string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errUA1Barrier
	}
	var selected *ua1Control
	for _, a := range c.records {
		c.expire(a)
		if a.record.State != "armed" || a.reserved || a.arm.Point != point {
			continue
		}
		if point == "before-process-mail" || a.arm.Link != nil && delivery.Link != nil && a.arm.Link.JobID == delivery.JobID && a.arm.Link.InvitationID == delivery.Link.InvitationID {
			selected = a
			a.reserved = true
			break
		}
	}
	c.mu.Unlock()
	if selected == nil {
		return nil
	}
	var revision domain.Version
	attempt := 0
	if point != "before-process-mail" {
		v, err := c.opts.Store.Load(ctx)
		if err != nil {
			c.mu.Lock()
			selected.reserved = false
			c.cancel(selected, "claim-observation-unavailable")
			c.mu.Unlock()
			return err
		}
		a := v.Snapshot()
		sel := selected.arm.Link
		matches := 0
		if len(a.MailJobs)+len(a.Invitations) <= 16384 {
			for _, j := range a.MailJobs {
				if j.JobID == sel.JobID && j.InvitationID == sel.InvitationID && j.OrgID == sel.OrgID && j.Purpose == "invitation_link" && j.ChallengeID == "" && j.State == "sending" && j.Attempts > 0 {
					matches++
					attempt = j.Attempts
				}
			}
		}
		if matches != 1 {
			c.mu.Lock()
			selected.reserved = false
			c.cancel(selected, "claim-correlation-conflict")
			c.mu.Unlock()
			return errUA1Barrier
		}
		revision = v.Revision()
	}
	c.mu.Lock()
	selected.reserved = false
	if err := c.hit(ctx, selected); err != nil {
		c.mu.Unlock()
		return err
	}
	selected.record.AggregateRevision = revision
	selected.record.Attempt = attempt
	if senderResult != "" {
		selected.record.SenderResult = senderResult
	}
	c.mu.Unlock()
	return c.wait(ctx, selected)
}
