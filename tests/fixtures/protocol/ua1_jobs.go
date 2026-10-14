package protocol

import (
	"context"
	"sort"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func (h *UA1Handler) discover(ctx context.Context, input UA1Request) (UA1Response, string) {
	clock := h.opts.Clock.Read()
	if h.identity(clock) != input.Expected {
		return UA1Response{}, "ClockConflict"
	}
	value, err := h.opts.Store.Load(ctx)
	if err != nil {
		return UA1Response{}, storeCode(err)
	}
	after := h.opts.Clock.Read()
	if clock.InstanceID != after.InstanceID || clock.FixtureID != after.FixtureID || clock.Generation != after.Generation || clock.Instant != after.Instant || !after.Healthy {
		return UA1Response{}, "ClockConflict"
	}
	a := value.Snapshot()
	if len(a.Invitations)+len(a.Challenges)+len(a.MailJobs)+len(a.Idempotency) > 16384 {
		return UA1Response{}, "CapacityExceeded"
	}
	rows, code := selectUA1Jobs(a, input.Selector)
	if code != "" {
		return UA1Response{}, code
	}
	return UA1Response{Version: 1, Supplement: UA1Supplement, BindingSHA256: UA1BindingSHA256, Project: h.opts.Project, RequestID: input.RequestID, Owner: "auth", Identity: h.identity(clock), Instant: clock.Instant, AggregateRevision: a.AggregateRevision, Selector: input.Selector, Jobs: rows, Complete: true}, ""
}

func selectUA1Jobs(a domain.Aggregate, selector UA1Selector) ([]UA1Job, string) {
	var expiresAt domain.Instant
	if selector.Kind == "invitation_link" {
		found := false
		for _, invitation := range a.Invitations {
			if invitation.InvitationID != selector.InvitationID {
				continue
			}
			if found || invitation.OrgID != selector.OrgID {
				return nil, "CorrelationConflict"
			}
			found = true
			expiresAt = invitation.ExpiresAt
		}
		if !found {
			return nil, "NotFound"
		}
	} else {
		found := false
		for _, challenge := range a.Challenges {
			if challenge.ChallengeID == selector.ChallengeID {
				if found {
					return nil, "CorrelationConflict"
				}
				found = true
				expiresAt = challenge.ExpiresAt
			}
		}
		if !found {
			return nil, "NotFound"
		}
	}
	allocators := map[domain.EntityID]UA1CommandLink{}
	for _, record := range a.Idempotency {
		if record.ContractProfile != "UA1" {
			continue
		}
		if len(record.JobIDs) != 1 {
			return nil, "CorrelationConflict"
		}
		id := record.JobIDs[0]
		if _, exists := allocators[id]; exists {
			return nil, "CorrelationConflict"
		}
		allocators[id] = UA1CommandLink{OperationID: record.OperationID, CommandID: record.CommandID, ActorID: record.ActorID, AggregateRevision: record.AggregateRevision}
	}
	rows := []UA1Job{}
	seen := map[domain.EntityID]bool{}
	jobFound := false
	for _, job := range a.MailJobs {
		if seen[job.JobID] {
			return nil, "CorrelationConflict"
		}
		seen[job.JobID] = true
		matches := selector.Kind == "invitation_link" && job.Purpose == "invitation_link" && job.InvitationID == selector.InvitationID && job.OrgID == selector.OrgID && job.ChallengeID == "" || selector.Kind == "otp" && (job.Purpose == "otp" || a.SchemaVersion == 1 && job.Purpose == "") && job.ChallengeID == selector.ChallengeID
		if selector.JobID != "" {
			if job.JobID != selector.JobID {
				continue
			}
			jobFound = true
			if !matches {
				return nil, "CorrelationConflict"
			}
		}
		if !matches {
			continue
		}
		if len(rows) == 64 {
			return nil, "CapacityExceeded"
		}
		row := UA1Job{Kind: selector.Kind, JobID: job.JobID, State: job.State, Attempts: job.Attempts, AcceptedAt: job.AcceptedAt, ExpiresAt: expiresAt}
		if job.LastAttemptAt != "" {
			value := job.LastAttemptAt
			row.LastAttemptAt = &value
		}
		if job.NextAttemptAt != "" {
			value := job.NextAttemptAt
			row.NextAttemptAt = &value
		}
		if job.EnqueueOrder != "" {
			value := job.EnqueueOrder
			row.EnqueueOrder = &value
		}
		if selector.Kind == "invitation_link" {
			allocator, exists := allocators[job.JobID]
			if !exists {
				return nil, "CorrelationConflict"
			}
			row.Command = &allocator
			row.Anchor = UA1Anchor{OrgID: job.OrgID, InvitationID: job.InvitationID}
			row.MessageID = "<invitation." + string(job.JobID) + "@umir.invalid>"
		} else {
			row.Anchor = UA1Anchor{ChallengeID: job.ChallengeID}
			row.MessageID = "<registration." + string(job.ChallengeID) + "." + string(job.JobID) + "@umir.invalid>"
		}
		rows = append(rows, row)
	}
	if selector.JobID != "" && !jobFound {
		return nil, "NotFound"
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].JobID < rows[j].JobID })
	return rows, ""
}
