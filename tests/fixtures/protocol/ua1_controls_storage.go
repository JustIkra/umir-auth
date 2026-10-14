package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type ua1CommandKey struct{}

type ua1CommandObservation struct {
	selector    UA1CommandSelector
	fingerprint string
}

func (c *UA1MailControls) CommandContext(ctx context.Context, observed UA1CommandSelector, body []byte) (context.Context, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(body) > 1<<20 || checkDocument(body) != nil || SHA(body) != observed.BodySHA256 || !validUA1ControlArm(UA1ControlArm{ControlID: "11111111-1111-4111-8111-111111111111", Point: "storage-before-commit", LifetimeMS: 100, Command: &observed}) {
		return nil, errors.New("invalid UA1 command observation")
	}
	var normalized any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if observed.OperationID == "createInvitation" {
		var input application.CreateInvitationInput
		if decoder.Decode(&input) != nil || input.CommandID != observed.CommandID {
			return nil, errors.New("invalid UA1 create observation")
		}
		_, comparison, err := application.CanonicalEmail(input.Email)
		if err != nil {
			return nil, errors.New("invalid UA1 email observation")
		}
		input.Email = comparison
		for i := range input.Assignments {
			slices.Sort(input.Assignments[i].Roles)
		}
		slices.SortFunc(input.Assignments, func(a, b domain.InviteAssignment) int {
			return strings.Compare(string(a.RestaurantID), string(b.RestaurantID))
		})
		normalized = input
	} else {
		var input struct {
			CommandID string `json:"commandID"`
		}
		if decoder.Decode(&input) != nil || input.CommandID != observed.CommandID {
			return nil, errors.New("invalid UA1 resend observation")
		}
		normalized = observed.InvitationID
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, application.ErrAuthUnavailable
	}
	defer clear(encoded)
	digest, err := c.results.Digest(encoded)
	if err != nil || !digestPattern.MatchString(digest) {
		return nil, application.ErrAuthUnavailable
	}
	tuple, err := json.Marshal(struct{ Version, Operation, Actor, Initiator, Org, Input string }{"UA1", observed.OperationID, string(observed.ActorID), "", string(observed.OrgID), digest})
	if err != nil {
		return nil, application.ErrAuthUnavailable
	}
	return context.WithValue(ctx, ua1CommandKey{}, ua1CommandObservation{observed, application.TokenDigest(string(tuple))}), nil
}

type ua1ControlRepository struct{ controls *UA1MailControls }

func (c *UA1MailControls) Repository() application.AggregateRepository {
	return &ua1ControlRepository{controls: c}
}

func (r *ua1ControlRepository) Load(ctx context.Context) (domain.ValidatedAggregate, error) {
	return r.controls.opts.Store.Load(ctx)
}

func (r *ua1ControlRepository) Commit(ctx context.Context, revision domain.Version, next domain.ValidatedAggregate) (application.CommitResult, error) {
	c := r.controls
	observation, ok := ctx.Value(ua1CommandKey{}).(ua1CommandObservation)
	if !ok {
		return c.opts.Store.Commit(ctx, revision, next)
	}
	observed := observation.selector
	before, err := c.opts.Store.Load(ctx)
	if err != nil {
		if errors.Is(err, application.ErrRecoveryRequired) {
			return application.CommitResult{Outcome: application.Unknown, AggregateRevision: revision}, err
		}
		return application.CommitResult{Outcome: application.NotCommitted, AggregateRevision: revision}, err
	}
	if before.Revision() != revision {
		return application.CommitResult{Outcome: application.NotCommitted, AggregateRevision: before.Revision()}, application.ErrRevisionConflict
	}
	record, matched := ua1NewCommand(before.Snapshot(), next.Snapshot(), observed)
	if !matched || record.Fingerprint != observation.fingerprint {
		return c.opts.Store.Commit(ctx, revision, next)
	}
	c.mu.Lock()
	var selected *ua1Control
	for _, a := range c.records {
		c.expire(a)
		if a.record.State == "armed" && !a.reserved && a.arm.Command != nil && *a.arm.Command == observed && record.ActorID == observed.ActorID && record.OrgID == observed.OrgID {
			selected = a
			break
		}
	}
	if selected == nil {
		c.mu.Unlock()
		return c.opts.Store.Commit(ctx, revision, next)
	}
	selected.reserved = true
	if selected.arm.Point == "storage-before-commit" {
		if err = c.hit(ctx, selected); err != nil {
			selected.reserved = false
			c.mu.Unlock()
			return c.opts.Store.Commit(ctx, revision, next)
		}
		selected.record.Fingerprint = record.Fingerprint
		selected.record.AggregateRevision = revision
		selected.record.StoreOutcome = "not-called"
		selected.record.ReturnedOutcome = "not_committed"
		selected.record.Effect = "writer-not-called"
		selected.record.EffectSequence = c.next()
		v := c.identity()
		selected.record.EffectIdentity = &v
		c.finish(selected, "effected", "")
		selected.reserved = false
		c.mu.Unlock()
		return application.CommitResult{Outcome: application.NotCommitted, AggregateRevision: revision}, application.ErrStorageUnavailable
	}
	c.mu.Unlock()
	result, err := c.opts.Store.Commit(ctx, revision, next)
	c.mu.Lock()
	defer c.mu.Unlock()
	selected.reserved = false
	selected.record.Fingerprint = record.Fingerprint
	selected.record.AggregateRevision = result.AggregateRevision
	selected.record.StoreOutcome = string(result.Outcome)
	selected.record.ReturnedOutcome = string(result.Outcome)
	selected.record.Effect = "writer-return-observed"
	if result.Outcome == application.Committed && err == nil && c.hit(ctx, selected) == nil {
		selected.record.ReturnedOutcome = "unknown"
		selected.record.EffectSequence = c.next()
		v := c.identity()
		selected.record.EffectIdentity = &v
		c.finish(selected, "effected", "")
		return application.CommitResult{Outcome: application.Unknown, AggregateRevision: result.AggregateRevision}, application.ErrRecoveryRequired
	}
	c.expire(selected)
	if selected.record.State == "armed" {
		c.finish(selected, "not-hit", "writer-did-not-commit")
	}
	selected.record.EffectSequence = c.next()
	v := c.identity()
	selected.record.EffectIdentity = &v
	return result, err
}

func ua1NewCommand(before, next domain.Aggregate, observed UA1CommandSelector) (domain.IdempotencyRecord, bool) {
	if len(before.Idempotency)+len(next.Idempotency)+len(next.Invitations)+len(next.MailJobs) > 16384 {
		return domain.IdempotencyRecord{}, false
	}
	matches := func(r domain.IdempotencyRecord) bool {
		return r.ActorID == observed.ActorID && r.PreauthDigest == "" && r.OrgID == observed.OrgID && r.RestaurantID == "" && r.OperationID == observed.OperationID && r.CommandID == observed.CommandID
	}
	for _, r := range before.Idempotency {
		if matches(r) {
			return domain.IdempotencyRecord{}, false
		}
	}
	var selected domain.IdempotencyRecord
	count := 0
	for _, r := range next.Idempotency {
		if matches(r) {
			selected = r
			count++
		}
	}
	if count != 1 || selected.ContractProfile != "UA1" || selected.AggregateRevision != next.AggregateRevision {
		return domain.IdempotencyRecord{}, false
	}
	if observed.OperationID == "resendInvitationLink" {
		if len(selected.JobIDs) != 1 {
			return domain.IdempotencyRecord{}, false
		}
		found := false
		for _, j := range next.MailJobs {
			if j.JobID == selected.JobIDs[0] && j.Purpose == "invitation_link" && j.OrgID == observed.OrgID && j.InvitationID == observed.InvitationID {
				found = true
			}
		}
		if !found {
			return domain.IdempotencyRecord{}, false
		}
	}
	return selected, true
}
