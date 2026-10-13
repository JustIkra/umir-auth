package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type selector struct {
	Kind        string          `json:"kind"`
	ChallengeID domain.EntityID `json:"challengeID"`
	CommandID   string          `json:"commandID,omitempty"`
	OperationID string          `json:"operationID,omitempty"`
}
type discoveredJob struct {
	JobID       domain.EntityID `json:"jobID"`
	Channel     string          `json:"channel"`
	State       string          `json:"state"`
	Attempts    int             `json:"attempts"`
	AcceptedAt  domain.Instant  `json:"acceptedAt"`
	ChallengeID domain.EntityID `json:"challengeID"`
	ExpiresAt   domain.Instant  `json:"expiresAt"`
}
type jobResult struct {
	InstanceID      string          `json:"instanceID"`
	ClockGeneration string          `json:"clockGeneration"`
	Revision        domain.Version  `json:"aggregateRevision"`
	Selector        *selector       `json:"selector,omitempty"`
	CommandRevision *domain.Version `json:"commandAggregateRevision"`
	Jobs            []discoveredJob `json:"jobs"`
	Complete        bool            `json:"complete"`
}

func storeCode(e error) string {
	if errors.Is(e, application.ErrRecoveryRequired) {
		return "OutcomeUnknown"
	}
	return "StoreUnavailable"
}
func (h *Handler) jobs(ctx context.Context, r Request) (any, string) {
	var in struct {
		ExpectedInstanceID string            `json:"expectedInstanceID"`
		ExpectedGeneration string            `json:"expectedClockGeneration"`
		Selector           selector          `json:"selector"`
		JobIDs             []domain.EntityID `json:"jobIDs"`
		WaitMs             int               `json:"waitMs"`
	}
	if json.Unmarshal(r.Data, &in) != nil {
		return nil, "InvalidRequest"
	}
	if r.Operation == "owner.jobs" {
		state := h.opts.Clock.Read()
		in.ExpectedInstanceID = state.InstanceID
		in.ExpectedGeneration = state.Generation
	}
	deadline := time.NewTimer(time.Duration(in.WaitMs) * time.Millisecond)
	defer deadline.Stop()
	for {
		state, ok := h.opts.Clock.ReadExpected(in.ExpectedInstanceID, in.ExpectedGeneration)
		if !ok {
			return nil, "ClockConflict"
		}
		v, e := h.opts.Store.Load(ctx)
		if e != nil {
			return nil, storeCode(e)
		}
		a := v.Snapshot()
		after, ok := h.opts.Clock.ReadExpected(in.ExpectedInstanceID, in.ExpectedGeneration)
		if !ok || after.Instant != state.Instant {
			return nil, "ClockConflict"
		}
		result, code := projectJobs(a, in.Selector, in.JobIDs, r.Operation)
		if code == "" {
			result.InstanceID = state.InstanceID
			result.ClockGeneration = state.Generation
			if r.Operation == "owner.jobs" {
				return struct {
					InstanceID string          `json:"instanceID"`
					Generation string          `json:"clockGeneration"`
					Revision   domain.Version  `json:"aggregateRevision"`
					Jobs       []discoveredJob `json:"jobs"`
					Complete   bool            `json:"complete"`
				}{result.InstanceID, result.ClockGeneration, result.Revision, result.Jobs, true}, ""
			}
			return result, ""
		}
		if code != "NotFound" && code != "WaitExpired" {
			return nil, code
		}
		if in.WaitMs == 0 {
			return nil, code
		}
		poll := time.NewTimer(100 * time.Millisecond)
		select {
		case <-deadline.C:
			poll.Stop()
			return nil, code
		case <-ctx.Done():
			poll.Stop()
			return nil, "WaitExpired"
		case <-poll.C:
		}
	}
}
func projectJobs(a domain.Aggregate, sel selector, ids []domain.EntityID, operation string) (jobResult, string) {
	result := jobResult{Revision: a.AggregateRevision, Jobs: []discoveredJob{}, Complete: true}
	if len(a.Challenges)+len(a.MailJobs)+len(a.Idempotency) > 16384 {
		return result, "CapacityExceeded"
	}
	if operation == "owner.jobs.discover" {
		result.Selector = &sel
	}
	selected := map[domain.EntityID]bool{}
	if operation == "owner.jobs" {
		for _, id := range ids {
			if selected[id] {
				return result, "InvalidRequest"
			}
			selected[id] = true
		}
	} else {
		var challenge *domain.Challenge
		for i := range a.Challenges {
			if a.Challenges[i].ChallengeID == sel.ChallengeID {
				if challenge != nil {
					return result, "CorrelationConflict"
				}
				challenge = &a.Challenges[i]
			}
		}
		if challenge == nil {
			return result, "NotFound"
		}
		if sel.Kind == "challenge" {
			for _, j := range a.MailJobs {
				if j.ChallengeID == sel.ChallengeID {
					selected[j.JobID] = true
				}
			}
		} else {
			matches := 0
			for _, rec := range a.Idempotency {
				if rec.CommandID != sel.CommandID || rec.OperationID != sel.OperationID {
					continue
				}
				anchored := false
				for _, id := range rec.JobIDs {
					for _, j := range a.MailJobs {
						if j.JobID == id && j.ChallengeID == sel.ChallengeID {
							anchored = true
						}
					}
				}
				if !anchored {
					continue
				}
				matches++
				if len(rec.JobIDs) != 1 {
					return result, "CorrelationConflict"
				}
				n, ok := domain.VersionNumber(rec.AggregateRevision)
				current, cok := domain.VersionNumber(a.AggregateRevision)
				if !ok || !cok || n > current {
					return result, "CorrelationConflict"
				}
				rev := rec.AggregateRevision
				result.CommandRevision = &rev
				selected[rec.JobIDs[0]] = true
			}
			if matches > 1 {
				return result, "CorrelationConflict"
			}
		}
	}
	if len(selected) > 64 {
		return result, "CapacityExceeded"
	}
	if len(selected) == 0 {
		return result, "WaitExpired"
	}
	seen := map[domain.EntityID]bool{}
	for _, j := range a.MailJobs {
		if !selected[j.JobID] {
			continue
		}
		if seen[j.JobID] {
			return result, "CorrelationConflict"
		}
		seen[j.JobID] = true
		var c *domain.Challenge
		for i := range a.Challenges {
			if a.Challenges[i].ChallengeID == j.ChallengeID {
				if c != nil {
					return result, "CorrelationConflict"
				}
				c = &a.Challenges[i]
			}
		}
		if c == nil || operation == "owner.jobs.discover" && j.ChallengeID != sel.ChallengeID {
			return result, "CorrelationConflict"
		}
		state := j.State
		switch state {
		case "queued":
			state = "pending"
		case "delivered":
			state = "sent"
		case "sending", "unknown", "failed", "suppressed":
		default:
			return result, "NotReady"
		}
		if j.Attempts < 0 || j.Attempts > 100 {
			return result, "NotReady"
		}
		if _, e := parseInstant(string(j.AcceptedAt)); e != nil {
			return result, "NotReady"
		}
		if _, e := parseInstant(string(c.ExpiresAt)); e != nil {
			return result, "NotReady"
		}
		result.Jobs = append(result.Jobs, discoveredJob{j.JobID, "smtp", state, j.Attempts, j.AcceptedAt, j.ChallengeID, c.ExpiresAt})
	}
	if len(result.Jobs) != len(selected) {
		return result, "NotFound"
	}
	sort.Slice(result.Jobs, func(i, j int) bool { return result.Jobs[i].JobID < result.Jobs[j].JobID })
	return result, ""
}
