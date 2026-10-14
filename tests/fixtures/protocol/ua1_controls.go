package protocol

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

//go:embed ua1-controls.binding.json
var ua1ControlBinding []byte

var errUA1Barrier = errors.New("UA1 mail barrier did not continue")

type UA1MailControls struct {
	opts     HandlerOptions
	results  UA1CommandDigest
	mu       sync.Mutex
	records  map[string]*ua1Control
	sequence uint64
	closed   bool
	worker   chan struct{}
}

type ua1Control struct {
	arm       UA1ControlArm
	canonical string
	until     time.Time
	reserved  bool
	done      chan struct{}
	finished  bool
	record    UA1ControlRecord
}

func NewUA1MailControls(opts HandlerOptions, results UA1CommandDigest) (*UA1MailControls, error) {
	var binding struct{ Supplement, DiscoveryBindingSHA256, ContractSHA256 string }
	if !projectPattern.MatchString(opts.Project) || !digestPattern.MatchString(opts.BinarySHA256) || !digestPattern.MatchString(opts.ConfigSHA256) || opts.Clock == nil || opts.Store == nil || results == nil || SHA(ua1ControlBinding) != UA1ControlBindingSHA256 || json.Unmarshal(ua1ControlBinding, &binding) != nil || binding.Supplement != UA1ControlSupplement || binding.DiscoveryBindingSHA256 != UA1BindingSHA256 || !digestPattern.MatchString(binding.ContractSHA256) {
		return nil, errors.New("invalid UA1 mail control dependencies")
	}
	c := opts.Clock.Read()
	if !c.Healthy || !uuidPattern.MatchString(c.FixtureID) || !uuidPattern.MatchString(c.InstanceID) || !generationPattern.MatchString(c.Generation) {
		return nil, errors.New("invalid UA1 mail control identity")
	}
	return &UA1MailControls{opts: opts, results: results, records: map[string]*ua1Control{}, worker: make(chan struct{}, 1)}, nil
}

func (c *UA1MailControls) identity() UA1Identity {
	v := c.opts.Clock.Read()
	return UA1Identity{v.FixtureID, v.InstanceID, v.Generation, c.opts.BinarySHA256, c.opts.ConfigSHA256}
}

func sameUA1Instance(a, b UA1Identity) bool {
	return a.FixtureID == b.FixtureID && a.InstanceID == b.InstanceID && a.BinarySHA256 == b.BinarySHA256 && a.ConfigSHA256 == b.ConfigSHA256
}

func (c *UA1MailControls) admit(ctx context.Context, binding string, expected UA1Identity) string {
	if ctx.Err() != nil {
		return "WaitExpired"
	}
	if c.closed {
		return "NotReady"
	}
	actual := c.identity()
	if binding != UA1ControlBindingSHA256 || !sameUA1Instance(expected, actual) {
		return "IdentityConflict"
	}
	if expected.ClockGeneration != actual.ClockGeneration {
		return "ClockConflict"
	}
	if !c.opts.Clock.Read().Healthy {
		return "NotReady"
	}
	return ""
}

func validUA1ControlArm(in UA1ControlArm) bool {
	if !uuidPattern.MatchString(in.ControlID) || in.LifetimeMS < 100 || in.LifetimeMS > 30000 {
		return false
	}
	switch in.Point {
	case "storage-before-commit", "storage-after-commit-unknown":
		if in.Command == nil || in.Link != nil {
			return false
		}
		s := in.Command
		if !uuidPattern.MatchString(string(s.ActorID)) || !uuidPattern.MatchString(string(s.OrgID)) || !digestPattern.MatchString(s.BodySHA256) || len(s.CommandID) < 1 || len(s.CommandID) > 256 || !utf8.ValidString(s.CommandID) || strings.HasPrefix(s.CommandID, "expiration/") {
			return false
		}
		return s.OperationID == "createInvitation" && s.InvitationID == "" || s.OperationID == "resendInvitationLink" && uuidPattern.MatchString(string(s.InvitationID))
	case "before-process-mail":
		return in.Command == nil && in.Link == nil
	case "after-durable-claim", "after-send-before-result":
		if in.Link == nil || in.Command != nil {
			return false
		}
		s := in.Link
		return s.Kind == "invitation_link" && s.ChallengeID == "" && uuidPattern.MatchString(string(s.OrgID)) && uuidPattern.MatchString(string(s.InvitationID)) && uuidPattern.MatchString(string(s.JobID))
	default:
		return false
	}
}

func cloneUA1Arm(in UA1ControlArm) UA1ControlArm {
	if in.Command != nil {
		v := *in.Command
		in.Command = &v
	}
	if in.Link != nil {
		v := *in.Link
		in.Link = &v
	}
	return in
}

func cloneUA1Record(in UA1ControlRecord) UA1ControlRecord {
	if in.HitIdentity != nil {
		v := *in.HitIdentity
		in.HitIdentity = &v
	}
	if in.ReleaseIdentity != nil {
		v := *in.ReleaseIdentity
		in.ReleaseIdentity = &v
	}
	if in.EffectIdentity != nil {
		v := *in.EffectIdentity
		in.EffectIdentity = &v
	}
	return in
}

func sameUA1Population(a, b UA1ControlArm) bool {
	if a.Command != nil && b.Command != nil {
		x, y := a.Command, b.Command
		return x.OperationID == y.OperationID && x.CommandID == y.CommandID && x.ActorID == y.ActorID && x.OrgID == y.OrgID
	}
	if a.Point != b.Point {
		return false
	}
	if a.Link != nil && b.Link != nil {
		return *a.Link == *b.Link
	}
	return a.Point == "before-process-mail"
}

func (c *UA1MailControls) next() uint64 { c.sequence++; return c.sequence }

func (c *UA1MailControls) finish(a *ua1Control, state, reason string) {
	a.record.State = state
	a.record.Reason = reason
	if !a.finished {
		close(a.done)
		a.finished = true
	}
}

func (c *UA1MailControls) expire(a *ua1Control) {
	if (a.record.State == "armed" || a.record.State == "hit") && !time.Now().Before(a.until) {
		c.finish(a, "expired", "control-deadline")
		v := c.identity()
		a.record.EffectIdentity = &v
		a.record.EffectSequence = c.next()
		if a.record.Hits > 0 {
			a.record.Effect = "cancelled"
		}
	}
}

func (c *UA1MailControls) Arm(ctx context.Context, binding string, expected UA1Identity, in UA1ControlArm) (UA1ControlRecord, string) {
	if ctx.Err() != nil {
		return UA1ControlRecord{}, "WaitExpired"
	}
	if !validUA1ControlArm(in) {
		return UA1ControlRecord{}, "InvalidRequest"
	}
	data, err := json.Marshal(struct {
		Expected UA1Identity
		Arm      UA1ControlArm
	}{expected, in})
	if err != nil {
		return UA1ControlRecord{}, "InvalidRequest"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if code := c.admit(ctx, binding, expected); code != "" {
		return UA1ControlRecord{}, code
	}
	if prior := c.records[in.ControlID]; prior != nil {
		if prior.canonical != string(data) {
			return UA1ControlRecord{}, "CorrelationConflict"
		}
		c.expire(prior)
		return cloneUA1Record(prior.record), ""
	}
	if len(c.records) >= 64 {
		return UA1ControlRecord{}, "CapacityExceeded"
	}
	for _, a := range c.records {
		c.expire(a)
		if (a.reserved || a.record.State == "armed" || a.record.State == "hit") && sameUA1Population(a.arm, in) {
			return UA1ControlRecord{}, "ControlConflict"
		}
	}
	a := &ua1Control{arm: cloneUA1Arm(in), canonical: string(data), until: time.Now().Add(time.Duration(in.LifetimeMS) * time.Millisecond), done: make(chan struct{}), record: UA1ControlRecord{Version: 1, Supplement: UA1ControlSupplement, BindingSHA256: UA1ControlBindingSHA256, Project: c.opts.Project, Owner: "auth", ControlID: in.ControlID, Point: in.Point, State: "armed", Effect: "not-observed", ArmIdentity: expected, ArmSequence: c.next(), StoreOutcome: "not-observed", ReturnedOutcome: "not-observed", SenderResult: "not-observed"}}
	c.records[in.ControlID] = a
	return cloneUA1Record(a.record), ""
}

func (c *UA1MailControls) Read(ctx context.Context, binding string, expected UA1Identity, id string) (UA1ControlRecord, string) {
	if ctx.Err() != nil {
		return UA1ControlRecord{}, "WaitExpired"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if code := c.admit(ctx, binding, expected); code != "" {
		return UA1ControlRecord{}, code
	}
	a := c.records[id]
	if a == nil {
		return UA1ControlRecord{}, "NotFound"
	}
	c.expire(a)
	return cloneUA1Record(a.record), ""
}

func (c *UA1MailControls) Release(ctx context.Context, binding string, expected UA1Identity, id string) (UA1ControlRecord, string) {
	if ctx.Err() != nil {
		return UA1ControlRecord{}, "WaitExpired"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if code := c.admit(ctx, binding, expected); code != "" {
		return UA1ControlRecord{}, code
	}
	a := c.records[id]
	if a == nil {
		return UA1ControlRecord{}, "NotFound"
	}
	c.expire(a)
	if !sameUA1Instance(a.record.ArmIdentity, expected) {
		return UA1ControlRecord{}, "IdentityConflict"
	}
	if a.record.State == "released" || a.record.State == "effected" && a.record.ReleaseSequence != 0 {
		return cloneUA1Record(a.record), ""
	}
	if a.record.State != "hit" || a.arm.Command != nil {
		return UA1ControlRecord{}, "ControlConflict"
	}
	a.record.ReleaseIdentity = &expected
	a.record.ReleaseSequence = c.next()
	c.finish(a, "released", "")
	return cloneUA1Record(a.record), ""
}

func (c *UA1MailControls) Cancel(ctx context.Context, binding string, expected UA1Identity, id string) (UA1ControlRecord, string) {
	if ctx.Err() != nil {
		return UA1ControlRecord{}, "WaitExpired"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if code := c.admit(ctx, binding, expected); code != "" {
		return UA1ControlRecord{}, code
	}
	a := c.records[id]
	if a == nil {
		return UA1ControlRecord{}, "NotFound"
	}
	c.expire(a)
	if a.record.State == "armed" || a.record.State == "hit" {
		c.cancel(a, "controller-cancelled")
	}
	return cloneUA1Record(a.record), ""
}

func (c *UA1MailControls) cancel(a *ua1Control, reason string) {
	c.finish(a, "cancelled", reason)
	a.record.Effect = "cancelled"
	a.record.EffectSequence = c.next()
	v := c.identity()
	a.record.EffectIdentity = &v
}

func (c *UA1MailControls) conflict(a *ua1Control, reason string) {
	c.finish(a, "identity-conflict", reason)
	a.record.Effect = "cancelled"
	a.record.EffectSequence = c.next()
	v := c.identity()
	a.record.EffectIdentity = &v
}

func (c *UA1MailControls) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for _, a := range c.records {
		if a.record.State == "armed" || a.record.State == "hit" || a.record.State == "released" {
			c.cancel(a, "controller-closed")
		}
	}
}

func (c *UA1MailControls) hit(ctx context.Context, a *ua1Control) error {
	c.expire(a)
	if a.record.State != "armed" {
		return errUA1Barrier
	}
	if ctx.Err() != nil {
		c.cancel(a, "caller-cancelled")
		return ctx.Err()
	}
	if c.closed {
		return errUA1Barrier
	}
	actual := c.identity()
	if actual != a.record.ArmIdentity || !c.opts.Clock.Read().Healthy {
		c.conflict(a, "owner-progress-before-hit")
		return errUA1Barrier
	}
	a.record.Hits = 1
	a.record.State = "hit"
	a.record.HitIdentity = &actual
	a.record.HitSequence = c.next()
	return nil
}

func (c *UA1MailControls) wait(ctx context.Context, a *ua1Control) error {
	timer := time.NewTimer(time.Until(a.until))
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
		case <-a.done:
		case <-timer.C:
		case <-tick.C:
		}
		c.mu.Lock()
		c.expire(a)
		if c.closed && (a.record.State == "hit" || a.record.State == "released") {
			c.cancel(a, "controller-closed")
		}
		if ctx.Err() != nil && (a.record.State == "hit" || a.record.State == "released") {
			c.cancel(a, "caller-cancelled")
		}
		actual := c.identity()
		if !sameUA1Instance(actual, a.record.ArmIdentity) || !c.opts.Clock.Read().Healthy {
			c.conflict(a, "owner-instance-changed")
		}
		switch a.record.State {
		case "released":
			a.record.State = "effected"
			a.record.Effect = "continued"
			a.record.EffectIdentity = &actual
			a.record.EffectSequence = c.next()
			c.mu.Unlock()
			return nil
		case "hit":
			c.mu.Unlock()
		default:
			c.mu.Unlock()
			if err := ctx.Err(); err != nil {
				return err
			}
			return errUA1Barrier
		}
	}
}
