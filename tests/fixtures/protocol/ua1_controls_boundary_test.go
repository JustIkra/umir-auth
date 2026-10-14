package protocol

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type ua1CancelOnSecondCheck struct {
	context.Context
	checks atomic.Int32
}

func (c *ua1CancelOnSecondCheck) Err() error {
	if c.checks.Add(1) >= 2 {
		return context.Canceled
	}
	return nil
}

func TestUA1ControlAdmissionAndBoundedRetention(t *testing.T) {
	o := newUA1ControlOwner(t)
	in := UA1ControlArm{ControlID: ua1ControlID(t), Point: "before-process-mail", LifetimeMS: 100}
	for _, wrong := range []UA1ControlArm{
		{ControlID: in.ControlID, Point: "assign-sent", LifetimeMS: 100},
		{ControlID: in.ControlID, Point: "before-process-mail", LifetimeMS: 99},
		{ControlID: in.ControlID, Point: "before-process-mail", LifetimeMS: 30001},
		{ControlID: in.ControlID, Point: "after-durable-claim", LifetimeMS: 100, Link: &UA1Selector{Kind: "otp", ChallengeID: "11111111-1111-4111-8111-111111111111"}},
		{ControlID: in.ControlID, Point: "storage-before-commit", LifetimeMS: 100, Command: &UA1CommandSelector{OperationID: "resendInvitation"}},
	} {
		if _, code := o.controls.Arm(context.Background(), UA1ControlBindingSHA256, o.identity(), wrong); code != "InvalidRequest" {
			t.Fatal("open control admitted", code)
		}
	}
	wrong := o.identity()
	wrong.InstanceID = "99999999-9999-4999-8999-999999999999"
	if _, code := o.controls.Arm(context.Background(), UA1ControlBindingSHA256, wrong, in); code != "IdentityConflict" {
		t.Fatal(code)
	}
	wrong = o.identity()
	wrong.ClockGeneration = "2"
	if _, code := o.controls.Arm(context.Background(), UA1ControlBindingSHA256, wrong, in); code != "ClockConflict" {
		t.Fatal(code)
	}
	if _, code := o.controls.Arm(context.Background(), strings.Repeat("d", 64), o.identity(), in); code != "IdentityConflict" {
		t.Fatal(code)
	}
	if _, code := o.controls.Arm(&ua1CancelOnSecondCheck{Context: context.Background()}, UA1ControlBindingSHA256, o.identity(), in); code != "WaitExpired" {
		t.Fatal("cancellation after first check armed a control", code)
	}
	o.controls.mu.Lock()
	count := len(o.controls.records)
	o.controls.mu.Unlock()
	if count != 0 {
		t.Fatal("rejected admission mutated controls")
	}
	first := o.arm(t, in)
	same := o.arm(t, in)
	if first != same {
		t.Fatal("arm replay changed original record")
	}
	changed := in
	changed.LifetimeMS = 101
	if _, code := o.controls.Arm(context.Background(), UA1ControlBindingSHA256, o.identity(), changed); code != "CorrelationConflict" {
		t.Fatal("control identity reused", code)
	}
	changed = in
	changed.ControlID = ua1ControlID(t)
	if _, code := o.controls.Arm(context.Background(), UA1ControlBindingSHA256, o.identity(), changed); code != "ControlConflict" {
		t.Fatal("overlapping control armed", code)
	}
	if _, code := o.controls.Cancel(context.Background(), UA1ControlBindingSHA256, o.identity(), in.ControlID); code != "" {
		t.Fatal(code)
	}
	for i := 1; i < 64; i++ {
		in.ControlID = ua1ControlID(t)
		o.arm(t, in)
		if _, code := o.controls.Cancel(context.Background(), UA1ControlBindingSHA256, o.identity(), in.ControlID); code != "" {
			t.Fatal(code)
		}
	}
	in.ControlID = ua1ControlID(t)
	if _, code := o.controls.Arm(context.Background(), UA1ControlBindingSHA256, o.identity(), in); code != "CapacityExceeded" {
		t.Fatal("retention bound evicted evidence", code)
	}
}

func TestUA1ControlBeforeProcessAllowsRealCancellationBeforeClaim(t *testing.T) {
	o := newUA1ControlOwner(t)
	inv, _ := o.create(t, "before-claim")
	id := ua1ControlID(t)
	o.arm(t, UA1ControlArm{ControlID: id, Point: "before-process-mail", LifetimeMS: 30000})
	sender := &ua1CountingSender{result: application.DeliveryResult{Success: true}}
	done := make(chan error, 1)
	go func() { _, err := o.controls.ProcessMail(context.Background(), o.r.Accounts, sender); done <- err }()
	waitUA1ControlHit(t, o, id)
	if _, err := o.r.Accounts.CancelInvitation(context.Background(), o.session.Token, o.session.CSRFToken, o.org.OrgID, inv.InvitationID, "cancel-before-claim"); err != nil {
		t.Fatal(err)
	}
	if _, code := o.controls.Release(context.Background(), UA1ControlBindingSHA256, o.identity(), id); code != "" {
		t.Fatal(code)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not drain")
	}
	a, err := o.r.Store.Load(context.Background())
	if err != nil || sender.calls.Load() != 0 || a.Snapshot().MailJobs[0].State != "suppressed" || a.Snapshot().MailJobs[0].Attempts != 0 {
		t.Fatal("preclaim cancellation did not suppress real job")
	}
}

func TestUA1ControlHeldBarrierExpiresAndCancelsIO(t *testing.T) {
	o := newUA1ControlOwner(t)
	inv, job := o.create(t, "expire-barrier")
	sel := UA1Selector{Kind: "invitation_link", OrgID: o.org.OrgID, InvitationID: inv.InvitationID, JobID: job.JobID}
	id := ua1ControlID(t)
	o.arm(t, UA1ControlArm{ControlID: id, Point: "after-durable-claim", LifetimeMS: 100, Link: &sel})
	sender := &ua1CountingSender{result: application.DeliveryResult{Success: true}}
	_, err := o.controls.ProcessMail(context.Background(), o.r.Accounts, sender)
	if !errors.Is(err, context.Canceled) || sender.calls.Load() != 0 {
		t.Fatal("expired gate started IO", err)
	}
	r := o.read(t, id)
	if r.State != "expired" || r.Hits != 1 || r.ReleaseSequence != 0 || r.Effect != "cancelled" {
		t.Fatal("expiration fabricated release", r)
	}
}

func TestUA1ControlCloseAfterReleasePreventsContinuation(t *testing.T) {
	o := newUA1ControlOwner(t)
	id := ua1ControlID(t)
	o.arm(t, UA1ControlArm{ControlID: id, Point: "before-process-mail", LifetimeMS: 30000})
	o.controls.mu.Lock()
	a := o.controls.records[id]
	err := o.controls.hit(context.Background(), a)
	o.controls.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := o.controls.Release(context.Background(), UA1ControlBindingSHA256, o.identity(), id); code != "" {
		t.Fatal(code)
	}
	o.controls.Close()
	if err = o.controls.wait(context.Background(), a); err == nil {
		t.Fatal("closed controller continued released work")
	}
}

func TestUA1ControlClockProgressBeforeHitAndCopiesAreImmutable(t *testing.T) {
	o := newUA1ControlOwner(t)
	inv, job := o.create(t, "stale-control")
	sel := UA1Selector{Kind: "invitation_link", OrgID: o.org.OrgID, InvitationID: inv.InvitationID, JobID: job.JobID}
	id := ua1ControlID(t)
	o.arm(t, UA1ControlArm{ControlID: id, Point: "after-durable-claim", LifetimeMS: 30000, Link: &sel})
	sel.JobID = "99999999-9999-4999-8999-999999999999"
	c := o.clock.Read()
	if code := o.clock.Set(c.InstanceID, c.Generation, c.Instant); code != "" {
		t.Fatal(code)
	}
	sender := &ua1CountingSender{result: application.DeliveryResult{Success: true}}
	_, err := o.controls.ProcessMail(context.Background(), o.r.Accounts, sender)
	if !errors.Is(err, context.Canceled) || sender.calls.Load() != 0 {
		t.Fatal("stale arm hit or caller modified selector", err)
	}
	r := o.read(t, id)
	if r.Hits != 0 || r.State != "identity-conflict" || r.ArmIdentity.ClockGeneration != "1" || r.EffectSequence <= r.ArmSequence || r.EffectIdentity == nil || r.EffectIdentity.ClockGeneration != "2" {
		t.Fatal("stale arm relabelled", r)
	}
}

type ua1RejectingWriter struct {
	store application.AggregateRepository
}

func (r ua1RejectingWriter) Load(ctx context.Context) (domain.ValidatedAggregate, error) {
	return r.store.Load(ctx)
}
func (r ua1RejectingWriter) Commit(ctx context.Context, _ domain.Version, next domain.ValidatedAggregate) (application.CommitResult, error) {
	return r.store.Commit(ctx, "999999", next)
}

func TestUA1ControlUnknownRequiresActualCommittedWriterResult(t *testing.T) {
	o := newUA1ControlOwner(t)
	o.controls.opts.Store = ua1RejectingWriter{o.r.Store}
	in := application.CreateInvitationInput{CommandID: "writer-rejected", Email: "rejected@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: o.org.RestaurantIDs[0], Roles: []string{"Waiter"}}}}
	sel := UA1CommandSelector{OperationID: "createInvitation", CommandID: in.CommandID, ActorID: o.session.User.UserID, OrgID: o.org.OrgID, BodySHA256: ua1Body(t, in)}
	id := ua1ControlID(t)
	o.arm(t, UA1ControlArm{ControlID: id, Point: "storage-after-commit-unknown", LifetimeMS: 30000, Command: &sel})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := o.r.Accounts.CreateInvitation(o.command(t, ctx, sel, in), o.session.Token, o.session.CSRFToken, o.org.OrgID, in)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, application.ErrUpdateOutcomeUnknown) {
		t.Fatal("uncommitted writer result replaced with unknown", err)
	}
	r := o.read(t, id)
	if r.Hits != 0 || r.State != "not-hit" || r.StoreOutcome != "not_committed" || r.ReturnedOutcome != "not_committed" {
		t.Fatal("unknown control fabricated a committed hit", r)
	}
	a, err := o.r.Store.Load(context.Background())
	if err != nil || len(a.Snapshot().MailJobs) != 0 {
		t.Fatal("rejected writer mutated authority")
	}
}
