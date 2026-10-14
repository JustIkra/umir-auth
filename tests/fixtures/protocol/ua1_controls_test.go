package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type ua1ControlOwner struct {
	r        *bootstrap.Runtime
	clock    *Clock
	controls *UA1MailControls
	session  application.SessionView
	org      application.LifecycleResult
	opts     bootstrap.Options
}

func newUA1ControlOwner(t *testing.T) ua1ControlOwner {
	t.Helper()
	r, clock, opts := liveOwner(t)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	controls, err := NewUA1MailControls(HandlerOptions{Project: "umir-backend-000000000000000000000000", BinarySHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), Clock: clock, Store: r.Store}, r.AccountOptions.Results)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(controls.Close)
	accountOpts := r.AccountOptions
	accountOpts.Repository = controls.Repository()
	r.Accounts, err = application.NewAccounts(context.Background(), accountOpts)
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Accounts.Login(context.Background(), application.LoginInput{Login: opts.Initial.Login, Password: opts.Password})
	if err != nil {
		t.Fatal(err)
	}
	org, err := r.Accounts.CreateOrganization(context.Background(), session.Token, session.CSRFToken, application.CreateOrganizationInput{CommandID: "controls-org", Name: "Synthetic", TimeZone: "Europe/Moscow", FirstRestaurantName: "Synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Accounts.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	return ua1ControlOwner{r, clock, controls, session, org, opts}
}

func (o ua1ControlOwner) identity() UA1Identity {
	c := o.clock.Read()
	return UA1Identity{c.FixtureID, c.InstanceID, c.Generation, strings.Repeat("b", 64), strings.Repeat("c", 64)}
}

func (o ua1ControlOwner) create(t *testing.T, command string) (domain.Invitation, domain.MailJob) {
	t.Helper()
	inv, err := o.r.Accounts.CreateInvitation(context.Background(), o.session.Token, o.session.CSRFToken, o.org.OrgID, application.CreateInvitationInput{CommandID: command, Email: command + "@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: o.org.RestaurantIDs[0], Roles: []string{"Waiter"}}}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.r.Store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range a.Snapshot().MailJobs {
		if j.InvitationID == inv.InvitationID && j.Purpose == "invitation_link" {
			return inv, j
		}
	}
	t.Fatal("real link job absent")
	return domain.Invitation{}, domain.MailJob{}
}

func ua1ControlID(t *testing.T) string {
	t.Helper()
	id, err := UUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func ua1Body(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return SHA(b)
}

func (o ua1ControlOwner) command(t *testing.T, ctx context.Context, sel UA1CommandSelector, input any) context.Context {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := o.controls.CommandContext(ctx, sel, body)
	if err != nil {
		t.Fatal(err)
	}
	return observed
}

func (o ua1ControlOwner) arm(t *testing.T, in UA1ControlArm) UA1ControlRecord {
	t.Helper()
	v, code := o.controls.Arm(context.Background(), UA1ControlBindingSHA256, o.identity(), in)
	if code != "" {
		t.Fatal(code)
	}
	return v
}

func (o ua1ControlOwner) read(t *testing.T, id string) UA1ControlRecord {
	t.Helper()
	v, code := o.controls.Read(context.Background(), UA1ControlBindingSHA256, o.identity(), id)
	if code != "" {
		t.Fatal(code)
	}
	return v
}

func TestUA1ControlStorageMatchesRealCommandAndPreservesReplay(t *testing.T) {
	for _, point := range []string{"storage-before-commit", "storage-after-commit-unknown"} {
		t.Run(point, func(t *testing.T) {
			o := newUA1ControlOwner(t)
			in := application.CreateInvitationInput{CommandID: "controlled-create", Email: "controlled@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: o.org.RestaurantIDs[0], Roles: []string{"Waiter"}}}}
			sel := UA1CommandSelector{OperationID: "createInvitation", CommandID: in.CommandID, ActorID: o.session.User.UserID, OrgID: o.org.OrgID, BodySHA256: ua1Body(t, in)}
			id := ua1ControlID(t)
			o.arm(t, UA1ControlArm{ControlID: id, Point: point, LifetimeMS: 30000, Command: &sel})
			before, err := o.r.Store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx := o.command(t, context.Background(), sel, in)
			_, err = o.r.Accounts.CreateInvitation(ctx, o.session.Token, o.session.CSRFToken, o.org.OrgID, in)
			if err == nil {
				t.Fatal("storage control did not reach the real command")
			}
			after, err := o.r.Store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			r := o.read(t, id)
			if r.State != "effected" || r.Hits != 1 || r.HitSequence <= r.ArmSequence || r.EffectSequence <= r.HitSequence {
				t.Fatal("missing ordered actual effect", r)
			}
			if point == "storage-before-commit" {
				if after.Revision() != before.Revision() || len(after.Snapshot().MailJobs) != 0 || r.StoreOutcome != "not-called" || r.ReturnedOutcome != "not_committed" {
					t.Fatal("precommit fault changed storage", r)
				}
			} else {
				if after.Revision() == before.Revision() || len(after.Snapshot().MailJobs) != 1 || r.StoreOutcome != "committed" || r.ReturnedOutcome != "unknown" || r.AggregateRevision != after.Revision() {
					t.Fatal("unknown replaced a real commit", r)
				}
				accountOpts := o.r.AccountOptions
				accountOpts.Repository = o.controls.Repository()
				o.r.Accounts, err = application.NewAccounts(context.Background(), accountOpts)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = o.r.Accounts.CreateInvitation(ctx, o.session.Token, o.session.CSRFToken, o.org.OrgID, in); err != nil {
					t.Fatal(err)
				}
				replayed, err := o.r.Store.Load(context.Background())
				if err != nil || replayed.Revision() != after.Revision() || o.read(t, id).Hits != 1 {
					t.Fatal("replay repeated the commit/fault")
				}
			}
		})
	}
}

func TestUA1ControlResendAndBodyScopeMismatch(t *testing.T) {
	o := newUA1ControlOwner(t)
	inv, _ := o.create(t, "resend-source")
	c := o.clock.Read()
	if code := o.clock.Set(c.InstanceID, c.Generation, "2026-10-13T09:01:00+03:00"); code != "" {
		t.Fatal(code)
	}
	sel := UA1CommandSelector{OperationID: "resendInvitationLink", CommandID: "controlled-resend", ActorID: o.session.User.UserID, OrgID: o.org.OrgID, InvitationID: inv.InvitationID, BodySHA256: ua1Body(t, map[string]string{"commandID": "controlled-resend"})}
	id := ua1ControlID(t)
	o.arm(t, UA1ControlArm{ControlID: id, Point: "storage-before-commit", LifetimeMS: 30000, Command: &sel})
	wrong := sel
	wrong.BodySHA256 = strings.Repeat("d", 64)
	body, err := json.Marshal(map[string]string{"commandID": sel.CommandID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.controls.CommandContext(context.Background(), wrong, body); err == nil {
		t.Fatal("body digest mismatch created a private observation")
	}
	if _, err := o.r.Accounts.ResendInvitationLink(context.Background(), o.session.Token, o.session.CSRFToken, o.org.OrgID, inv.InvitationID, sel.CommandID); err != nil {
		t.Fatal(err)
	}
	if o.read(t, id).Hits != 0 {
		t.Fatal("foreign body hit a command fault")
	}
	if _, err := o.r.Accounts.ResendInvitationLink(o.command(t, context.Background(), sel, map[string]string{"commandID": sel.CommandID}), o.session.Token, o.session.CSRFToken, o.org.OrgID, inv.InvitationID, sel.CommandID); err != nil {
		t.Fatal(err)
	}
	if o.read(t, id).Hits != 0 {
		t.Fatal("durable replay hit a command fault")
	}
	sel.CommandID = "controlled-resend-two"
	sel.BodySHA256 = ua1Body(t, map[string]string{"commandID": sel.CommandID})
	c = o.clock.Read()
	if code := o.clock.Set(c.InstanceID, c.Generation, "2026-10-13T09:02:00+03:00"); code != "" {
		t.Fatal(code)
	}
	id = ua1ControlID(t)
	o.arm(t, UA1ControlArm{ControlID: id, Point: "storage-before-commit", LifetimeMS: 30000, Command: &sel})
	_, err = o.r.Accounts.ResendInvitationLink(o.command(t, context.Background(), sel, map[string]string{"commandID": sel.CommandID}), o.session.Token, o.session.CSRFToken, o.org.OrgID, inv.InvitationID, sel.CommandID)
	if !errors.Is(err, application.ErrStorageUnavailable) || o.read(t, id).Hits != 1 {
		t.Fatal("new link resend not controlled", err)
	}
}

type ua1CountingSender struct {
	calls  atomic.Int32
	result application.DeliveryResult
}

func (s *ua1CountingSender) Send(context.Context, application.MailDelivery) application.DeliveryResult {
	s.calls.Add(1)
	return s.result
}

func waitUA1ControlHit(t *testing.T, o ua1ControlOwner, id string) UA1ControlRecord {
	t.Helper()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		v := o.read(t, id)
		if v.State == "hit" {
			return v
		}
		select {
		case <-timeout.C:
			t.Fatal("barrier never reached", v)
			return v
		case <-tick.C:
		}
	}
}

func TestUA1ControlClaimAndResultBarriersObserveRealOwner(t *testing.T) {
	for _, point := range []string{"after-durable-claim", "after-send-before-result"} {
		t.Run(point, func(t *testing.T) {
			o := newUA1ControlOwner(t)
			inv, job := o.create(t, "barrier-invite")
			sel := UA1Selector{Kind: "invitation_link", OrgID: o.org.OrgID, InvitationID: inv.InvitationID, JobID: job.JobID}
			id := ua1ControlID(t)
			o.arm(t, UA1ControlArm{ControlID: id, Point: point, LifetimeMS: 30000, Link: &sel})
			sender := &ua1CountingSender{result: application.DeliveryResult{Success: true}}
			done := make(chan error, 1)
			go func() { _, err := o.controls.ProcessMail(context.Background(), o.r.Accounts, sender); done <- err }()
			hit := waitUA1ControlHit(t, o, id)
			if hit.Attempt != 1 || hit.AggregateRevision == "" || hit.HitIdentity == nil || hit.HitIdentity.ClockGeneration != "1" {
				t.Fatal("claim provenance missing", hit)
			}
			hit.HitIdentity.ClockGeneration = "999"
			if o.read(t, id).HitIdentity.ClockGeneration != "1" {
				t.Fatal("caller changed retained hit identity")
			}
			a, err := o.r.Store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if a.Snapshot().MailJobs[0].State != "sending" || a.Snapshot().MailJobs[0].Attempts != 1 {
				t.Fatal("barrier preceded durable claim")
			}
			want := int32(0)
			if point == "after-send-before-result" {
				want = 1
				if hit.SenderResult != "success" {
					t.Fatal("actual sender result absent")
				}
			}
			if sender.calls.Load() != want {
				t.Fatal("sender boundary is misplaced")
			}
			c := o.clock.Read()
			if code := o.clock.Set(c.InstanceID, c.Generation, "2026-10-13T09:01:00+03:00"); code != "" {
				t.Fatal(code)
			}
			if _, code := o.controls.Release(context.Background(), UA1ControlBindingSHA256, o.identity(), id); code != "" {
				t.Fatal(code)
			}
			select {
			case err = <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("release did not drain worker")
			}
			result := o.read(t, id)
			if result.State != "effected" || result.HitIdentity.ClockGeneration != "1" || result.ReleaseIdentity == nil || result.ReleaseIdentity.ClockGeneration != "2" || result.EffectSequence <= result.ReleaseSequence {
				t.Fatal("barrier provenance relabelled", result)
			}
			a, err = o.r.Store.Load(context.Background())
			if err != nil || a.Snapshot().MailJobs[0].State != "delivered" || sender.calls.Load() != 1 {
				t.Fatal("released real delivery did not finish")
			}
		})
	}
}

func TestUA1ControlCancellationLeavesDurableClaimForRealRecovery(t *testing.T) {
	o := newUA1ControlOwner(t)
	inv, job := o.create(t, "cancel-barrier")
	sel := UA1Selector{Kind: "invitation_link", OrgID: o.org.OrgID, InvitationID: inv.InvitationID, JobID: job.JobID}
	id := ua1ControlID(t)
	o.arm(t, UA1ControlArm{ControlID: id, Point: "after-durable-claim", LifetimeMS: 30000, Link: &sel})
	sender := &ua1CountingSender{result: application.DeliveryResult{Success: true}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := o.controls.ProcessMail(ctx, o.r.Accounts, sender); done <- err }()
	waitUA1ControlHit(t, o, id)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not drain")
	}
	if sender.calls.Load() != 0 || o.read(t, id).State != "cancelled" {
		t.Fatal("cancel sent IO or fabricated release")
	}
	if err := o.r.Accounts.RecoverMail(context.Background()); err != nil {
		t.Fatal(err)
	}
	a, err := o.r.Store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	j := a.Snapshot().MailJobs[0]
	if j.State != "unknown" || j.JobID != job.JobID || j.Attempts != 1 || j.NextAttemptAt != "2026-10-13T09:01:00+03:00" {
		t.Fatal("actual recovery lost claimed linkage", j.State)
	}
}
