package protocol

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
)

type ua1ObservedProcessor struct {
	controls    *UA1MailControls
	active, max atomic.Int32
}

func (p *ua1ObservedProcessor) ProcessMail(ctx context.Context, a *application.Accounts, s application.MailSender) (bool, error) {
	n := p.active.Add(1)
	defer p.active.Add(-1)
	if n > p.max.Load() {
		p.max.Store(n)
	}
	return p.controls.ProcessMail(ctx, a, s)
}

func TestUA1ControlWorkerRoutesOneRealServedInvocation(t *testing.T) {
	o, h, _ := ua1WireOwner(t)
	inv, job := o.create(t, "served-worker")
	before, claim, result := ua1ControlID(t), ua1ControlID(t), ua1ControlID(t)
	link := UA1Selector{Kind: "invitation_link", OrgID: o.org.OrgID, InvitationID: inv.InvitationID, JobID: job.JobID}
	for _, in := range []UA1ControlArm{{ControlID: before, Point: "before-process-mail", LifetimeMS: 30000}, {ControlID: claim, Point: "after-durable-claim", LifetimeMS: 30000, Link: &link}, {ControlID: result, Point: "after-send-before-result", LifetimeMS: 30000, Link: &link}} {
		if res := ua1WireCall(t, h, ua1WireRequest(t, o, "control.arm", "", &in)); res.Code != 200 {
			t.Fatal("valid served barrier refused", res.Code)
		}
	}
	owner, err := o.r.Handler(map[string]string{"gateway": strings.Repeat("a", 64), "serving": strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	sender := &ua1CountingSender{result: application.DeliveryResult{Success: true}}
	processor := &ua1ObservedProcessor{controls: o.controls}
	go func() { done <- o.r.ServeWithMailProcessor(ctx, l, owner, sender, processor) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("served worker did not drain")
		}
	})
	waitUA1ControlHit(t, o, before)
	a, err := o.r.Store.Load(context.Background())
	if err != nil || a.Snapshot().MailJobs[0].State != "queued" || sender.calls.Load() != 0 {
		t.Fatal("another worker bypassed the invocation gate")
	}
	for _, id := range []string{before, claim, result} {
		if id != before {
			waitUA1ControlHit(t, o, id)
		}
		if id == claim && sender.calls.Load() != 0 || id == result && sender.calls.Load() != 1 {
			t.Fatal("actual sender boundary order changed")
		}
		if res := ua1WireCall(t, h, ua1WireRequest(t, o, "control.release", id, nil)); res.Code != http.StatusOK {
			t.Fatal("served barrier release failed", res.Code)
		}
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		a, err = o.r.Store.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if a.Snapshot().MailJobs[0].State == "delivered" {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("real served result was not committed")
		case <-tick.C:
		}
	}
	if sender.calls.Load() != 1 || processor.max.Load() != 1 {
		t.Fatal("served invocation/IO was duplicated")
	}
}
