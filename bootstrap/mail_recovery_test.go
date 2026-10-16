package bootstrap_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type mailWorkerClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *mailWorkerClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *mailWorkerClock) advance()       { c.mu.Lock(); defer c.mu.Unlock(); c.at = c.at.Add(time.Minute) }

type mailWorkerPeers struct{}

func (mailWorkerPeers) Status(_ context.Context, service string) (application.RuntimeStatus, error) {
	return application.RuntimeStatus{Service: service, Epoch: "22222222-2222-4222-8222-222222222222", Ready: true, TZDataVersion: "2026a"}, nil
}
func (mailWorkerPeers) Register(_ context.Context, service string, id domain.EntityID, in application.RegisterRuntime) (domain.PeerReadiness, error) {
	return domain.PeerReadiness{RestaurantID: id, Service: service, Epoch: in.ExpectedEpoch, State: "ready", LifecycleVersion: in.LifecycleVersion}, nil
}
func (mailWorkerPeers) Close(_ context.Context, service string, id domain.EntityID, in application.CloseRuntime) (domain.PeerReadiness, error) {
	return domain.PeerReadiness{RestaurantID: id, Service: service, Epoch: in.ExpectedEpoch, State: "closed", LifecycleVersion: in.LifecycleVersion}, nil
}

type attemptDeadlineSender struct {
	attempt context.Context
	claimed chan application.MailDelivery
}

func (s attemptDeadlineSender) Send(_ context.Context, d application.MailDelivery) application.DeliveryResult {
	s.claimed <- d
	<-s.attempt.Done()
	return application.DeliveryResult{Unknown: true, Code: "synthetic_lost_reply"}
}

type mailSuccessSender struct{ sent chan application.MailDelivery }

func (s mailSuccessSender) Send(_ context.Context, d application.MailDelivery) application.DeliveryResult {
	s.sent <- d
	return application.DeliveryResult{Success: true, Code: "smtp_sent"}
}

type attemptDeadlineProcessor struct {
	first              atomic.Bool
	resumed, delivered chan struct{}
	claimed            chan application.MailDelivery
	resume, deliver    sync.Once
}

func (p *attemptDeadlineProcessor) ProcessMail(ctx context.Context, accounts *application.Accounts, sender application.MailSender) (bool, error) {
	if p.first.CompareAndSwap(false, true) {
		return accounts.ProcessMail(ctx, attemptDeadlineSender{attempt: ctx, claimed: p.claimed})
	}
	worked, err := accounts.ProcessMail(ctx, sender)
	p.resume.Do(func() { close(p.resumed) })
	if worked && err == nil {
		p.deliver.Do(func() { close(p.delivered) })
	}
	return worked, err
}

func TestMailAttemptDeadlineRecoversWithoutRestart(t *testing.T) {
	o := options(t)
	clock := &mailWorkerClock{at: o.Clock.Now()}
	o.Clock, o.Runtimes = clock, mailWorkerPeers{}
	o.InvitationMail = application.InvitationMailOptions{FrontendOrigin: "http://127.0.0.1:18081", AllowLoopbackHTTP: true}
	r, err := bootstrap.Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	session, err := r.Accounts.Login(context.Background(), application.LoginInput{Login: o.Initial.Login, Password: o.Password})
	if err != nil {
		t.Fatal(err)
	}
	created, err := r.Accounts.CreateOrganization(context.Background(), session.Token, session.CSRFToken, application.CreateOrganizationInput{CommandID: "mail-organization", Name: "Mail Test", TimeZone: "Europe/Moscow", FirstRestaurantName: "Mail Restaurant"})
	if err != nil {
		t.Fatal(err)
	}
	if complete, err := r.Accounts.Reconcile(context.Background()); err != nil || !complete {
		t.Fatal("mail scope was not registered", err)
	}
	if _, err := r.Accounts.CreateInvitation(context.Background(), session.Token, session.CSRFToken, created.OrgID, application.CreateInvitationInput{CommandID: "mail-invitation", Email: "recipient@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: created.RestaurantIDs[0], Roles: []string{"Waiter"}}}}); err != nil {
		t.Fatal(err)
	}
	handler, err := r.Handler(o.ServiceKeys)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	processor := &attemptDeadlineProcessor{resumed: make(chan struct{}), delivered: make(chan struct{}), claimed: make(chan application.MailDelivery, 1)}
	sender := mailSuccessSender{sent: make(chan application.MailDelivery, 1)}
	work, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.ServeWithMailProcessor(work, listener, handler, sender, processor) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	var original application.MailDelivery
	select {
	case original = <-processor.claimed:
	case <-time.After(5 * time.Second):
		t.Fatal("mail worker did not durably claim the invitation")
	}
	select {
	case <-processor.resumed:
	case <-time.After(13 * time.Second):
		t.Fatal("attempt deadline permanently stopped the mail worker")
	}
	if err := r.Ready(context.Background()); err != nil {
		t.Fatal("mail timeout permanently closed Auth readiness", err)
	}
	state, err := r.Store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	jobs := state.Snapshot().MailJobs
	if len(jobs) != 1 || jobs[0].JobID != original.JobID || jobs[0].State != "unknown" || jobs[0].Attempts != 1 || jobs[0].NextAttemptAt == "" {
		t.Fatal("interrupted delivery lost its durable job or retry deadline")
	}
	clock.advance()
	select {
	case <-processor.delivered:
	case <-time.After(3 * time.Second):
		t.Fatal("recovered job was not retried after its saved deadline")
	}
	retried := <-sender.sent
	state, err = r.Store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	jobs = state.Snapshot().MailJobs
	if retried.JobID != original.JobID || len(jobs) != 1 || jobs[0].State != "delivered" || jobs[0].Attempts != 2 || jobs[0].EncryptedPayload != "" {
		t.Fatal("retry replaced the original job or lost confirmed delivery")
	}
}

type unknownAuthorityProcessor struct {
	returned chan struct{}
	once     sync.Once
}

func (p *unknownAuthorityProcessor) ProcessMail(ctx context.Context, _ *application.Accounts, _ application.MailSender) (bool, error) {
	<-ctx.Done()
	p.once.Do(func() { close(p.returned) })
	return true, errors.Join(ctx.Err(), application.ErrUpdateOutcomeUnknown)
}

func TestMailDeadlineDoesNotHideUnknownAuthorityOutcome(t *testing.T) {
	o := options(t)
	o.Runtimes = mailWorkerPeers{}
	r, err := bootstrap.Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	handler, err := r.Handler(o.ServiceKeys)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	processor := &unknownAuthorityProcessor{returned: make(chan struct{})}
	work, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.ServeWithMailProcessor(work, listener, handler, mailSuccessSender{}, processor) }()
	select {
	case <-processor.returned:
	case <-time.After(13 * time.Second):
		t.Fatal("worker did not finish its timed-out attempt")
	}
	// The unknown outcome is not hidden by the attempt deadline: the process stops
	// (the supervisor restarts it) instead of staying alive and unready.
	select {
	case err := <-done:
		if !errors.Is(err, application.ErrUpdateOutcomeUnknown) {
			t.Fatalf("Serve returned %v; want the unknown authority outcome", err)
		}
	case <-time.After(time.Second):
		t.Fatal("attempt timeout hid an unknown authority outcome")
	}
}
