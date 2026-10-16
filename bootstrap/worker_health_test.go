package bootstrap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) records(t *testing.T) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.b.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		out = append(out, m)
	}
	return out
}
func (l *lockedBuffer) text() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// scriptedProcessor fails with the given errors in order, then succeeds.
type scriptedProcessor struct {
	mu       sync.Mutex
	failures []error
	calls    int
	ok       chan struct{}
	once     sync.Once
	send     *application.MailDelivery
}

func (p *scriptedProcessor) ProcessMail(ctx context.Context, _ *application.Accounts, sender application.MailSender) (bool, error) {
	p.mu.Lock()
	p.calls++
	var err error
	if len(p.failures) > 0 {
		err, p.failures = p.failures[0], p.failures[1:]
	}
	p.mu.Unlock()
	if err != nil {
		return false, err
	}
	if p.send != nil {
		sender.Send(ctx, *p.send)
	}
	p.once.Do(func() { close(p.ok) })
	return false, nil
}

// recordingPause records every backoff and checks, during each pause, that the
// key set and readiness still answer.
type recordingPause struct {
	mu     sync.Mutex
	delays []time.Duration
	check  func()
}

func (p *recordingPause) Wait(ctx context.Context, d time.Duration) error {
	p.mu.Lock()
	p.delays = append(p.delays, d)
	p.mu.Unlock()
	p.check()
	return ctx.Err()
}

func startServe(t *testing.T, r *bootstrap.Runtime, o bootstrap.Options, processor bootstrap.MailProcessor, sender application.MailSender) (handler http.Handler, stop func() error, done chan error) {
	t.Helper()
	handler, err := r.Handler(o.ServiceKeys)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	work, cancel := context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { done <- r.ServeWithMailProcessor(work, listener, handler, sender, processor) }()
	t.Cleanup(cancel)
	return handler, func() error { cancel(); return <-done }, done
}

func openWithLog(t *testing.T) (*bootstrap.Runtime, bootstrap.Options, *lockedBuffer) {
	t.Helper()
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
	buffer := &lockedBuffer{}
	r.Log = bootstrap.NewLogger(buffer, "test-build", "test-instance")
	return r, o, buffer
}

func TestWorkerStorageErrorsBackOffWithoutClosingReadiness(t *testing.T) {
	r, o, logs := openWithLog(t)
	secret := errors.New("synthetic failure for recipient-secret@umir.invalid with code 482913 and token tok-synthetic")
	failure := errors.Join(application.ErrStorageUnavailable, secret)
	processor := &scriptedProcessor{failures: []error{failure, failure, failure, failure, failure, failure}, ok: make(chan struct{})}
	handler, err := r.Handler(o.ServiceKeys)
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	var problemsMu sync.Mutex
	pause := &recordingPause{}
	pause.check = func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/auth/v1/jwks", nil)
		req.Header.Set("X-Umir-Service-Key", o.ServiceKeys["gateway"])
		handler.ServeHTTP(rec, req)
		problemsMu.Lock()
		defer problemsMu.Unlock()
		if rec.Code != http.StatusOK {
			problems = append(problems, "jwks answered "+http.StatusText(rec.Code))
		}
		if err := r.Ready(context.Background()); err != nil {
			problems = append(problems, "Ready failed during the pause")
		}
	}
	r.Pause = pause
	_, stop, _ := startServe(t, r, o, processor, mailSuccessSender{})
	select {
	case <-processor.ok:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not recover from storage errors")
	}
	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	if len(pause.delays) != len(want) {
		t.Fatalf("pauses %v; want %v", pause.delays, want)
	}
	for i := range want {
		if pause.delays[i] != want[i] {
			t.Fatalf("pauses %v; want %v", pause.delays, want)
		}
	}
	if len(problems) != 0 {
		t.Fatalf("service answers degraded during worker failures: %v", problems)
	}
	degraded, recovered := 0, 0
	for _, rec := range logs.records(t) {
		for _, key := range []string{"time", "level", "msg", "log_schema_version", "service", "version", "instance_id"} {
			if _, ok := rec[key]; !ok {
				t.Fatalf("log record lacks %q: %v", key, rec)
			}
		}
		if ts, ok := rec["time"].(string); !ok || !strings.HasSuffix(ts, "+03:00") {
			t.Fatalf("log time %v has no +03:00 offset", rec["time"])
		}
		switch rec["event"] {
		case "auth.worker.degraded":
			degraded++
		case "auth.worker.recovered":
			recovered++
		}
	}
	if degraded != 6 || recovered != 1 {
		t.Fatalf("%d degraded and %d recovered records; want 6 and 1", degraded, recovered)
	}
	for _, secretText := range []string{"recipient-secret", "482913", "tok-synthetic", "synthetic failure"} {
		if strings.Contains(logs.text(), secretText) {
			t.Fatalf("log contains %q", secretText)
		}
	}
}

func TestUnrecoverableWorkerErrorsStopTheProcess(t *testing.T) {
	for name, cause := range map[string]error{"recovery required": application.ErrRecoveryRequired, "unknown outcome": application.ErrUpdateOutcomeUnknown} {
		t.Run(name, func(t *testing.T) {
			r, o, logs := openWithLog(t)
			pause := &recordingPause{check: func() {}}
			r.Pause = pause
			processor := &scriptedProcessor{failures: []error{errors.Join(cause, errors.New("synthetic detail for fatal-recipient@umir.invalid"))}, ok: make(chan struct{})}
			_, _, done := startServe(t, r, o, processor, mailSuccessSender{})
			select {
			case err := <-done:
				if !errors.Is(err, cause) {
					t.Fatalf("Serve returned %v; want %v", err, cause)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("process stayed alive after an unrecoverable worker error")
			}
			if len(pause.delays) != 0 {
				t.Fatalf("an unrecoverable error was retried: %v", pause.delays)
			}
			fatal := 0
			for _, rec := range logs.records(t) {
				if rec["event"] == "auth.worker.fatal" {
					fatal++
				}
			}
			if fatal != 1 || strings.Contains(logs.text(), "fatal-recipient") {
				t.Fatalf("fatal records %d or leaked detail", fatal)
			}
		})
	}
}

func TestMailAttemptLogCarriesNoRecipientCodeOrToken(t *testing.T) {
	r, o, logs := openWithLog(t)
	delivery := application.MailDelivery{JobID: "33333333-3333-4333-8333-333333333333", Attempt: 2, Age: 90 * time.Second, Mail: application.CodeMail{Email: "log-recipient@umir.invalid", Code: "654321"}}
	processor := &scriptedProcessor{ok: make(chan struct{}), send: &delivery}
	_, stop, _ := startServe(t, r, o, processor, mailSuccessSender{sent: make(chan application.MailDelivery, 4)})
	select {
	case <-processor.ok:
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery was attempted")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range logs.records(t) {
		if rec["event"] != "auth.mail.attempt" {
			continue
		}
		found = true
		if rec["job_id"] != string(delivery.JobID) || rec["attempt"] != float64(2) || rec["age_seconds"] != float64(90) || rec["state"] != "sent" {
			t.Fatalf("unexpected attempt record %v", rec)
		}
	}
	if !found {
		t.Fatal("no auth.mail.attempt record")
	}
	for _, secretText := range []string{"log-recipient", "654321"} {
		if strings.Contains(logs.text(), secretText) {
			t.Fatalf("log contains %q", secretText)
		}
	}
}

// unknownCommitRepo loads normally but reports every commit as unknown, like a
// store that lost its answer.
type unknownCommitRepo struct {
	application.AggregateRepository
}

func (unknownCommitRepo) Commit(context.Context, domain.Version, domain.ValidatedAggregate) (application.CommitResult, error) {
	return application.CommitResult{Outcome: application.Unknown}, application.ErrStorageUnavailable
}

// An unknown outcome inside an HTTP request leaves Accounts refusing all work. The
// workers then see only plain unavailable errors, but the process must still stop
// so that it restarts, instead of staying alive and answering 503.
func TestRecoveryStartedByARequestStopsTheProcess(t *testing.T) {
	r, o, logs := openWithLog(t)
	opts := r.AccountOptions
	opts.Repository = unknownCommitRepo{opts.Repository}
	accounts, err := application.NewAccounts(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r.Accounts = accounts
	r.Pause = &recordingPause{check: func() {}}
	_, _, done := startServe(t, r, o, accountsProcessor{}, mailSuccessSender{})
	if _, err := accounts.Login(context.Background(), application.LoginInput{Login: o.Initial.Login, Password: o.Password}); !errors.Is(err, application.ErrUpdateOutcomeUnknown) {
		t.Fatalf("login = %v; want an unknown outcome", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, application.ErrRecoveryRequired) {
			t.Fatalf("Serve returned %v; want a recovery-required stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the process stayed alive after a request left Accounts in recovery")
	}
	fatal := 0
	for _, rec := range logs.records(t) {
		if rec["event"] == "auth.worker.fatal" {
			fatal++
		}
	}
	if fatal == 0 {
		t.Fatal("no auth.worker.fatal record")
	}
}

type accountsProcessor struct{}

func (accountsProcessor) ProcessMail(ctx context.Context, accounts *application.Accounts, sender application.MailSender) (bool, error) {
	return accounts.ProcessMail(ctx, sender)
}
