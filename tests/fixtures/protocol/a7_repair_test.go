package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type a7RepairTimeoutSender struct {
	timedOut chan struct{}
	attempts atomic.Int32
}

func (s *a7RepairTimeoutSender) Send(ctx context.Context, _ application.MailDelivery) application.DeliveryResult {
	if s.attempts.Add(1) > 1 {
		return application.DeliveryResult{Success: true}
	}
	<-ctx.Done()
	close(s.timedOut)
	return application.DeliveryResult{Unknown: true, Code: "Timeout"}
}

func TestA7RepairTransportTimeoutDoesNotPermanentlyCloseAuth(t *testing.T) {
	ctx := context.Background()
	r, c, o := liveOwner(t)
	defer func() {
		if closeErr := r.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	session, e := r.Accounts.Login(ctx, application.LoginInput{Login: o.Initial.Login, Password: o.Password})
	if e != nil {
		t.Fatal(e)
	}
	org, e := r.Accounts.CreateOrganization(ctx, session.Token, session.CSRFToken, application.CreateOrganizationInput{CommandID: "org-for-timeout", Name: "Synthetic", TimeZone: "Europe/Moscow", FirstRestaurantName: "Synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Accounts.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	inv, e := r.Accounts.CreateInvitation(ctx, session.Token, session.CSRFToken, org.OrgID, application.CreateInvitationInput{CommandID: "invite-for-timeout", Email: "synthetic@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: org.RestaurantIDs[0], Roles: []string{"Waiter"}}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Accounts.BeginInvitationChallenge(ctx, application.ChallengeActor{PreauthDigest: application.TokenDigest("review-browser")}, application.ChallengeBeginInput{CommandID: "challenge-for-timeout", InvitationID: inv.InvitationID}); e != nil {
		t.Fatal(e)
	}
	key := string(bytes.Repeat([]byte{'a'}, 64))
	handler, e := r.Handler(map[string]string{"gateway": key, "serving": string(bytes.Repeat([]byte{'b'}, 64))})
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	work, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	timedOut := make(chan struct{})
	go func() { done <- r.Serve(work, listener, handler, &a7RepairTimeoutSender{timedOut: timedOut}) }()
	var stopped sync.Once
	stop := func() {
		stopped.Do(func() {
			cancel()
			if e := <-done; e != nil {
				t.Error(e)
			}
		})
	}
	defer stop()
	select {
	case <-timedOut:
	case <-time.After(8 * time.Second):
		t.Fatal("mail attempt did not execute")
	}
	deadline := time.Now().Add(2 * time.Second)
	var job domain.MailJob
	for time.Now().Before(deadline) {
		v, loadErr := r.Store.Load(ctx)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		job = v.Snapshot().MailJobs[0]
		if job.State == "unknown" || r.Ready(ctx) != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r.Ready(ctx) != nil || job.State != "unknown" || job.Attempts != 1 || job.NextAttemptAt != "2026-10-13T09:01:00+03:00" {
		t.Fatalf("transport deadline failed durable uncertainty: healthy=%v state=%s attempts=%d next=%s", r.Ready(ctx) == nil, job.State, job.Attempts, job.NextAttemptAt)
	}
	originalID, originalChallenge := job.JobID, job.ChallengeID
	state := c.Read()
	if code := c.Set(state.InstanceID, state.Generation, "2026-10-13T09:01:00+03:00"); code != "" {
		t.Fatal(code)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		v, loadErr := r.Store.Load(ctx)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		job = v.Snapshot().MailJobs[0]
		if job.State == "delivered" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if job.State != "delivered" || job.Attempts != 2 || job.JobID != originalID || job.ChallengeID != originalChallenge || r.Ready(ctx) != nil {
		t.Fatal("worker did not deliver the same durable job after owner-clock retry")
	}
	stop()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	v, e := reopened.Store.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	job = v.Snapshot().MailJobs[0]
	if job.State != "delivered" || job.Attempts != 2 || job.JobID != originalID || job.ChallengeID != originalChallenge {
		t.Fatal("durable timeout/retry outcome lost on restart")
	}
	if _, e = reopened.Accounts.Peek(ctx, session.Token); e != nil {
		t.Fatal("transport timeout revoked healthy session")
	}

}

func TestA7RepairArmedSettingsFaultMustReachRealCommit(t *testing.T) {
	for _, point := range []string{"before-commit", "after-real-commit-return-unknown", "after-durable-before-reply"} {
		t.Run(point, func(t *testing.T) {
			ctx := context.Background()
			r, _, o := liveOwner(t)
			defer func() {
				if closeErr := r.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}()
			faults := &Faults{}
			opts := r.AccountOptions
			opts.Repository = &FaultRepository{Store: r.Store, Faults: faults}
			var e error
			r.Accounts, e = application.NewAccounts(ctx, opts)
			if e != nil {
				t.Fatal(e)
			}
			session, e := r.Accounts.Login(ctx, application.LoginInput{Login: o.Initial.Login, Password: o.Password})
			if e != nil {
				t.Fatal(e)
			}
			org, e := r.Accounts.CreateOrganization(ctx, session.Token, session.CSRFToken, application.CreateOrganizationInput{CommandID: "org-for-settings-fault", Name: "Synthetic", TimeZone: "Europe/Moscow", FirstRestaurantName: "Synthetic"})
			if e != nil {
				t.Fatal(e)
			}
			arm := []byte(`{"faultID":"11111111-1111-4111-8111-111111111111","point":"` + point + `","operationID":"updateSettings","commandID":"review-settings-fault","expireAfterMs":30000,"count":1}`)
			if _, code := faults.Control("owner.fault.arm", arm); code != "" {
				t.Fatalf("arm refused: %s", code)
			}
			credential := string(bytes.Repeat([]byte{'a'}, 64))
			handler, e := r.Handler(map[string]string{"gateway": credential, "serving": string(bytes.Repeat([]byte{'b'}, 64))})
			if e != nil {
				t.Fatal(e)
			}
			request := httptest.NewRequest("PATCH", "/internal/auth/v1/public/orgs/"+string(org.OrgID)+"/settings", bytes.NewBufferString(`{"commandID":"review-settings-fault","expectedSettingsVersion":"1","timeZone":"America/New_York"}`))
			request.Header.Set("X-Umir-Service-Key", credential)
			request.Header.Set("X-Umir-Session", session.Token)
			request.Header.Set("X-Umir-CSRF-Token", session.CSRFToken)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			faults.WrapHTTP(handler).ServeHTTP(response, request)

			if response.Code != 503 {
				t.Fatalf("fault response status=%d", response.Code)
			}
			v, e := r.Store.Load(ctx)
			if e != nil {
				t.Fatal(e)
			}
			zone := v.Snapshot().Organizations[0].Settings.TimeZone
			wantZone, wantOutcome := "America/New_York", "committed"
			if point == "before-commit" {
				wantZone = "Europe/Moscow"
				wantOutcome = "not_committed"
			}
			if zone != wantZone {
				t.Fatal("real settings commit did not match selected fault outcome")
			}
			faults.mu.Lock()
			hits, state, outcome := faults.armed.Hits, faults.armed.State, faults.armed.Outcome
			faults.mu.Unlock()
			if hits != 1 || state != "hit" || outcome != wantOutcome {
				t.Fatalf("fault observation hits=%d state=%s outcome=%s", hits, state, outcome)
			}
		})
	}
}

func TestA7RepairUnsupportedFaultSelectorsNeverArm(t *testing.T) {
	for _, op := range []string{"organization", "jwks", "logout", "privateproducts", "inventedOperation"} {
		f := &Faults{}
		data, e := json.Marshal(map[string]any{"faultID": "11111111-1111-4111-8111-111111111111", "point": "before-commit", "operationID": op, "commandID": "repair-selector", "expireAfterMs": 30000, "count": 1})
		if e != nil {
			t.Fatal(e)
		}
		if _, code := f.Control("owner.fault.arm", data); code != "UnsupportedOperation" {
			t.Fatalf("unsupported selector %s reported arm: %s", op, code)
		}
		if f.armed != nil {
			t.Fatal("rejected selector created fault state")
		}
	}
}

func TestA7RepairFaultRoutesMatchFrozenCommandOperations(t *testing.T) {
	b, e := os.ReadFile("../../../internal/adapters/httpapi/contract.json")
	if e != nil {
		t.Fatal(e)
	}
	var contract struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
			RequestBody struct {
				Content map[string]struct {
					Schema struct {
						Ref string `json:"$ref"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			}
		} `json:"components"`
	}
	if e = json.Unmarshal(b, &contract); e != nil {
		t.Fatal(e)
	}
	for path, methods := range contract.Paths {
		for method, spec := range methods {
			if !strings.HasPrefix(spec.OperationID, "authFacade") {
				continue
			}
			ref := strings.TrimPrefix(spec.RequestBody.Content["application/json"].Schema.Ref, "#/components/schemas/")
			if _, ok := contract.Components.Schemas[ref].Properties["commandID"]; !ok {
				continue
			}
			requestPath := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(path, "11111111-1111-4111-8111-111111111111")
			want := strings.TrimPrefix(spec.OperationID, "authFacade")
			if got := facadeOperation(strings.ToUpper(method), requestPath); got != want {
				t.Errorf("frozen command route %s %s: got %s want %s", method, path, got, want)
			}
			if got := facadeOperation("GET", requestPath); got != "" {
				t.Errorf("read route selected mutation %s", got)
			}
		}
	}
}
