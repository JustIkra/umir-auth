package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/adapters/timezones"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type localPeers struct{}

func (localPeers) Status(_ context.Context, service string) (application.RuntimeStatus, error) {
	return application.RuntimeStatus{Service: service, Epoch: "22222222-2222-4222-8222-222222222222", Ready: true, TZDataVersion: "test"}, nil
}
func (localPeers) Register(_ context.Context, service string, id domain.EntityID, in application.RegisterRuntime) (domain.PeerReadiness, error) {
	return domain.PeerReadiness{RestaurantID: id, Service: service, Epoch: in.ExpectedEpoch, State: "ready", LifecycleVersion: in.LifecycleVersion}, nil
}
func (localPeers) Close(_ context.Context, service string, id domain.EntityID, in application.CloseRuntime) (domain.PeerReadiness, error) {
	return domain.PeerReadiness{RestaurantID: id, Service: service, Epoch: in.ExpectedEpoch, State: "closed", LifecycleVersion: in.LifecycleVersion}, nil
}
func liveOwner(t *testing.T) (*bootstrap.Runtime, *Clock, bootstrap.Options) {
	t.Helper()
	ctx := context.Background()
	clock, e := NewClock("33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "2026-10-13T09:00:00+03:00", "1")
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile("../../testdata/zoneinfo.zip")
	if e != nil {
		t.Fatal(e)
	}
	zones, e := timezones.New(data, "test")
	if e != nil {
		t.Fatal(e)
	}
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	o := bootstrap.Options{StateFile: filepath.Join(dir, "auth.json"), SecretsDir: filepath.Join(dir, "secrets"), Password: "0123456789abcdef0123456789abcdef", Initial: &bootstrap.InitialUser{UserID: "11111111-1111-4111-8111-111111111111", Login: "e2e.initial", DisplayName: "E2E Initial Operator", CredentialVersion: "1"}, Clock: clock, TimeZones: zones, Runtimes: localPeers{}}
	r, e := bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	return r, clock, o
}
func discover(t *testing.T, r *bootstrap.Runtime, c *Clock, in selector) (jobResult, string) {
	t.Helper()
	h := &Handler{opts: HandlerOptions{Clock: c, Store: r.Store}}
	state := c.Read()
	b, e := json.Marshal(map[string]any{"expectedInstanceID": state.InstanceID, "expectedClockGeneration": state.Generation, "selector": in, "waitMs": 0})
	if e != nil {
		t.Fatal(e)
	}
	v, code := h.jobs(context.Background(), Request{Operation: "owner.jobs.discover", Data: b})
	if code != "" {
		return jobResult{}, code
	}
	out, ok := v.(jobResult)
	if !ok {
		t.Fatal("invalid discovery type")
	}
	return out, ""
}
func TestLiveAuthDiscoveryExactReplayResendAndReopen(t *testing.T) {
	ctx := context.Background()
	r, c, o := liveOwner(t)
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	s, e := r.Accounts.Login(ctx, application.LoginInput{Login: o.Initial.Login, Password: o.Password})
	if e != nil {
		t.Fatal(e)
	}
	org, e := r.Accounts.CreateOrganization(ctx, s.Token, s.CSRFToken, application.CreateOrganizationInput{CommandID: "org-one", Name: "Synthetic", TimeZone: "Europe/Moscow", FirstRestaurantName: "Synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Accounts.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	inv, e := r.Accounts.CreateInvitation(ctx, s.Token, s.CSRFToken, org.OrgID, application.CreateInvitationInput{CommandID: "invite-one", Email: "synthetic@umir.test", Assignments: []domain.InviteAssignment{{RestaurantID: org.RestaurantIDs[0], Roles: []string{"Waiter"}}}})
	if e != nil {
		t.Fatal(e)
	}
	actor := application.ChallengeActor{PreauthDigest: application.TokenDigest("synthetic-browser-one")}
	challenge, e := r.Accounts.BeginInvitationChallenge(ctx, actor, application.ChallengeBeginInput{CommandID: "challenge-one", InvitationID: inv.InvitationID})
	if e != nil {
		t.Fatal(e)
	}
	sel := selector{Kind: "command", ChallengeID: challenge.ChallengeID, CommandID: "challenge-one", OperationID: "beginInvitationChallenge"}
	first, code := discover(t, r, c, sel)
	if code != "" || len(first.Jobs) != 1 || first.CommandRevision == nil {
		t.Fatalf("discovery failed %s", code)
	}
	if _, e = r.Accounts.BeginInvitationChallenge(ctx, actor, application.ChallengeBeginInput{CommandID: "challenge-one", InvitationID: inv.InvitationID}); e != nil {
		t.Fatal(e)
	}
	replay, code := discover(t, r, c, sel)
	if code != "" || fmt.Sprint(first.Jobs) != fmt.Sprint(replay.Jobs) || *first.CommandRevision != *replay.CommandRevision {
		t.Fatal("command replay changed durable edge")
	}
	if code = c.Set(c.Read().InstanceID, "1", "2026-10-13T09:01:00+03:00"); code != "" {
		t.Fatal(code)
	}
	if _, e = r.Accounts.ResendChallenge(ctx, actor, challenge.ChallengeID, "resend-one"); e != nil {
		t.Fatal(e)
	}
	all, code := discover(t, r, c, selector{Kind: "challenge", ChallengeID: challenge.ChallengeID})
	if code != "" || len(all.Jobs) != 2 {
		t.Fatal("challenge discovery omitted retained jobs", code)
	}
	for _, j := range all.Jobs {
		if j.ExpiresAt != challenge.ExpiresAt {
			t.Fatal("expiry reconstructed")
		}
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	nextClock, e := NewClock(c.Read().FixtureID, "55555555-5555-4555-8555-555555555555", c.Read().Instant, c.Read().Generation)
	if e != nil {
		t.Fatal(e)
	}
	o.Clock = nextClock
	r, e = bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	after, code := discover(t, r, nextClock, sel)
	if code != "" || after.InstanceID == first.InstanceID || fmt.Sprint(after.Jobs) != fmt.Sprint(first.Jobs) || *after.CommandRevision != *first.CommandRevision {
		t.Fatal("reopened projection lost original edge", code)
	}
	if _, code = discover(t, r, nextClock, selector{Kind: "command", ChallengeID: challenge.ChallengeID, CommandID: "missing", OperationID: "resendChallenge"}); code != "WaitExpired" {
		t.Fatal("missing edge invented", code)
	}
}
func TestControlClockReplayAndPrivateTCPIsolation(t *testing.T) {
	r, c, _ := liveOwner(t)
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	credential := string(bytes.Repeat([]byte{'a'}, 64))
	h, e := NewHandler(HandlerOptions{Project: "umir-backend-000000000000000000000000", Credential: credential, BinarySHA256: credential, ConfigSHA256: credential, Clock: c, Store: r.Store, Faults: &Faults{}, Ready: func(ctx context.Context) bool { return r.Ready(ctx) == nil }, BootstrapID: "11111111-1111-4111-8111-111111111111", BindingSHA256: r.BindingSHA256, Initialized: r.Initialized})
	if e != nil {
		t.Fatal(e)
	}
	body := func(id, instant string) []byte {
		b, e := json.Marshal(Request{Version: 1, Project: h.opts.Project, RequestID: id, Operation: "clock.set", Data: json.RawMessage(fmt.Sprintf(`{"expectedInstanceID":%q,"expectedGeneration":"1","instant":%q}`, c.Read().InstanceID, instant))})
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	call := func(b []byte) (int, []byte) {
		req := httptest.NewRequest("POST", ControlPath, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+credential)
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		return out.Code, out.Body.Bytes()
	}
	b := body("11111111-1111-4111-8111-111111111111", "2026-10-13T09:01:00+03:00")
	status, first := call(b)
	if status != 200 {
		t.Fatalf("clock set failed %d %s", status, first)
	}
	status, replay := call(b)
	if status != 200 || !bytes.Equal(first, replay) || c.Read().Generation != "2" {
		t.Fatal("clock replay reapplied mutation")
	}
	status, _ = call(body("11111111-1111-4111-8111-111111111111", "2026-10-13T09:02:00+03:00"))
	if status != 409 {
		t.Fatal("changed request ID payload accepted")
	}
	api, e := r.Handler(map[string]string{"gateway": credential, "serving": string(bytes.Repeat([]byte{'b'}, 64))})
	if e != nil {
		t.Fatal(e)
	}
	req := httptest.NewRequest("POST", ControlPath, bytes.NewReader(b))
	req.Header.Set("X-Umir-Service-Key", credential)
	out := httptest.NewRecorder()
	api.ServeHTTP(out, req)
	if out.Code != http.StatusNotFound {
		t.Fatal("fixture control leaked onto business listener")
	}
}
