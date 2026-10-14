package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

const ua1TestBinding = "c468cb825a3b9bfe01577485f47267f4765c95286ac08de367002e3e25f3df45"

func TestUA1JobsDiscoverActualLinkAndOTPSeparately(t *testing.T) {
	r, clock, options := liveOwner(t)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := context.Background()
	session, err := r.Accounts.Login(ctx, application.LoginInput{Login: options.Initial.Login, Password: options.Password})
	if err != nil {
		t.Fatal(err)
	}
	org, err := r.Accounts.CreateOrganization(ctx, session.Token, session.CSRFToken, application.CreateOrganizationInput{CommandID: "ua1-discovery-org", Name: "Synthetic", TimeZone: "Europe/Moscow", FirstRestaurantName: "Synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accounts.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	invitation, err := r.Accounts.CreateInvitation(ctx, session.Token, session.CSRFToken, org.OrgID, application.CreateInvitationInput{CommandID: "ua1-discovery-invite", Email: "discovery@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: org.RestaurantIDs[0], Roles: []string{"Waiter"}}}})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := r.Accounts.BeginInvitationChallenge(ctx, application.ChallengeActor{PreauthDigest: application.TokenDigest("ua1-discovery-browser")}, application.ChallengeBeginInput{CommandID: "ua1-discovery-challenge", InvitationID: invitation.InvitationID})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewUA1Handler(HandlerOptions{Project: "umir-backend-000000000000000000000000", Credential: strings.Repeat("a", 64), BinarySHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), Clock: clock, Store: r.Store, Ready: func(context.Context) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	state := clock.Read()
	expected := map[string]any{"fixtureID": state.FixtureID, "instanceID": state.InstanceID, "clockGeneration": state.Generation, "binarySHA256": strings.Repeat("b", 64), "configSHA256": strings.Repeat("c", 64)}
	request := func(selector map[string]any) map[string]any {
		id, err := UUID()
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"version": 1, "supplement": "umir-ua1-mail-fixtures/0.1.0-unpublished", "bindingSHA256": ua1TestBinding, "project": "umir-backend-000000000000000000000000", "requestID": id, "owner": "auth", "expected": expected, "action": "jobs.discover", "selector": selector}
	}
	call := func(value map[string]any) *httptest.ResponseRecorder {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/ua1-fixtures/v1", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		req.Header.Set("Content-Type", "application/json")
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		return result
	}
	type jobView struct {
		Kind      string `json:"kind"`
		JobID     string `json:"jobID"`
		State     string `json:"state"`
		Attempts  int    `json:"attempts"`
		ExpiresAt string `json:"expiresAt"`
		MessageID string `json:"messageID"`
		Anchor    struct {
			OrgID        string `json:"orgID"`
			InvitationID string `json:"invitationID"`
			ChallengeID  string `json:"challengeID"`
		} `json:"anchor"`
		Command *struct {
			CommandID         string `json:"commandID"`
			OperationID       string `json:"operationID"`
			ActorID           string `json:"actorID"`
			AggregateRevision string `json:"aggregateRevision"`
		} `json:"command"`
	}
	decode := func(response *httptest.ResponseRecorder) []jobView {
		t.Helper()
		if response.Code != http.StatusOK {
			t.Fatalf("UA1 discovery failed: status %d, %s", response.Code, response.Body.String())
		}
		var value struct {
			Jobs     []jobView `json:"jobs"`
			Complete bool      `json:"complete"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil || !value.Complete || len(value.Jobs) != 1 {
			t.Fatalf("incomplete durable selection: %v", err)
		}
		for _, forbidden := range []string{"discovery@umir.invalid", "encryptedPayload", "codeDigest", "encryptedCode", "proofDigest", "/invite/"} {
			if strings.Contains(response.Body.String(), forbidden) {
				t.Fatalf("private content exposed: %s", forbidden)
			}
		}
		return value.Jobs
	}
	linkRequest := request(map[string]any{"kind": "invitation_link", "orgID": org.OrgID, "invitationID": invitation.InvitationID})
	linkReply := call(linkRequest)
	link := decode(linkReply)[0]
	if link.Kind != "invitation_link" || link.Anchor.OrgID != string(org.OrgID) || link.Anchor.InvitationID != string(invitation.InvitationID) || link.Anchor.ChallengeID != "" || link.State != "queued" || link.Attempts != 0 || link.ExpiresAt != string(invitation.ExpiresAt) || link.MessageID != "<invitation."+link.JobID+"@umir.invalid>" {
		t.Fatalf("wrong link durable facts: %+v", link)
	}
	if link.Command == nil || link.Command.CommandID != "ua1-discovery-invite" || link.Command.OperationID != "createInvitation" || link.Command.ActorID != string(options.Initial.UserID) || link.Command.AggregateRevision == "" {
		t.Fatal("link allocator identity missing")
	}
	if replay := call(linkRequest); replay.Code != http.StatusOK || !bytes.Equal(replay.Body.Bytes(), linkReply.Body.Bytes()) {
		t.Fatal("identical observation replay changed")
	}
	otp := decode(call(request(map[string]any{"kind": "otp", "challengeID": challenge.ChallengeID})))[0]
	if otp.Kind != "otp" || otp.Anchor.ChallengeID != string(challenge.ChallengeID) || otp.Anchor.InvitationID != "" || otp.Anchor.OrgID != "" || otp.Command != nil || otp.JobID == link.JobID || otp.ExpiresAt != string(challenge.ExpiresAt) || otp.MessageID != "<registration."+string(challenge.ChallengeID)+"."+otp.JobID+"@umir.invalid>" {
		t.Fatalf("OTP/link identity conflated: %+v", otp)
	}
	before, err := r.Store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, selector := range []map[string]any{
		{"kind": "otp", "challengeID": challenge.ChallengeID, "jobID": link.JobID},
		{"kind": "invitation_link", "orgID": org.OrgID, "invitationID": invitation.InvitationID, "jobID": otp.JobID},
		{"kind": "invitation_link", "orgID": "99999999-9999-4999-8999-999999999999", "invitationID": invitation.InvitationID},
	} {
		if response := call(request(selector)); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "CorrelationConflict") {
			t.Fatal("foreign kind or scope accepted")
		}
	}
	after, err := r.Store.Load(ctx)
	if err != nil || before.Revision() != after.Revision() {
		t.Fatal("read-only discovery changed authority")
	}
	if code := clock.Set(state.InstanceID, state.Generation, state.Instant); code != "" {
		t.Fatal(code)
	}
	if replay := call(linkRequest); replay.Code != http.StatusOK || !bytes.Equal(replay.Body.Bytes(), linkReply.Body.Bytes()) {
		t.Fatal("clock progress changed the retained observation replay")
	}
	changed := make(map[string]any, len(linkRequest))
	for key, value := range linkRequest {
		changed[key] = value
	}
	changed["bindingSHA256"] = strings.Repeat("d", 64)
	if conflict := call(changed); conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "CorrelationConflict") {
		t.Fatal("changed cached request bypassed correlation conflict")
	}
}
