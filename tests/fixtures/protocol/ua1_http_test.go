package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestUA1RealHTTPResendLinkAndCollections(t *testing.T) {
	r, c, options := liveOwner(t)
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
	org, err := r.Accounts.CreateOrganization(ctx, session.Token, session.CSRFToken, application.CreateOrganizationInput{CommandID: "ua1-org", Name: "Synthetic", TimeZone: "Europe/Moscow", FirstRestaurantName: "Synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accounts.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	invitation, err := r.Accounts.CreateInvitation(ctx, session.Token, session.CSRFToken, org.OrgID, application.CreateInvitationInput{CommandID: "ua1-invite", Email: "invitee@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: org.RestaurantIDs[0], Roles: []string{"Waiter"}}}})
	if err != nil {
		t.Fatal(err)
	}
	key := string(bytes.Repeat([]byte{'a'}, 64))
	h, err := r.Handler(map[string]string{"gateway": key, "serving": string(bytes.Repeat([]byte{'b'}, 64))})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Umir-Service-Key", key)
		req.Header.Set("X-Umir-Session", session.Token)
		req.Header.Set("X-Umir-CSRF-Token", session.CSRFToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	for _, route := range []string{"members", "invitations"} {
		if w := call("GET", "/internal/auth/v1/public/orgs/"+string(org.OrgID)+"/"+route, ""); w.Code != 200 {
			t.Fatalf("collection %s = %d", route, w.Code)
		}
	}
	state := c.Read()
	if code := c.Set(state.InstanceID, state.Generation, "2026-10-13T09:01:00+03:00"); code != "" {
		t.Fatal(code)
	}
	path := "/internal/auth/v1/public/orgs/" + string(org.OrgID) + "/invitations/" + string(invitation.InvitationID) + "/resend-link"
	w := call("POST", path, `{"commandID":"ua1-resend-http"}`)
	if w.Code != 200 {
		t.Fatalf("resend-link route/schema missing: %d", w.Code)
	}
	var result application.DurableResult
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.MailJobs) != 1 || result.ResourceID != invitation.InvitationID || result.CommandID != "ua1-resend-http" {
		t.Fatal("resend-link receipt identity mismatch")
	}
	if bad := call("POST", path, `{"commandID":"ua1-other","url":"https://hostile.invalid"}`); bad.Code != 400 {
		t.Fatalf("untrusted URL/body accepted: %d", bad.Code)
	}
}
