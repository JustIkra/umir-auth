package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestRealHTTPOrganizationSettingsReplayAndMinimumSchedulerAuthority(t *testing.T) {
	ctx := context.Background()
	r, _, o := liveOwner(t)
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	key := string(bytes.Repeat([]byte{'a'}, 64))
	h, e := r.Handler(map[string]string{"gateway": key, "serving": string(bytes.Repeat([]byte{'b'}, 64))})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	headers := map[string]string{}
	call := func(method, path string, in any) (int, map[string]json.RawMessage) {
		t.Helper()
		var b []byte
		var e error
		if in != nil {
			b, e = json.Marshal(in)
			if e != nil {
				t.Fatal(e)
			}
		}
		req, e := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("X-Umir-Service-Key", key)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		b, e = io.ReadAll(res.Body)
		ce := res.Body.Close()
		if e != nil || ce != nil {
			t.Fatal(e, ce)
		}
		var out map[string]json.RawMessage
		if json.Unmarshal(b, &out) != nil {
			t.Fatal("invalid typed response")
		}
		return res.StatusCode, out
	}
	status, pre := call("GET", "/internal/auth/v1/public/csrf", nil)
	if status != 200 {
		t.Fatal(status)
	}
	var token, csrf string
	if json.Unmarshal(pre["preauthToken"], &token) != nil || json.Unmarshal(pre["csrfToken"], &csrf) != nil {
		t.Fatal("invalid preauth")
	}
	headers["X-Umir-Preauth"] = token
	headers["X-Umir-CSRF-Token"] = csrf
	status, session := call("POST", "/internal/auth/v1/public/session", map[string]any{"login": o.Initial.Login, "password": o.Password, "rememberMe": false, "commandID": "login-contract"})
	if status != 200 {
		t.Fatal(status)
	}
	if json.Unmarshal(session["sessionToken"], &token) != nil {
		t.Fatal("missing session")
	}
	var view struct {
		Session struct {
			CSRF string `json:"csrfToken"`
		} `json:"session"`
	}
	if json.Unmarshal(session["view"], &view) != nil {
		t.Fatal("invalid session view")
	}
	headers["X-Umir-Session"] = token
	headers["X-Umir-CSRF-Token"] = view.Session.CSRF
	status, org := call("POST", "/internal/auth/v1/public/orgs", map[string]any{"commandID": "org-contract", "name": "Synthetic", "timeZone": "Europe/Moscow", "firstRestaurantName": "Synthetic"})
	if status != 201 {
		t.Fatal(status)
	}
	var orgID string
	var restaurants []string
	if json.Unmarshal(org["orgID"], &orgID) != nil || json.Unmarshal(org["restaurantIDs"], &restaurants) != nil {
		t.Fatal("invalid creation")
	}
	if _, e = r.Accounts.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	status, _ = call("GET", "/internal/auth/v1/public/access", nil)
	if status != 200 {
		t.Fatal(status)
	}
	path := "/internal/auth/v1/public/orgs/" + orgID + "/settings"
	input := map[string]any{"commandID": "zone-one", "expectedSettingsVersion": "1", "timeZone": "America/New_York"}
	status, first := call("PATCH", path, input)
	if status != 200 {
		t.Fatal(status)
	}
	status, _ = call("PATCH", path, map[string]any{"commandID": "zone-two", "expectedSettingsVersion": "2", "timeZone": "Europe/Moscow"})
	if status != 200 {
		t.Fatal(status)
	}
	status, replay := call("PATCH", path, input)
	if status != 200 || !bytes.Equal(first["settings"], replay["settings"]) {
		t.Fatal("exact settings retry returned current settings")
	}
	ns, e := application.Namespace(application.CommandNamespace{OperationID: "updateSettings", OrgID: domain.EntityID(orgID)})
	if e != nil {
		t.Fatal(e)
	}
	status, lookup := call("GET", "/internal/auth/v1/public/commands?namespace="+url.QueryEscape(ns)+"&commandID=zone-one", nil)
	if status != 200 {
		t.Fatal("original settings lookup failed", status)
	}
	var recorded struct {
		Type string `json:"type"`
		Body struct {
			Settings json.RawMessage `json:"settings"`
		} `json:"body"`
	}
	if json.Unmarshal(lookup["response"], &recorded) != nil || recorded.Type != "Organization" || !bytes.Equal(recorded.Body.Settings, first["settings"]) {
		t.Fatal("lookup lost original settings")
	}
	status, scheduler := call("POST", "/internal/auth/v1/service-tokens", map[string]any{"restaurantID": restaurants[0], "operation": "expiry.due", "epoch": "22222222-2222-4222-8222-222222222222"})
	if status != 200 || len(scheduler["token"]) == 0 {
		t.Fatal("due-only credential failed", status)
	}
	status, _ = call("POST", "/internal/auth/v1/service-tokens", map[string]any{"restaurantID": restaurants[0], "operation": "runtime.close", "epoch": "22222222-2222-4222-8222-222222222222"})
	if status != 403 {
		t.Fatal("Gateway minted Auth lifecycle credential", status)
	}
}
func TestLostReplyFollowsRealCommitAndExactOwnerRetry(t *testing.T) {
	ctx := context.Background()
	r, _, o := liveOwner(t)
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	faults := &Faults{}
	options := r.AccountOptions
	options.Repository = &FaultRepository{Store: r.Store, Faults: faults}
	var e error
	r.Accounts, e = application.NewAccounts(ctx, options)
	if e != nil {
		t.Fatal(e)
	}
	s, e := r.Accounts.Login(ctx, application.LoginInput{Login: o.Initial.Login, Password: o.Password})
	if e != nil {
		t.Fatal(e)
	}
	key := string(bytes.Repeat([]byte{'a'}, 64))
	handler, e := r.Handler(map[string]string{"gateway": key, "serving": string(bytes.Repeat([]byte{'b'}, 64))})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(faults.WrapHTTP(handler))
	defer server.Close()
	arm, e := json.Marshal(map[string]any{"faultID": "11111111-1111-4111-8111-111111111111", "point": "after-durable-before-reply", "operationID": "createOrganization", "commandID": "lost-org", "expireAfterMs": 30000})
	if e != nil {
		t.Fatal(e)
	}
	if _, code := faults.Control("owner.fault.arm", arm); code != "" {
		t.Fatal(code)
	}
	input := application.CreateOrganizationInput{CommandID: "lost-org", Name: "Synthetic", TimeZone: "Europe/Moscow", FirstRestaurantName: "Synthetic"}
	body, e := json.Marshal(input)
	if e != nil {
		t.Fatal(e)
	}
	req, e := http.NewRequestWithContext(ctx, "POST", server.URL+"/internal/auth/v1/public/orgs", bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("X-Umir-Service-Key", key)
	req.Header.Set("X-Umir-Session", s.Token)
	req.Header.Set("X-Umir-CSRF-Token", s.CSRFToken)
	req.Header.Set("Content-Type", "application/json")
	res, e := server.Client().Do(req)
	if e == nil {
		if ce := res.Body.Close(); ce != nil {
			t.Fatal(ce)
		}
		t.Fatal("committed reply was not lost")
	}
	snapshot, e := r.Store.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	before := snapshot.Revision()
	if len(snapshot.Snapshot().Organizations) != 1 || len(snapshot.Snapshot().Idempotency) != 1 {
		t.Fatal("fault did not follow real atomic commit")
	}
	saved, e := r.Accounts.CreateOrganization(ctx, s.Token, s.CSRFToken, input)
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e = r.Store.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if snapshot.Revision() != before || len(snapshot.Snapshot().Organizations) != 1 || saved.CommandID != "lost-org" {
		t.Fatal("retry created another organization")
	}
}
func TestCreationCommandLookupDeniesDeletedScope(t *testing.T) {
	ctx := context.Background()
	r, _, o := liveOwner(t)
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	s, e := r.Accounts.Login(ctx, application.LoginInput{Login: o.Initial.Login, Password: o.Password})
	if e != nil {
		t.Fatal(e)
	}
	created, e := r.Accounts.CreateOrganization(ctx, s.Token, s.CSRFToken, application.CreateOrganizationInput{CommandID: "create-then-delete", Name: "Synthetic", TimeZone: "Europe/Moscow", FirstRestaurantName: "Synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Accounts.DeleteOrganization(ctx, s.Token, s.CSRFToken, created.OrgID, "delete-for-lookup"); e != nil {
		t.Fatal(e)
	}
	ns, e := application.Namespace(application.CommandNamespace{OperationID: "createOrganization"})
	if e != nil {
		t.Fatal(e)
	}
	_, e = r.Accounts.LookupCommand(ctx, application.ChallengeActor{Token: s.Token, CSRFToken: s.CSRFToken}, ns, "create-then-delete")
	if !errors.Is(e, application.ErrForbidden) {
		t.Fatal("creation lookup bypassed deleted-scope access", e)
	}
}
