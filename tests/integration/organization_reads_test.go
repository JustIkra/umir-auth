package integration_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/httpapi"
	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
	"github.com/JustIkra/umir-auth/internal/application"
)

func TestUA1MembersCaptureContactsAndCurrentAuthority(t *testing.T) {
	f := membershipsSetup(t)
	physical := &clock{at: f.opts.Clock.Now()}
	f.opts.PageClock = physical
	f.opts.PageAfter = organizationTestAfter
	var err error
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	request := application.OrganizationListRequest{Limit: 1}
	first, err := f.accounts.Members(ctx, f.owner.Token, f.org, request)
	if err != nil || len(first.Items) != 1 || first.NextCursor == "" || first.Items[0].Email == nil || *first.Items[0].Email != f.snapshot(t).Users[0].Email || first.Context.OrgID != f.org || first.Context.AggregateRevision == "" || first.Context.ReaderEpoch == "" {
		t.Fatalf("first member page %+v %v", first, err)
	}
	request.Cursor = first.NextCursor
	before, err := f.accounts.Members(ctx, f.owner.Token, f.org, request)
	if err != nil {
		t.Fatal(err)
	}
	if before.Items[0].Email != nil {
		t.Fatal("legacy User without email gained a contact address")
	}
	if _, err := f.accounts.UpdateDisplayName(ctx, f.second.Token, "Changed after capture"); err != nil {
		t.Fatal(err)
	}
	before.Items[0].Membership.OrgRoles = append(before.Items[0].Membership.OrgRoles, "Admin")
	before.Items[0].Membership.Assignments = nil
	after, err := f.accounts.Members(ctx, f.owner.Token, f.org, request)
	if err != nil || after.Context != first.Context || after.Items[0].DisplayName == "Changed after capture" || reflect.DeepEqual(after.Items[0].Membership, before.Items[0].Membership) {
		t.Fatalf("capture drift or alias %+v %v", after, err)
	}
	if _, err := f.accounts.Members(ctx, f.worker.Token, f.org, request); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("employee read admitted: %v", err)
	}
	if _, err := f.accounts.Members(ctx, f.second.Token, f.org, request); !errors.Is(err, application.ErrRefreshRequired) {
		t.Fatalf("another Admin reused cursor: %v", err)
	}
	if _, err := f.accounts.RevokeMembership(ctx, f.second.Token, f.second.CSRFToken, f.org, f.admin1, application.RevokeMembershipInput{CommandID: "ua1-revoke-admin", ExpectedMembershipVersion: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.accounts.Members(ctx, f.owner.Token, f.org, request); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("cached page bypassed current revocation: %v", err)
	}
}

func TestUA1MembersCursorExpiryAndScope(t *testing.T) {
	f := membershipsSetup(t)
	physical := &clock{at: f.opts.Clock.Now()}
	f.opts.PageClock = physical
	f.opts.PageAfter = organizationTestAfter
	var err error
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	r := application.OrganizationListRequest{Limit: 1}
	first, err := f.accounts.Members(ctx, f.owner.Token, f.org, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Cursor = first.NextCursor
	changed := r
	changed.State = "all"
	if _, err := f.accounts.Members(ctx, f.owner.Token, f.org, changed); !errors.Is(err, application.ErrRefreshRequired) {
		t.Fatalf("changed filter accepted: %v", err)
	}
	if _, err := f.accounts.Members(ctx, f.owner.Token, f.otherOrg, r); !errors.Is(err, application.ErrRefreshRequired) {
		t.Fatalf("cross-org cursor accepted: %v", err)
	}
	physical.at = physical.at.Add(5 * time.Minute)
	if _, err := f.accounts.Members(ctx, f.owner.Token, f.org, r); !errors.Is(err, application.ErrRefreshRequired) {
		t.Fatalf("expired cursor accepted: %v", err)
	}
	for _, limit := range []int{-1, 501} {
		if _, err := f.accounts.Members(ctx, f.owner.Token, f.org, application.OrganizationListRequest{Limit: limit}); err == nil {
			t.Fatalf("bad limit %d accepted", limit)
		}
	}
}

func organizationTestAfter(d time.Duration, f func()) application.PageExpiryTimer {
	return time.AfterFunc(d, f)
}

func TestUA1OrganizationReadHTTPGuards(t *testing.T) {
	f := membershipsSetup(t)
	f.opts.PageAfter = organizationTestAfter
	var err error
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.accounts.CloseReadPages)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.New(jwt.Options{Clock: f.opts.Clock, IDs: f.opts.IDs, Active: jwt.SigningKey{KID: "ua1", PrivateKey: key}})
	if err != nil {
		t.Fatal(err)
	}
	preauth, err := httpapi.NewPreauth([]byte(strings.Repeat("k", 32)), f.opts.Clock)
	if err != nil {
		t.Fatal(err)
	}
	h, err := httpapi.New(httpapi.Options{Accounts: f.accounts, Signer: signer, Clock: f.opts.Clock, Preauth: preauth, ServiceKeys: map[string]string{"gateway": strings.Repeat("a", 64), "serving": strings.Repeat("b", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	call := func(path, body, token, service string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/internal/auth/v1/public/orgs/"+string(f.org)+path, strings.NewReader(body))
		r.Header.Set("X-Umir-Session", token)
		r.Header.Set("X-Umir-Service-Key", service)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, route := range []string{"/members", "/invitations"} {
		w := call(route, "", f.owner.Token, strings.Repeat("a", 64))
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("read route not composed: %s = %d %s", route, w.Code, w.Body)
		}
		for _, query := range []string{"?limit=0", "?limit=501", "?limit=01", "?limit=1&limit=2", "?cursor=", "?state=unknown", "?foreign=x"} {
			if w := call(route+query, "", f.owner.Token, strings.Repeat("a", 64)); w.Code != 400 {
				t.Fatalf("strict query %s%s = %d", route, query, w.Code)
			}
		}
		if w := call(route, `{}`, f.owner.Token, strings.Repeat("a", 64)); w.Code != 400 {
			t.Fatalf("GET body admitted: %d", w.Code)
		}
		if w := call(route, "", f.worker.Token, strings.Repeat("a", 64)); w.Code != 403 {
			t.Fatalf("employee contacts admitted: %d", w.Code)
		}
		if w := call(route, "", f.owner.Token, strings.Repeat("b", 64)); w.Code != 403 {
			t.Fatalf("non-gateway caller admitted: %d", w.Code)
		}
	}
}

func TestUA1InvitationsLegacyDeliveryAndReadExpiry(t *testing.T) {
	e := enrollmentSetup(t)
	first, err := e.accounts.Invitations(ctx, e.owner.Token, e.org, application.OrganizationListRequest{})
	if err != nil || len(first.Items) != 1 || first.Items[0].LinkDelivery != nil || first.Items[0].ResendAllowed {
		t.Fatalf("legacy invitation %+v %v", first, err)
	}
	originalVersion := first.Items[0].Invitation.Version
	physical, ok := e.opts.Clock.(*clock)
	if !ok {
		t.Fatal("unexpected test clock")
	}
	physical.advance(7 * 24 * time.Hour)
	e.owner = login(t, e.accounts, "owner", false)
	page, err := e.accounts.Invitations(ctx, e.owner.Token, e.org, application.OrganizationListRequest{State: "expired"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Invitation.State != "expired" || page.Items[0].Invitation.Version != originalVersion || page.Items[0].ResendAllowed {
		t.Fatalf("expiry projection %+v %v", page, err)
	}
	if stored := loadEnrollment(t, e).Invitations[0]; stored.State != "pending" || stored.Version != originalVersion {
		t.Fatalf("read mutated invitation: %+v", stored)
	}
}
