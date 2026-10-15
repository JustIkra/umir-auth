package integration_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"reflect"

	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
	"github.com/JustIkra/umir-auth/internal/adapters/timezones"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func a5Setup(t *testing.T) (*membershipFixture, *jwt.Signer) {
	t.Helper()
	f, signer := a5UnreconciledSetup(t)
	readyMembershipRuntimes(t, f)
	return f, signer
}
func a5UnreconciledSetup(t *testing.T) (*membershipFixture, *jwt.Signer) {
	t.Helper()
	f := membershipsSetup(t)
	data, e := os.ReadFile("../testdata/zoneinfo.zip")
	if e != nil {
		t.Fatal(e)
	}
	z, e := timezones.New(data, "go1.26.9-packaged")
	if e != nil {
		t.Fatal(e)
	}
	_, p, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := jwt.New(jwt.Options{Clock: f.opts.Clock, IDs: f.opts.IDs, Active: jwt.SigningKey{KID: "a5", PrivateKey: p}})
	if e != nil {
		t.Fatal(e)
	}
	f.opts.Issuer = s
	f.opts.TimeZones = z
	f.accounts, e = application.NewAccounts(ctx, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	return f, s
}
func authInput(f *membershipFixture, op string, audiences ...string) application.AuthorizationInput {
	return application.AuthorizationInput{SessionToken: f.worker.Token, RestaurantID: f.r1, Operation: op, Audiences: audiences, Activity: "background"}
}
func TestA5FreshAuthorizationMinimumAuthority(t *testing.T) {
	f, s := a5Setup(t)
	in := authInput(f, "menu", "umir-serving", "umir-warehouse")
	r, e := f.accounts.AuthorizeToken(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.JWKS(ctx)
	if e != nil {
		t.Fatal(e)
	}
	c, e := jwt.VerifyUser(r.Token, j, f.opts.Clock.Now(), "umir-warehouse")
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(c.Permissions, []string{"menu.read", "consumer.menu.evaluate"}) || c.TenantID != f.r1 || c.OrgID != f.org || c.SessionID != f.worker.Session.SessionID || c.AccessVersion != "1" {
		t.Fatal("claims not current minimum authority")
	}
	before := f.snapshot(t)
	for _, change := range []func(*application.AuthorizationInput){func(i *application.AuthorizationInput) { i.Audiences = []string{"umir-serving"} }, func(i *application.AuthorizationInput) {
		i.Audiences = []string{"umir-serving", "umir-warehouse", "umir-feedback"}
	}, func(i *application.AuthorizationInput) { i.Operation = "runtime.close" }, func(i *application.AuthorizationInput) { i.Operation = "prepareOrder" }, func(i *application.AuthorizationInput) {
		i.RestaurantID = f.r2
		i.Operation = "confirmWriteoff"
		i.Audiences = []string{"umir-warehouse"}
	}, func(i *application.AuthorizationInput) { i.Activity = "invalid" }} {
		bad := in
		change(&bad)
		if _, e := f.accounts.AuthorizeToken(ctx, bad); e == nil {
			t.Fatal("invalid scope/action/audience accepted")
		}
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("denied/background requests mutated sessions")
	}
	if _, e := f.accounts.RevokeMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, application.RevokeMembershipInput{CommandID: "a5-revoke", ExpectedMembershipVersion: "1"}); e != nil {
		t.Fatal(e)
	}
	if _, e := f.accounts.AuthorizeToken(ctx, in); !errors.Is(e, application.ErrForbidden) {
		t.Fatal("revoked membership minted token")
	}
	if _, e := f.accounts.RestaurantAccess(ctx, f.worker.Token, f.r3); e != nil {
		t.Fatal("scoped revoke killed neighbor/global session")
	}
}
func TestA5FreshSessionAndStoreFailClosed(t *testing.T) {
	for _, reason := range []string{"logout", "idle-expiry", "store"} {
		t.Run(reason, func(t *testing.T) {
			f, _ := a5Setup(t)
			in := authInput(f, "inventory", "umir-warehouse")
			switch reason {
			case "logout":
				if e := f.accounts.Logout(ctx, f.worker.Token); e != nil {
					t.Fatal(e)
				}
			case "idle-expiry":
				if c, ok := f.opts.Clock.(*clock); ok {
					c.advance(30 * time.Minute)
				} else {
					t.Fatal("wrong clock fixture")
				}
			case "store":
				if e := f.store.Close(); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := f.accounts.AuthorizeToken(ctx, in); e == nil {
				t.Fatal("unavailable/revoked/expired authority minted")
			}
		})
	}
}
func TestA5SettingsExactRetryRestartAndCapturedToken(t *testing.T) {
	f, s := a5Setup(t)
	old, e := f.accounts.AuthorizeToken(ctx, authInput(f, "menu", "umir-serving", "umir-warehouse"))
	if e != nil {
		t.Fatal(e)
	}
	before := f.snapshot(t)
	in := application.UpdateSettingsInput{CommandID: "a5-zone", ExpectedSettingsVersion: "1", TimeZone: "America/New_York"}
	r, e := f.accounts.UpdateSettings(ctx, f.owner.Token, f.owner.CSRFToken, f.org, in)
	if e != nil {
		t.Fatal(e)
	}
	if r.TimeZone != "America/New_York" || r.SettingsVersion != "2" {
		t.Fatal("timezone/version not committed")
	}
	after := f.snapshot(t)
	if !reflect.DeepEqual(before.Sessions, after.Sessions) || !reflect.DeepEqual(before.Challenges, after.Challenges) || !reflect.DeepEqual(before.Invitations, after.Invitations) {
		t.Fatal("zone update altered expiry instants")
	}
	if _, e := f.accounts.UpdateSettings(ctx, f.owner.Token, f.owner.CSRFToken, f.org, application.UpdateSettingsInput{CommandID: "a5-next", ExpectedSettingsVersion: "2", TimeZone: "Asia/Tokyo"}); e != nil {
		t.Fatal(e)
	}
	f.reopen(t)
	saved := f.snapshot(t)
	replay, e := f.accounts.UpdateSettings(ctx, f.owner.Token, f.owner.CSRFToken, f.org, in)
	if e != nil || replay != r {
		t.Fatal("retained old version refused/recomputed on restart")
	}
	if !reflect.DeepEqual(saved, f.snapshot(t)) {
		t.Fatal("replay wrote again")
	}
	in.TimeZone = "Europe/Moscow"
	if _, e := f.accounts.UpdateSettings(ctx, f.owner.Token, f.owner.CSRFToken, f.org, in); !errors.Is(e, application.ErrCommandConflict) {
		t.Fatal("changed retained payload accepted")
	}
	current, e := f.accounts.AuthorizeToken(ctx, authInput(f, "menu", "umir-serving", "umir-warehouse"))
	if e != nil {
		t.Fatal(e)
	}
	if current.Settings.TimeZone != "Asia/Tokyo" || current.Settings.SettingsVersion != "3" {
		t.Fatal("new request did not fetch current settings")
	}
	j, e := s.JWKS(ctx)
	if e != nil {
		t.Fatal(e)
	}
	c, e := jwt.VerifyUser(old.Token, j, f.opts.Clock.Now(), "umir-serving")
	if e != nil || c.TimeZone != "Europe/Moscow" || c.SettingsVersion != "1" {
		t.Fatal("captured token/expiry changed")
	}
}
func TestA5SettingsRefusalAndConcurrentExpectedVersion(t *testing.T) {
	f, _ := a5Setup(t)
	before := f.snapshot(t)
	for _, z := range []string{"No/SuchZone", "Local", "", "../Europe/Moscow"} {
		if _, e := f.accounts.UpdateSettings(ctx, f.owner.Token, f.owner.CSRFToken, f.org, application.UpdateSettingsInput{CommandID: "bad-zone", ExpectedSettingsVersion: "1", TimeZone: z}); e == nil {
			t.Fatal("invalid zone accepted")
		}
	}
	if _, e := f.accounts.UpdateSettings(ctx, f.worker.Token, f.worker.CSRFToken, f.org, application.UpdateSettingsInput{CommandID: "employee-zone", ExpectedSettingsVersion: "1", TimeZone: "Asia/Tokyo"}); !errors.Is(e, application.ErrForbidden) {
		t.Fatal("employee changed settings")
	}
	if _, e := f.accounts.UpdateSettings(ctx, f.second.Token, f.second.CSRFToken, f.otherOrg, application.UpdateSettingsInput{CommandID: "foreign-zone", ExpectedSettingsVersion: "1", TimeZone: "Asia/Tokyo"}); !errors.Is(e, application.ErrForbidden) {
		t.Fatal("foreign admin changed settings")
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("refused update mutated store")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, zone := range []string{"Asia/Tokyo", "America/New_York"} {
		wg.Go(func() {
			_, e := f.accounts.UpdateSettings(ctx, f.owner.Token, f.owner.CSRFToken, f.org, application.UpdateSettingsInput{CommandID: zone, ExpectedSettingsVersion: "1", TimeZone: zone})
			errs <- e
		})
	}
	wg.Wait()
	close(errs)
	ok, conflict := 0, 0
	for e := range errs {
		if e == nil {
			ok++
		} else if errors.Is(e, application.ErrSettingsChanged) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || conflict != 1 || f.snapshot(t).Organizations[0].Settings.SettingsVersion != "2" {
		t.Fatal("concurrent stale version committed")
	}
}
func TestA5MissingPackagedDataAndForegroundActivity(t *testing.T) {
	f, _ := a5Setup(t)
	f.opts.TimeZones = nil
	f.opts.Issuer = nil
	var e error
	f.accounts, e = application.NewAccounts(ctx, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	before := f.snapshot(t)
	if _, e := f.accounts.AuthorizeToken(ctx, authInput(f, "inventory", "umir-warehouse")); !errors.Is(e, application.ErrTimeZoneDataUnavailable) {
		t.Fatal("missing data minted/fell back")
	}
	if _, e := f.accounts.UpdateSettings(ctx, f.owner.Token, f.owner.CSRFToken, f.org, application.UpdateSettingsInput{CommandID: "missing", ExpectedSettingsVersion: "1", TimeZone: "Europe/Moscow"}); !errors.Is(e, application.ErrTimeZoneDataUnavailable) {
		t.Fatal("missing data update")
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("missing data changed state")
	}
	f, s := a5Setup(t)
	if c, ok := f.opts.Clock.(*clock); ok {
		c.advance(time.Minute)
	} else {
		t.Fatal("wrong clock fixture")
	}
	in := authInput(f, "inventory", "umir-warehouse")
	in.Activity = "foreground"
	r, e := f.accounts.AuthorizeToken(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.JWKS(ctx)
	if e != nil {
		t.Fatal(e)
	}
	c, e := jwt.VerifyUser(r.Token, j, f.opts.Clock.Now(), "umir-warehouse")
	if e != nil || c.SessionVersion != "2" {
		t.Fatal("foreground token has stale session version")
	}
	st := f.snapshot(t).Sessions
	found := false
	for _, v := range st {
		if v.SessionID == f.worker.Session.SessionID {
			found = true
			if v.AbsoluteExpiresAt != f.worker.Session.AbsoluteExpiresAt || v.IdleExpiresAt != domain.Instant("2026-10-13T01:31:00+03:00") {
				t.Fatal("activity moved absolute/incorrect idle")
			}
		}
	}
	if !found {
		t.Fatal("session lost")
	}
}

func (f *membershipFixture) reopen(t *testing.T) {
	t.Helper()
	if e := f.store.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	f.store, e = jsonstore.Open(ctx, f.path)
	if e != nil {
		t.Fatal(e)
	}
	f.opts.Repository = f.store
	f.accounts, e = application.NewAccounts(ctx, f.opts)
	if e != nil {
		t.Fatal(e)
	}
}

func TestA5AuthorizationRefusesNonreadyAndMissingRestaurant(t *testing.T) {
	for _, state := range []string{"registering", "missing"} {
		t.Run(state, func(t *testing.T) {
			f, _ := a5Setup(t)
			in := authInput(f, "menu", "umir-serving", "umir-warehouse")
			if state == "missing" {
				in.RestaurantID = uid(700)
			} else {
				a := f.snapshot(t)
				a.Restaurants[0].Lifecycle = "registering"
				old := a.AggregateRevision
				n, ok := domain.VersionNumber(old)
				if !ok {
					t.Fatal("invalid revision")
				}
				a.AggregateRevision = domain.Version(fmt.Sprint(n + 1))
				r, e := f.store.Commit(ctx, old, validate(t, a))
				if e != nil || r.Outcome != application.Committed {
					t.Fatal("real lifecycle transition failed", e)
				}
			}
			if _, e := f.accounts.AuthorizeToken(ctx, in); !errors.Is(e, application.ErrForbidden) {
				t.Fatal("nonready/missing restaurant authorized")
			}
		})
	}
}
func TestA5ConcurrentSettingsAcrossIndependentConsumers(t *testing.T) {
	f, _ := a5Setup(t)
	other, e := application.NewAccounts(ctx, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i, s := range []*application.Accounts{f.accounts, other} {
		wg.Go(func() {
			_, e := s.UpdateSettings(ctx, f.owner.Token, f.owner.CSRFToken, f.org, application.UpdateSettingsInput{CommandID: fmt.Sprint("separate-", i), ExpectedSettingsVersion: "1", TimeZone: "Asia/Tokyo"})
			errs <- e
		})
	}
	wg.Wait()
	close(errs)
	ok, conflict := 0, 0
	for e := range errs {
		if e == nil {
			ok++
		} else if errors.Is(e, application.ErrSettingsChanged) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || conflict != 1 || f.snapshot(t).Organizations[0].Settings.SettingsVersion != "2" {
		t.Fatal("expected version lost across independent consumers")
	}
}
func TestA5BusinessTokenPolicyMatrixWithFIN1Recommendations(t *testing.T) {
	f, s := a5Setup(t)
	j, e := s.JWKS(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		operation              string
		audiences, permissions []string
	}{
		{"products", []string{"umir-warehouse"}, []string{"catalog.read"}},
		{"confirmWriteoff", []string{"umir-warehouse"}, []string{"writeoff.confirm"}},
		{"servingProducts", []string{"umir-serving", "umir-warehouse"}, []string{"menu.read", "catalog.read"}},
		{"prepareOrder", []string{"umir-serving", "umir-warehouse"}, []string{"order.prepare", "consumer.order.evaluate"}},
		{"confirmOrder", []string{"umir-serving", "umir-warehouse"}, []string{"order.confirm", "consumer.order.evaluate", "consumer.order.commit", "consumer.order.resolve"}},
		{"resolveOrder", []string{"umir-serving", "umir-warehouse"}, []string{"order.read", "consumer.order.resolve"}},
		{"recommendations", []string{"umir-serving", "umir-warehouse"}, []string{"recommendations.read", "consumer.recommendations.read"}},
		{"appFeedback", []string{"umir-feedback"}, []string{"feedback.submit"}},
		{"publicFeedbackRead", []string{"umir-feedback"}, []string{"feedback.read"}},
		{"publicFeedbackExport", []string{"umir-feedback"}, []string{"feedback.export"}},
		{"orgSummary", []string{"umir-warehouse"}, []string{"org.summary.read"}},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			r, e := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.owner.Token, RestaurantID: f.r1, Operation: tc.operation, Audiences: tc.audiences, Activity: "background"})
			if e != nil {
				t.Fatal(e)
			}
			c, e := jwt.VerifyUser(r.Token, j, f.opts.Clock.Now(), tc.audiences[0])
			if e != nil || !reflect.DeepEqual(c.Permissions, tc.permissions) || !reflect.DeepEqual(c.Audiences, tc.audiences) {
				t.Fatal("current target/permission pairing violated")
			}
		})
	}
}

func TestA5ConfiguredSignerRequiresPackagedDataAtStartup(t *testing.T) {
	f, _ := a5Setup(t)
	f.opts.TimeZones = nil
	if _, e := application.NewAccounts(ctx, f.opts); !errors.Is(e, application.ErrTimeZoneDataUnavailable) {
		t.Fatal("configured signer became ready without packaged data")
	}
}
