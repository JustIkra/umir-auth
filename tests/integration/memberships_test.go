package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/adapters/sessionsecrets"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type membershipFixture struct {
	store                                               *jsonstore.Store
	accounts                                            *application.Accounts
	opts                                                application.AccountOptions
	path                                                string
	org, otherOrg, r1, r2, r3, admin1, admin2, employee domain.EntityID
	owner, second, worker                               application.SessionView
}

func membershipsSetup(t *testing.T) *membershipFixture {
	t.Helper()
	a := fixture(t)
	a.Restaurants[0].Lifecycle = "ready"
	f := &membershipFixture{org: a.Organizations[0].OrgID, r1: a.Restaurants[0].RestaurantID, admin1: a.Memberships[0].MembershipID, otherOrg: uid(60), r2: uid(61), r3: uid(62), admin2: uid(63), employee: uid(64)}
	a.Users = append(a.Users, domain.User{UserID: uid(50), Login: "second", DisplayName: "Second", CredentialVersion: "1", Verifier: verifier}, domain.User{UserID: uid(51), Login: "worker", DisplayName: "Worker", CredentialVersion: "1", Verifier: verifier})
	o := a.Organizations[0]
	o.OrgID = f.otherOrg
	o.Name = "Other"
	a.Organizations = append(a.Organizations, o)
	r := a.Restaurants[0]
	r.RestaurantID = f.r2
	a.Restaurants = append(a.Restaurants, r)
	r.RestaurantID = f.r3
	r.OrgID = f.otherOrg
	a.Restaurants = append(a.Restaurants, r)
	a.Memberships = append(a.Memberships, domain.Membership{MembershipID: f.admin2, MembershipVersion: "1", UserID: uid(50), OrgID: f.org, OrgRoles: []string{"Admin"}, Assignments: []domain.Assignment{}, State: "active"}, domain.Membership{MembershipID: f.employee, MembershipVersion: "1", UserID: uid(51), OrgID: f.org, OrgRoles: []string{}, Assignments: []domain.Assignment{{RestaurantID: f.r1, AssignmentID: uid(65), AssignmentVersion: "1", Roles: []string{"Warehouse"}}, {RestaurantID: f.r2, AssignmentID: uid(66), AssignmentVersion: "1", Roles: []string{"Waiter"}}}, State: "active"}, domain.Membership{MembershipID: uid(67), MembershipVersion: "1", UserID: a.Users[0].UserID, OrgID: f.otherOrg, OrgRoles: []string{"Admin"}, Assignments: []domain.Assignment{}, State: "active"}, domain.Membership{MembershipID: uid(68), MembershipVersion: "1", UserID: uid(51), OrgID: f.otherOrg, OrgRoles: []string{}, Assignments: []domain.Assignment{{RestaurantID: f.r3, AssignmentID: uid(69), AssignmentVersion: "1", Roles: []string{"Waiter"}}}, State: "active"})
	f.path = filepath.Join(t.TempDir(), "auth.json")
	var err error
	f.store, err = jsonstore.Initialize(ctx, f.path, validate(t, a))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.store.Close(); err != nil {
			t.Error(err)
		}
	})
	secrets, err := sessionsecrets.New([]byte(strings.Repeat("s", 32)), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.opts = application.AccountOptions{Repository: f.store, Passwords: &mechanisms{}, Clock: &clock{at: time.Date(2026, 10, 13, 1, 0, 0, 0, time.FixedZone("Europe/Moscow", 3*3600))}, IDs: &mechanisms{}, Tokens: &mechanisms{}, Results: secrets}
	m := &mechanisms{}
	f.opts.Passwords = m
	f.opts.IDs = m
	f.opts.Tokens = m
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	f.owner = login(t, f.accounts, "owner", false)
	f.second = login(t, f.accounts, "second", false)
	f.worker = login(t, f.accounts, "worker", false)
	return f
}
func (f *membershipFixture) snapshot(t *testing.T) domain.Aggregate {
	t.Helper()
	v, err := f.store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return v.Snapshot()
}
func emptyUpdate(command string, version domain.Version) application.UpdateMembershipInput {
	return application.UpdateMembershipInput{CommandID: command, ExpectedMembershipVersion: version, OrgRoles: []string{}, Assignments: []domain.InviteAssignment{}}
}
func TestMembershipPermissionsAreCurrentAndRestaurantScoped(t *testing.T) {
	f := membershipsSetup(t)
	readyMembershipRuntimes(t, f)
	s := f.accounts
	a, err := s.RestaurantAccess(ctx, f.worker.Token, f.r1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.RestaurantAccess(ctx, f.worker.Token, f.r2)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(a.Permissions, "writeoff.confirm") || slices.Contains(a.Permissions, "order.confirm") || slices.Contains(b.Permissions, "writeoff.confirm") || !slices.Contains(b.Permissions, "order.confirm") {
		t.Fatalf("cross-restaurant union or Waiter writeoff: %+v %+v", a, b)
	}
	if slices.Contains(a.Permissions, "membership.manage") || slices.Contains(b.Permissions, "feedback.read") {
		t.Fatal("employee privilege escalation")
	}
	admin, err := s.RestaurantAccess(ctx, f.second.Token, f.r2)
	if err != nil || !slices.Contains(admin.Permissions, "membership.manage") || !slices.Contains(admin.Permissions, "writeoff.confirm") || !slices.Contains(admin.Permissions, "order.confirm") {
		t.Fatalf("Admin union: %+v %v", admin, err)
	}
	if _, err := s.RestaurantAccess(ctx, f.second.Token, f.r3); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("foreign org allowed: %v", err)
	}
	in := emptyUpdate("roles", "1")
	in.Assignments = []domain.InviteAssignment{{RestaurantID: f.r1, Roles: []string{"Warehouse", "Waiter"}}}
	result, err := s.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, in)
	if err != nil {
		t.Fatal(err)
	}
	if result.MembershipVersion != "2" || result.Assignments[0].AssignmentID != uid(65) || result.Assignments[0].AssignmentVersion != "2" {
		t.Fatalf("versions/identity: %+v", result)
	}
	a, err = s.RestaurantAccess(ctx, f.worker.Token, f.r1)
	if err != nil || !slices.Contains(a.Permissions, "order.confirm") {
		t.Fatalf("union missing %v", err)
	}
	if _, err := s.RestaurantAccess(ctx, f.worker.Token, f.r2); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("stale assignment allowed: %v", err)
	}
	a.Permissions[0] = "runtime.close"
	a.Roles[0] = "Admin"
	a, err = s.RestaurantAccess(ctx, f.worker.Token, f.r1)
	if err != nil || slices.Contains(a.Permissions, "runtime.close") {
		t.Fatal("caller mutated authority")
	}
}
func TestMembershipCrossOrgStaleVersionsAndPrivilegeBoundaries(t *testing.T) {
	f := membershipsSetup(t)
	before := f.snapshot(t)
	in := emptyUpdate("cross", "1")
	for _, tc := range []struct {
		name        string
		token, csrf string
		org, id     domain.EntityID
		in          application.UpdateMembershipInput
		want        error
	}{
		{"foreign target", f.second.Token, f.second.CSRFToken, f.otherOrg, uid(68), in, application.ErrForbidden},
		{"mismatched route", f.owner.Token, f.owner.CSRFToken, f.otherOrg, f.employee, in, application.ErrForbidden},
		{"employee admin grant", f.worker.Token, f.worker.CSRFToken, f.org, f.employee, application.UpdateMembershipInput{CommandID: "promote", ExpectedMembershipVersion: "1", OrgRoles: []string{"Admin"}, Assignments: []domain.InviteAssignment{}}, application.ErrForbidden},
		{"csrf", f.owner.Token, "wrong", f.org, f.employee, in, application.ErrInvalidCSRFToken},
		{"stale version", f.owner.Token, f.owner.CSRFToken, f.org, f.employee, emptyUpdate("stale", "2"), application.ErrMembershipConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.accounts.UpdateMembership(ctx, tc.token, tc.csrf, tc.org, tc.id, tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	cross := emptyUpdate("foreign assignment", "1")
	cross.Assignments = []domain.InviteAssignment{{RestaurantID: f.r3, Roles: []string{"Waiter"}}}
	if _, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, cross); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("foreign assignment %v", err)
	}
	dup := emptyUpdate("duplicate", "1")
	dup.Assignments = []domain.InviteAssignment{{RestaurantID: f.r1, Roles: []string{"Waiter"}}, {RestaurantID: f.r1, Roles: []string{"Warehouse"}}}
	if _, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, dup); err == nil {
		t.Fatal("duplicate assignment accepted")
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("refusal mutated durable authority")
	}
}
func TestMembershipConcurrentLastAdminsAndSelfDemotion(t *testing.T) {
	for _, demote := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoke", true: "self-demote"}[demote], func(t *testing.T) {
			f := membershipsSetup(t)
			start := make(chan struct{})
			errs := make(chan error, 2)
			var wg sync.WaitGroup
			for i, device := range []application.SessionView{f.owner, f.second} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					id := f.admin1
					if i == 1 {
						id = f.admin2
					}
					var err error
					if demote {
						_, err = f.accounts.UpdateMembership(ctx, device.Token, device.CSRFToken, f.org, id, emptyUpdate("demote", "1"))
					} else {
						_, err = f.accounts.RevokeMembership(ctx, device.Token, device.CSRFToken, f.org, id, application.RevokeMembershipInput{CommandID: "remove", ExpectedMembershipVersion: "1"})
					}
					errs <- err
				}()
			}
			close(start)
			wg.Wait()
			close(errs)
			ok, last := 0, 0
			for err := range errs {
				if err == nil {
					ok++
				} else if errors.Is(err, application.ErrLastAdmin) {
					last++
				} else {
					t.Fatal(err)
				}
			}
			if ok != 1 || last != 1 {
				t.Fatalf("last admin race: success=%d LastAdmin=%d", ok, last)
			}
			a := f.snapshot(t)
			admins := 0
			for _, m := range a.Memberships {
				if m.OrgID == f.org && m.State == "active" && slices.Contains(m.OrgRoles, "Admin") {
					admins++
				}
			}
			if admins != 1 {
				t.Fatalf("remaining admins %d", admins)
			}
			for _, dev := range []application.SessionView{f.owner, f.second} {
				if _, err := f.accounts.Peek(ctx, dev.Token); err != nil {
					t.Fatal("scoped change revoked global session", err)
				}
			}
		})
	}
}
func TestMembershipStaleAdminCannotMutateAndNeighborScopeSurvives(t *testing.T) {
	f := membershipsSetup(t)
	readyMembershipRuntimes(t, f)
	if _, err := f.accounts.RevokeMembership(ctx, f.second.Token, f.second.CSRFToken, f.org, f.admin1, application.RevokeMembershipInput{CommandID: "cutoff", ExpectedMembershipVersion: "1"}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	if _, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, emptyUpdate("stale authority", "1")); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("stale Admin authorization", err)
	}
	if _, err := f.accounts.RestaurantAccess(ctx, f.owner.Token, f.r1); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("revoked scope allowed", err)
	}
	if _, err := f.accounts.RestaurantAccess(ctx, f.owner.Token, f.r3); err != nil {
		t.Fatal("neighbor scope lost", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("refused stale authority mutated state")
	}
}
func TestMembershipDurableRetryConflictAndRestart(t *testing.T) {
	f := membershipsSetup(t)
	in := emptyUpdate("\x00\r\n ё <>&\u2028", "1")
	in.Assignments = []domain.InviteAssignment{{RestaurantID: f.r2, Roles: []string{"Waiter", "Warehouse"}}}
	original, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, in)
	if err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	original.Assignments[0].Roles[0] = "invalid"
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.store, err = jsonstore.Open(ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.opts.Repository = f.store
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, in)
	if err != nil || replay.MembershipVersion != "2" || replay.Assignments[0].Roles[0] == "invalid" {
		t.Fatal("restart replay", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("retry wrote again")
	}
	changed := in
	changed.Assignments = []domain.InviteAssignment{{RestaurantID: f.r1, Roles: []string{"Waiter"}}}
	if _, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, changed); !errors.Is(err, application.ErrCommandConflict) {
		t.Fatal("changed input did not conflict", err)
	}
	if _, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.admin2, in); !errors.Is(err, application.ErrCommandConflict) {
		t.Fatal("same org command retargeted membership", err)
	}
	if _, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, emptyUpdate("fresh stale", "1")); !errors.Is(err, application.ErrMembershipConflict) {
		t.Fatal("old version changed replacement", err)
	}
}
func TestAssignmentRevocationIdentityAndRetry(t *testing.T) {
	f := membershipsSetup(t)
	readyMembershipRuntimes(t, f)
	in := application.RevokeAssignmentInput{CommandID: "revoke assignment", ExpectedAssignmentVersion: "1"}
	result, err := f.accounts.RevokeAssignment(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, uid(65), in)
	if err != nil || result.ResourceID != uid(65) || result.Outcome != "committed" || result.MailJobs == nil {
		t.Fatal(result, err)
	}
	before := f.snapshot(t)
	replay, err := f.accounts.RevokeAssignment(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, uid(65), in)
	if err != nil || !reflect.DeepEqual(result, replay) || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("assignment replay changed state", err)
	}
	if _, err := f.accounts.RestaurantAccess(ctx, f.worker.Token, f.r1); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed assignment still grants", err)
	}
	if _, err := f.accounts.RestaurantAccess(ctx, f.worker.Token, f.r2); err != nil {
		t.Fatal("neighbor assignment lost", err)
	}
	if _, err := f.accounts.RestaurantAccess(ctx, f.worker.Token, f.r3); err != nil {
		t.Fatal("neighbor org lost", err)
	}
	if _, err := f.accounts.RevokeAssignment(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, uid(66), in); !errors.Is(err, application.ErrCommandConflict) {
		t.Fatal("assignment command retargeted", err)
	}
}

type competingMembershipRepository struct {
	application.AggregateRepository
	mu      sync.Mutex
	armed   bool
	loads   int
	release chan struct{}
}

func (r *competingMembershipRepository) Load(c context.Context) (domain.ValidatedAggregate, error) {
	v, err := r.AggregateRepository.Load(c)
	if err != nil {
		return v, err
	}
	r.mu.Lock()
	wait := false
	if r.armed && r.loads < 2 {
		r.loads++
		wait = true
		if r.loads == 2 {
			close(r.release)
		}
	}
	r.mu.Unlock()
	if wait {
		select {
		case <-r.release:
		case <-c.Done():
			return domain.ValidatedAggregate{}, c.Err()
		}
	}
	return v, nil
}
func TestMembershipTwoApplicationInstancesRecheckLastAdminAfterCAS(t *testing.T) {
	f := membershipsSetup(t)
	r := &competingMembershipRepository{AggregateRepository: f.store, release: make(chan struct{})}
	opts := f.opts
	opts.Repository = r
	first, err := application.NewAccounts(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := application.NewAccounts(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	r.armed = true
	errs := make(chan error, 2)
	for i, s := range []*application.Accounts{first, second} {
		go func() {
			dev, id := f.owner, f.admin1
			if i == 1 {
				dev, id = f.second, f.admin2
			}
			_, err := s.RevokeMembership(ctx, dev.Token, dev.CSRFToken, f.org, id, application.RevokeMembershipInput{CommandID: "competing", ExpectedMembershipVersion: "1"})
			errs <- err
		}()
	}
	success, last := 0, 0
	for range 2 {
		err := <-errs
		if err == nil {
			success++
		} else if errors.Is(err, application.ErrLastAdmin) {
			last++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || last != 1 {
		t.Fatalf("CAS did not re-evaluate authoritative admins: success=%d last=%d", success, last)
	}
}

type membershipCommitFailure struct {
	application.AggregateRepository
	unknown bool
}

func (r membershipCommitFailure) Commit(c context.Context, v domain.Version, next domain.ValidatedAggregate) (application.CommitResult, error) {
	if !r.unknown {
		return application.CommitResult{Outcome: application.NotCommitted}, application.ErrStorageUnavailable
	}
	result, err := r.AggregateRepository.Commit(c, v, next)
	if err != nil {
		return result, err
	}
	return application.CommitResult{Outcome: application.Unknown}, application.ErrRecoveryRequired
}
func TestMembershipPersistenceFailureClassification(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "definite", true: "unknown after durable commit"}[unknown], func(t *testing.T) {
			f := membershipsSetup(t)
			before := f.snapshot(t)
			opts := f.opts
			opts.Repository = membershipCommitFailure{AggregateRepository: f.store, unknown: unknown}
			s, err := application.NewAccounts(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			input := application.RevokeMembershipInput{CommandID: "persist-once", ExpectedMembershipVersion: "1"}
			result, err := s.RevokeMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, input)
			expected := application.ErrStorageUnavailable
			if unknown {
				expected = application.ErrUpdateOutcomeUnknown
			}
			if !errors.Is(err, expected) || result.Outcome != "" {
				t.Fatalf("persistence failure inferred success: %+v %v", result, err)
			}
			if !unknown {
				if !reflect.DeepEqual(before, f.snapshot(t)) {
					t.Fatal("definite failure published state")
				}
				return
			}
			if _, err := s.RestaurantAccess(ctx, f.owner.Token, f.r1); !errors.Is(err, application.ErrAuthUnavailable) {
				t.Fatal("unknown outcome granted fresh access", err)
			}
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			f.store, err = jsonstore.Open(ctx, f.path)
			if err != nil {
				t.Fatal(err)
			}
			f.opts.Repository = f.store
			f.accounts, err = application.NewAccounts(ctx, f.opts)
			if err != nil {
				t.Fatal(err)
			}
			after := f.snapshot(t)
			result, err = f.accounts.RevokeMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, input)
			if err != nil || result.Outcome != application.Committed || !reflect.DeepEqual(after, f.snapshot(t)) {
				t.Fatal("recovered unknown outcome did not replay once", result, err)
			}
		})
	}
}
func TestMembershipReplayRequiresCurrentActorAuthority(t *testing.T) {
	f := membershipsSetup(t)
	input := emptyUpdate("self-demote-once", "1")
	if _, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.admin1, input); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	if _, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.admin1, input); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("self-demoted actor replayed administrative result", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("denied replay altered recorded outcome")
	}
	list, err := f.accounts.Memberships(ctx, f.second.Token, f.org)
	if err != nil || len(list) != 3 {
		t.Fatal("current admin list", err)
	}
	list[0].OrgRoles = append(list[0].OrgRoles, "Admin")
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("membership list aliases authority")
	}
	if _, err := f.accounts.Memberships(ctx, f.owner.Token, f.org); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("stale Admin read membership list", err)
	}
}

func TestMembershipFrozenWireShapes(t *testing.T) {
	f := membershipsSetup(t)
	readyMembershipRuntimes(t, f)
	input := emptyUpdate("wire update", "1")
	input.Assignments = []domain.InviteAssignment{{RestaurantID: f.r1, Roles: []string{"Waiter"}}}
	updated, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, input)
	if err != nil {
		t.Fatal(err)
	}
	access, err := f.accounts.RestaurantAccess(ctx, f.worker.Token, f.r1)
	if err != nil {
		t.Fatal(err)
	}
	revoke := application.RevokeAssignmentInput{CommandID: "wire revoke assignment", ExpectedAssignmentVersion: updated.Assignments[0].AssignmentVersion}
	result, err := f.accounts.RevokeAssignment(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, updated.Assignments[0].AssignmentID, revoke)
	if err != nil {
		t.Fatal(err)
	}
	membershipRevoke := application.RevokeMembershipInput{CommandID: "wire revoke membership", ExpectedMembershipVersion: "3"}
	removed, err := f.accounts.RevokeMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, membershipRevoke)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		schema string
		value  any
	}{{"UpdateMembership", input}, {"Membership", updated}, {"RestaurantAccess", access}, {"RevokeAssignment", revoke}, {"DurableResult", result}, {"RevokeMembership", membershipRevoke}, {"DurableResult", removed}} {
		b, err := json.Marshal(sample.value)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("A3_SCHEMA %s %s", sample.schema, b)
	}
}

func TestMembershipInvalidExpectedVersionsAreValidationErrors(t *testing.T) {
	f := membershipsSetup(t)
	before := f.snapshot(t)
	for _, version := range []domain.Version{"", "0", "01", "-1", "9223372036854775808"} {
		input := emptyUpdate("invalid version", version)
		_, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, input)
		var field *application.FieldError
		if !errors.As(err, &field) {
			t.Errorf("update expected version %q: %v", version, err)
		}
		_, err = f.accounts.RevokeMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, application.RevokeMembershipInput{CommandID: "invalid revoke", ExpectedMembershipVersion: version})
		if !errors.As(err, &field) {
			t.Errorf("revoke membership expected version %q: %v", version, err)
		}
		_, err = f.accounts.RevokeAssignment(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, uid(65), application.RevokeAssignmentInput{CommandID: "invalid assignment", ExpectedAssignmentVersion: version})
		if !errors.As(err, &field) {
			t.Errorf("revoke assignment expected version %q: %v", version, err)
		}
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("invalid expected version mutated state")
	}
}
func TestMembershipCommandIDsAndRolesRejectInvalidWithoutMutation(t *testing.T) {
	f := membershipsSetup(t)
	before := f.snapshot(t)
	for _, command := range []string{"", "expiration/x", string([]byte{0xff}), strings.Repeat("a", 1<<20+1)} {
		if _, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, emptyUpdate(command, "1")); err == nil {
			t.Fatal("invalid update command accepted")
		}
		if _, err := f.accounts.RevokeMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, application.RevokeMembershipInput{CommandID: command, ExpectedMembershipVersion: "1"}); err == nil {
			t.Fatal("invalid membership revoke command accepted")
		}
		if _, err := f.accounts.RevokeAssignment(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, uid(65), application.RevokeAssignmentInput{CommandID: command, ExpectedAssignmentVersion: "1"}); err == nil {
			t.Fatal("invalid assignment revoke command accepted")
		}
	}
	for _, roles := range [][]string{nil, {}, {"Admin"}, {"Waiter", "Waiter"}, {"Warehouse", "runtime.close"}} {
		input := emptyUpdate("invalid roles", "1")
		input.Assignments = []domain.InviteAssignment{{RestaurantID: f.r1, Roles: roles}}
		if _, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, input); err == nil {
			t.Fatal("invalid restaurant roles accepted", roles)
		}
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("invalid input changed authority")
	}
}
func TestRemovedAssignmentCannotRevokeNewReplacement(t *testing.T) {
	f := membershipsSetup(t)
	if _, err := f.accounts.RevokeAssignment(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, uid(65), application.RevokeAssignmentInput{CommandID: "remove-old", ExpectedAssignmentVersion: "1"}); err != nil {
		t.Fatal(err)
	}
	input := emptyUpdate("add-new", "2")
	input.Assignments = []domain.InviteAssignment{{RestaurantID: f.r1, Roles: []string{"Waiter"}}}
	replacement, err := f.accounts.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, input)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Assignments[0].AssignmentID == uid(65) || replacement.MembershipVersion != "3" {
		t.Fatal("retired assignment identity reused")
	}
	before := f.snapshot(t)
	if _, err := f.accounts.RevokeAssignment(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, uid(65), application.RevokeAssignmentInput{CommandID: "fresh-old-id", ExpectedAssignmentVersion: "1"}); !errors.Is(err, application.ErrMembershipConflict) {
		t.Fatal("old identity removed replacement", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("stale identity changed replacement")
	}
}

type interveningMembershipRepository struct {
	application.AggregateRepository
	beforeCommit func() error
}

func (r *interveningMembershipRepository) Commit(c context.Context, v domain.Version, next domain.ValidatedAggregate) (application.CommitResult, error) {
	if r.beforeCommit != nil {
		hook := r.beforeCommit
		r.beforeCommit = nil
		if err := hook(); err != nil {
			return application.CommitResult{Outcome: application.NotCommitted}, err
		}
	}
	return r.AggregateRepository.Commit(c, v, next)
}
func TestMembershipAuthorityRevokedBetweenLoadAndCommit(t *testing.T) {
	f := membershipsSetup(t)
	readyMembershipRuntimes(t, f)
	r := &interveningMembershipRepository{AggregateRepository: f.store, beforeCommit: func() error {
		_, err := f.accounts.RevokeMembership(ctx, f.second.Token, f.second.CSRFToken, f.org, f.admin1, application.RevokeMembershipInput{CommandID: "intervening cutoff", ExpectedMembershipVersion: "1"})
		return err
	}}
	opts := f.opts
	opts.Repository = r
	s, err := application.NewAccounts(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateMembership(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, emptyUpdate("stale admission", "1")); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("stale loaded Admin authority committed", err)
	}
	a := f.snapshot(t)
	for _, m := range a.Memberships {
		if m.MembershipID == f.employee && m.MembershipVersion != "1" {
			t.Fatal("stale actor mutated membership")
		}
	}
	for _, record := range a.Idempotency {
		if record.CommandID == "stale admission" {
			t.Fatal("stale actor command persisted")
		}
	}
	if _, err := s.RestaurantAccess(ctx, f.owner.Token, f.r3); err != nil {
		t.Fatal("neighbor scope lost", err)
	}
}
