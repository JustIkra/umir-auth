package integration_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/timezones"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestRegistrationBudgetDoesNotConsumeResetBudget(t *testing.T) {
	e := registrationSetup(t)
	for n := 0; n < 30; n++ {
		registrationBegin(t, e, fmt.Sprintf("budget-%d@umir.invalid", n), fmt.Sprintf("budget-%d", n))
	}
	_, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: "reset-independent", Email: "unknown@umir.invalid", Purpose: "password_reset"})
	if err != nil {
		t.Fatalf("registration starved reset: %v", err)
	}
}
func TestPasswordResetUnknownAndKnownAreNeutral(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "known@umir.invalid", "known"), "known-proof")
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "known-complete")); err != nil {
		t.Fatal(err)
	}
	e.advance(t, 11*time.Minute)
	known, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: "known-reset", Email: "known@umir.invalid", Purpose: "password_reset"})
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: "unknown-reset", Email: "unknown@umir.invalid", Purpose: "password_reset"})
	if err != nil {
		t.Fatal(err)
	}
	if known.State != unknown.State || known.ExpiresAt != unknown.ExpiresAt || known.ResendAvailableAt != unknown.ResendAvailableAt {
		t.Fatal("reset discloses address existence")
	}
	a := loadEnrollment(t, e)
	found := false
	for _, j := range a.MailJobs {
		if j.ChallengeID == unknown.ChallengeID {
			found = j.State == "suppressed" && j.EncryptedPayload == ""
		}
	}
	if !found {
		t.Fatal("unknown reset can send mail")
	}
	for _, v := range []application.ChallengeView{known, unknown} {
		code := "000000"
		if e.code(t, v.ChallengeID) == code {
			code = "999999"
		}
		_, err = e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "bad-" + string(v.ChallengeID), ChallengeID: v.ChallengeID, Code: code})
		if !errors.Is(err, application.ErrChallengeInvalidCode) {
			t.Fatalf("different invalid-code outcome: %v", err)
		}
	}
	e.reopen(t)
}
func TestEmailLoginDisabledIncludingSavedBeginVerifyAndCompletion(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "legacy@umir.invalid", "create-legacy"), "create-legacy-proof")
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "create-legacy-complete")); err != nil {
		t.Fatal(err)
	}
	in := application.EmailChallengeInput{CommandID: "legacy-begin", Email: "legacy@umir.invalid", Purpose: "login"}
	v, err := e.accounts.BeginEmailChallenge(ctx, e.actor, in)
	if err != nil {
		t.Fatal(err)
	}
	code := e.code(t, v.ChallengeID)
	proof, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "legacy-verify", ChallengeID: v.ChallengeID, Code: code})
	if err != nil {
		t.Fatal(err)
	}
	complete := application.EmailCompleteInput{CommandID: "legacy-complete", ChallengeID: v.ChallengeID, Proof: proof.Proof, Purpose: "login"}
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, complete); err != nil {
		t.Fatal(err)
	}
	e.opts.EmailLoginEnabled = false
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	before := loadEnrollment(t, e)
	if _, err := e.accounts.BeginEmailChallenge(ctx, e.actor, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("saved login begin admitted: %v", err)
	}
	if _, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "legacy-verify", ChallengeID: v.ChallengeID, Code: code}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := e.accounts.ResendChallenge(ctx, e.actor, v.ChallengeID, "resend"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, complete); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatal("disabled login mutated state")
	}
}
func TestWrongCodeBudgetIsPerAddressAcrossChallengesAndRestart(t *testing.T) {
	e := registrationSetup(t)
	for n := 0; n < 2; n++ {
		v := registrationBegin(t, e, "Target@umir.invalid", fmt.Sprintf("begin-%d", n))
		code := "000000"
		if e.code(t, v.ChallengeID) == code {
			code = "999999"
		}
		for j := 0; j < 5; j++ {
			_, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: fmt.Sprintf("bad-%d-%d", n, j), ChallengeID: v.ChallengeID, Code: code})
			if j < 4 && !errors.Is(err, application.ErrChallengeInvalidCode) || j == 4 && !errors.Is(err, application.ErrChallengeLocked) {
				t.Fatal(err)
			}
		}
	}
	e.reopen(t)
	v := registrationBegin(t, e, "target@umir.invalid", "third")
	code := e.code(t, v.ChallengeID)
	before := loadEnrollment(t, e)
	if _, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "address-blocked", ChallengeID: v.ChallengeID, Code: code}); !registrationRateLimit(err) {
		t.Fatalf("address budget bypass: %v", err)
	}
	if !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatal("rate refusal mutated challenge")
	}
	e.advance(t, time.Hour)
	fresh := registrationBegin(t, e, "target@umir.invalid", "after-window")
	registrationProof(t, e, fresh, "after-window-proof")
}
func TestOrganizationQuotaFrequencyAndReplay(t *testing.T) {
	e := registrationSetup(t)
	data, err := os.ReadFile("../testdata/zoneinfo.zip")
	if err != nil {
		t.Fatal(err)
	}
	e.opts.TimeZones, err = timezones.New(data, "go1.26.9-packaged")
	if err != nil {
		t.Fatal(err)
	}
	e.opts.Registration.OrganizationsPerUser = 2
	e.opts.Registration.OrganizationCreationsPerHour = 1
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	p := registrationProof(t, e, registrationBegin(t, e, "creator@umir.invalid", "creator"), "creator-proof")
	user, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "creator-complete"))
	if err != nil {
		t.Fatal(err)
	}
	in := application.CreateOrganizationInput{CommandID: "org-one", Name: "One", FirstRestaurantName: "One", TimeZone: "Europe/Moscow"}
	first, err := e.accounts.CreateOrganization(ctx, user.Token, user.CSRFToken, in)
	if err != nil {
		t.Fatal(err)
	}
	again, err := e.accounts.CreateOrganization(ctx, user.Token, user.CSRFToken, in)
	if err != nil || again.OrgID != first.OrgID {
		t.Fatal("quota broke replay")
	}
	in.CommandID = "org-two"
	if _, err := e.accounts.CreateOrganization(ctx, user.Token, user.CSRFToken, in); !registrationRateLimit(err) {
		t.Fatalf("frequency missing: %v", err)
	}
	e.advance(t, time.Hour)
	if _, err := e.accounts.CreateOrganization(ctx, user.Token, user.CSRFToken, in); err != nil {
		t.Fatal(err)
	}
	e.advance(t, time.Hour)
	in.CommandID = "org-three"
	if _, err := e.accounts.CreateOrganization(ctx, user.Token, user.CSRFToken, in); !registrationRateLimit(err) {
		t.Fatalf("quota missing: %v", err)
	}
}

type registrationMailCapture struct{ sent int }

func (c *registrationMailCapture) Send(context.Context, application.MailDelivery) application.DeliveryResult {
	c.sent++
	return application.DeliveryResult{Success: true}
}
func TestRegistrationDisableSuppressesQueuedMailAndSavedCompletion(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "completed@umir.invalid", "completed"), "completed-proof")
	in := registrationComplete(p, "completed-complete")
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, in); err != nil {
		t.Fatal(err)
	}
	pending := registrationBegin(t, e, "queued@umir.invalid", "queued")
	e.opts.Registration.Enabled = false
	var err error
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	before := loadEnrollment(t, e)
	if _, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: "queued", Email: "queued@umir.invalid", Purpose: "registration"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatal("disabled replay mutated state")
	}
	sender := &registrationMailCapture{}
	for n := 0; n < 10; n++ {
		worked, err := e.accounts.ProcessMail(ctx, sender)
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}
	if sender.sent != 0 {
		t.Fatal("disabled registration delivered mail")
	}
	found := false
	for _, j := range loadEnrollment(t, e).MailJobs {
		if j.ChallengeID == pending.ChallengeID {
			found = j.State == "suppressed" && j.EncryptedPayload == ""
		}
	}
	if !found {
		t.Fatal("queued mail not durably suppressed")
	}
}
func TestRegistrationPasswordFieldAndCommandBound(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "fields@umir.invalid", "fields"), "fields-proof")
	in := registrationComplete(p, "fields-complete")
	in.Password = "short"
	_, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, in)
	var field *application.FieldError
	if !errors.As(err, &field) || field.Field != "password" {
		t.Fatalf("wrong password field: %v", err)
	}
	if _, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: strings.Repeat("a", 257), Email: "bound@umir.invalid", Purpose: "registration"}); !errors.As(err, &field) || field.Field != "commandID" {
		t.Fatal("oversized command admitted")
	}
}

func TestRegistrationCompletionRejectsForeignBrowserAndActiveSession(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "actor@umir.invalid", "actor"), "actor-proof")
	in := registrationComplete(p, "actor-complete")
	before := loadEnrollment(t, e)
	for _, actor := range []application.ChallengeActor{{PreauthDigest: application.TokenDigest("foreign")}, {Token: e.owner.Token, CSRFToken: e.owner.CSRFToken}} {
		if _, err := e.accounts.CompleteEmailChallenge(ctx, actor, in); err == nil {
			t.Fatal("foreign actor completed")
		}
	}
	if !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatal("foreign completion changed state")
	}
}
func TestRegistrationUnknownWithoutCommitCanRecover(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "lost@umir.invalid", "lost"), "lost-proof")
	in := registrationComplete(p, "lost-complete")
	e.opts.Repository = &faultRepo{AggregateRepository: e.store, mode: application.Unknown, persist: false}
	var err error
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	before := loadEnrollment(t, e)
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, in); !errors.Is(err, application.ErrUpdateOutcomeUnknown) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatal("uncommitted registration changed state")
	}
	e.reopen(t)
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, in); err != nil {
		t.Fatal(err)
	}
}

type registrationBlockingHasher struct {
	application.PasswordHasher
	start, release chan struct{}
	once           sync.Once
}

func (h *registrationBlockingHasher) Hash(password string) (string, error) {
	h.once.Do(func() { close(h.start) })
	<-h.release
	return h.PasswordHasher.Hash(password)
}
func TestRegistrationHashDoesNotHoldSharedLock(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "hash@umir.invalid", "hash"), "hash-proof")
	h := &registrationBlockingHasher{PasswordHasher: e.opts.Passwords, start: make(chan struct{}), release: make(chan struct{})}
	e.opts.Passwords = h
	var err error
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "hash-complete"))
		done <- err
	}()
	select {
	case <-h.start:
	case <-time.After(3 * time.Second):
		t.Fatal("hash not started")
	}
	unlocked := make(chan error, 1)
	go func() { _, err := e.accounts.Peek(ctx, e.owner.Token); unlocked <- err }()
	select {
	case err := <-unlocked:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("password hashing blocked unrelated session read")
	}
	close(h.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestRegistrationAndInvitationRaceCreatesOnlyOneAccount(t *testing.T) {
	e := registrationSetup(t)
	v := e.begin(t)
	code := e.code(t, v.ChallengeID)
	invite, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "invite-proof", ChallengeID: v.ChallengeID, Code: code})
	if err != nil {
		t.Fatal(err)
	}
	registration := registrationProof(t, e, registrationBegin(t, e, strings.ToUpper(e.invitation.Email), "race-invite-register"), "race-register-proof")
	before := loadEnrollment(t, e)
	results := make(chan error, 2)
	go func() {
		_, err := e.accounts.CompleteInvitedUser(ctx, e.actor, application.InvitationCompleteInput{CommandID: "invite-complete", ChallengeID: v.ChallengeID, Proof: invite.Proof, Password: "invitation-password", DisplayName: "Invited User"})
		results <- err
	}()
	go func() {
		_, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(registration, "register-complete"))
		results <- err
	}()
	success, conflict := 0, 0
	for n := 0; n < 2; n++ {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, application.ErrCommandConflict) || errors.Is(err, application.ErrInvitationConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 || len(loadEnrollment(t, e).Users) != len(before.Users)+1 {
		t.Fatal("invitation and registration created duplicate accounts")
	}
}

type registrationConflictOnce struct {
	application.AggregateRepository
	conflicted bool
}

func (r *registrationConflictOnce) Commit(c context.Context, v domain.Version, n domain.ValidatedAggregate) (application.CommitResult, error) {
	if !r.conflicted {
		r.conflicted = true
		return application.CommitResult{Outcome: application.NotCommitted}, application.ErrRevisionConflict
	}
	return r.AggregateRepository.Commit(c, v, n)
}

type registrationCountingHasher struct {
	application.PasswordHasher
	hashes int
}

func (h *registrationCountingHasher) Hash(p string) (string, error) {
	h.hashes++
	return h.PasswordHasher.Hash(p)
}
func TestRegistrationRevisionRetryReusesPasswordHash(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "revision@umir.invalid", "revision"), "revision-proof")
	h := &registrationCountingHasher{PasswordHasher: e.opts.Passwords}
	e.opts.Passwords = h
	e.opts.Repository = &registrationConflictOnce{AggregateRepository: e.store}
	var err error
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	before := loadEnrollment(t, e)
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "revision-complete")); err != nil {
		t.Fatal(err)
	}
	if h.hashes != 1 || len(loadEnrollment(t, e).Users) != len(before.Users)+1 {
		t.Fatal("revision retry repeated password work or account creation")
	}
}
func TestRegistrationSeparateGlobalBudgetCountsOccupiedAndFreeEqually(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "existing-budget@umir.invalid", "existing-budget"), "existing-budget-proof")
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "existing-budget-complete")); err != nil {
		t.Fatal(err)
	}
	e.advance(t, 11*time.Minute)
	e.opts.Registration.MailLimitPer10Minutes = 2
	var err error
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	registrationBegin(t, e, "existing-budget@umir.invalid", "suppressed-budget")
	registrationBegin(t, e, "free-budget@umir.invalid", "free-budget")
	for _, email := range []string{"existing-budget@umir.invalid", "free-budget@umir.invalid"} {
		if _, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: "over-" + email, Email: email, Purpose: "registration"}); !registrationRateLimit(err) {
			t.Fatal("occupied and free global budgets differ")
		}
	}
	if _, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: "independent-reset", Email: "reset-budget@umir.invalid", Purpose: "password_reset"}); err != nil {
		t.Fatal("registration consumed reset global budget")
	}
}
