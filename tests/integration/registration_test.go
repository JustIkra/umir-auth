package integration_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/password"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func registrationSetup(t *testing.T) *enrollmentFixture {
	t.Helper()
	e := enrollmentSetup(t)
	e.opts.Registration.Enabled = true
	hasher, err := password.New(password.Selected, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e.opts.Passwords = hasher
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func registrationBegin(t *testing.T, e *enrollmentFixture, email, command string) application.ChallengeView {
	t.Helper()
	v, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: command, Email: email, Purpose: "registration"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func registrationProof(t *testing.T, e *enrollmentFixture, v application.ChallengeView, command string) application.VerifiedChallenge {
	t.Helper()
	p, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: command, ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func registrationComplete(v application.VerifiedChallenge, command string) application.EmailCompleteInput {
	return application.EmailCompleteInput{CommandID: command, ChallengeID: v.Challenge.ChallengeID, Proof: v.Proof, Purpose: "registration", DisplayName: "New User", Password: "new-user-password", RememberMe: true}
}
func TestRegistrationDisabledIsForbiddenWithoutMutation(t *testing.T) {
	e := enrollmentSetup(t)
	before := loadEnrollment(t, e)
	_, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: "disabled", Email: "new@umir.invalid", Purpose: "registration"})
	if !errors.Is(err, application.ErrForbidden) || !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatalf("disabled registration changed state or was not forbidden: %v", err)
	}
}
func TestRegistrationAtomicReplayReopenAndPasswordLogin(t *testing.T) {
	e := registrationSetup(t)
	before := loadEnrollment(t, e)
	v := registrationBegin(t, e, "New@UMIR.invalid", "register")
	if v.State != "pending" {
		t.Fatal("not pending")
	}
	p := registrationProof(t, e, v, "verify-register")
	in := registrationComplete(p, "complete-register")
	issued, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, in)
	if err != nil {
		t.Fatal(err)
	}
	after := loadEnrollment(t, e)
	if len(after.Users) != len(before.Users)+1 || len(after.Memberships) != len(before.Memberships) || len(after.Sessions) != len(before.Sessions)+1 || issued.User.Email != "New@umir.invalid" || !issued.Session.RememberMe {
		t.Fatal("registration did not atomically create a verified user and session without memberships")
	}
	e.reopen(t)
	again, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, in)
	if err != nil || again.Token != issued.Token || !reflect.DeepEqual(after, loadEnrollment(t, e)) {
		t.Fatalf("completion replay changed durable result: %v", err)
	}
	_, err = e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "reuse-proof"))
	if !errors.Is(err, application.ErrChallengeUnavailable) {
		t.Fatalf("proof reused: %v", err)
	}
	_, err = e.accounts.Login(ctx, application.LoginInput{Login: issued.User.Login, Password: in.Password})
	if err != nil {
		t.Fatalf("normal password login failed: %v", err)
	}
}
func TestRegistrationOccupiedAddressIsNeutralAndNeverDelivers(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "occupied@umir.invalid", "first"), "verify-first")
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "complete-first")); err != nil {
		t.Fatal(err)
	}
	e.advance(t, 11*time.Minute)
	free := registrationBegin(t, e, "free@umir.invalid", "free")
	occupied := registrationBegin(t, e, "occupied@umir.invalid", "occupied")
	if free.State != occupied.State || free.ExpiresAt != occupied.ExpiresAt || free.ResendAvailableAt != occupied.ResendAvailableAt {
		t.Fatal("address existence leaked through challenge response")
	}
	a := loadEnrollment(t, e)
	for _, j := range a.MailJobs {
		if j.ChallengeID == occupied.ChallengeID && (j.State != "suppressed" || j.EncryptedPayload != "") {
			t.Fatal("occupied address can receive OTP")
		}
	}
	for n := 1; n <= 5; n++ {
		_, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: fmt.Sprintf("guess-%d", n), ChallengeID: occupied.ChallengeID, Code: e.code(t, occupied.ChallengeID)})
		if n < 5 && !errors.Is(err, application.ErrChallengeInvalidCode) || n == 5 && !errors.Is(err, application.ErrChallengeLocked) {
			t.Fatalf("suppressed challenge verified or leaked: %v", err)
		}
	}
}
func TestRegistrationSameAddressRaceCreatesOneAccount(t *testing.T) {
	e := registrationSetup(t)
	first := registrationProof(t, e, registrationBegin(t, e, "race@umir.invalid", "race-one"), "proof-one")
	second := registrationProof(t, e, registrationBegin(t, e, "race@umir.invalid", "race-two"), "proof-two")
	before := loadEnrollment(t, e)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i, p := range []application.VerifiedChallenge{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, fmt.Sprintf("race-complete-%d", i)))
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, application.ErrCommandConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	after := loadEnrollment(t, e)
	if success != 1 || conflict != 1 || len(after.Users) != len(before.Users)+1 || len(after.Sessions) != len(before.Sessions)+1 {
		t.Fatal("duplicate registration was not atomic")
	}
}
func TestRegistrationActorFlagPurposeAndFields(t *testing.T) {
	e := registrationSetup(t)
	v := registrationBegin(t, e, "guards@umir.invalid", "guards")
	other := application.ChallengeActor{PreauthDigest: application.TokenDigest("different-browser")}
	if _, err := e.accounts.VerifyChallenge(ctx, other, application.ChallengeVerifyInput{CommandID: "foreign", ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)}); !errors.Is(err, application.ErrChallengeUnavailable) {
		t.Fatal("foreign browser verified challenge")
	}
	p := registrationProof(t, e, v, "guards-proof")
	in := registrationComplete(p, "guards-complete")
	for _, tc := range []struct {
		name   string
		change func(*application.EmailCompleteInput)
	}{
		{"short-password", func(i *application.EmailCompleteInput) { i.Password = "short" }},
		{"short-name", func(i *application.EmailCompleteInput) { i.DisplayName = "x" }},
		{"newPassword", func(i *application.EmailCompleteInput) { i.NewPassword = "forbidden-field" }},
		{"wrong-purpose", func(i *application.EmailCompleteInput) { i.Purpose = "login" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := in
			bad.CommandID = tc.name
			tc.change(&bad)
			before := loadEnrollment(t, e)
			if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, bad); err == nil || !reflect.DeepEqual(before, loadEnrollment(t, e)) {
				t.Fatal("invalid completion mutated state")
			}
		})
	}
	actor := application.ChallengeActor{Token: e.owner.Token, CSRFToken: e.owner.CSRFToken}
	if _, err := e.accounts.BeginEmailChallenge(ctx, actor, application.EmailChallengeInput{CommandID: "signed-in", Email: "other@umir.invalid", Purpose: "registration"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("signed-in registration allowed: %v", err)
	}
	e.opts.Registration.Enabled = false
	var err error
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	before := loadEnrollment(t, e)
	if _, err = e.accounts.CompleteEmailChallenge(ctx, e.actor, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("disabled completion: %v", err)
	}
	if _, err = e.accounts.ResendChallenge(ctx, e.actor, v.ChallengeID, "disabled-resend"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("disabled resend: %v", err)
	}
	if _, err = e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "guards-proof", ChallengeID: v.ChallengeID, Code: "123456"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("disabled verify: %v", err)
	}
	if !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatal("disabled operations changed state")
	}
}
func TestRegistrationResendLimitsAndExpiry(t *testing.T) {
	e := registrationSetup(t)
	v := registrationBegin(t, e, "limits@umir.invalid", "limits")
	if _, err := e.accounts.ResendChallenge(ctx, e.actor, v.ChallengeID, "too-soon"); !errors.Is(err, application.ErrChallengeRateLimited) {
		t.Fatal("resend cooldown missing")
	}
	for n := 1; n <= 2; n++ {
		e.advance(t, time.Minute)
		if _, err := e.accounts.ResendChallenge(ctx, e.actor, v.ChallengeID, fmt.Sprintf("resend-%d", n)); err != nil {
			t.Fatal(err)
		}
	}
	e.advance(t, time.Minute)
	if _, err := e.accounts.ResendChallenge(ctx, e.actor, v.ChallengeID, "address-limit"); !registrationRateLimit(err) {
		t.Fatalf("address limit missing: %v", err)
	}
	e.advance(t, 8*time.Minute)
	if _, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "expired", ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)}); !errors.Is(err, application.ErrChallengeUnavailable) {
		t.Fatal("expired challenge verified")
	}
}
func TestRegistrationUnknownCompletionRecoversOriginalSession(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "unknown@umir.invalid", "unknown"), "unknown-proof")
	e.opts.Repository = &faultRepo{AggregateRepository: e.store, mode: application.Unknown, persist: true}
	var err error
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	in := registrationComplete(p, "unknown-complete")
	if _, err = e.accounts.CompleteEmailChallenge(ctx, e.actor, in); !errors.Is(err, application.ErrUpdateOutcomeUnknown) {
		t.Fatalf("unknown outcome lost: %v", err)
	}
	e.reopen(t)
	before := loadEnrollment(t, e)
	issued, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, in)
	if err != nil || issued.Token == "" || !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatalf("unknown result did not recover: %v", err)
	}
}
func registrationRateLimit(err error) bool {
	var limited *application.InvitationRateLimitError
	return errors.As(err, &limited)
}

func TestRegistrationGlobalBudget(t *testing.T) {
	e := registrationSetup(t)
	for n := 0; n < 60; n++ {
		registrationBegin(t, e, fmt.Sprintf("global-%d@umir.invalid", n), fmt.Sprintf("global-%d", n))
	}
	before := loadEnrollment(t, e)
	_, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: "over-global", Email: "over@umir.invalid", Purpose: "registration"})
	if !registrationRateLimit(err) || !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatalf("global issue limit missing: %v", err)
	}
}
func TestRegistrationNeutralAddressBudgets(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "occupied-budget@umir.invalid", "initial-budget"), "initial-budget-proof")
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "initial-budget-complete")); err != nil {
		t.Fatal(err)
	}
	e.advance(t, 11*time.Minute)
	for _, email := range []string{"occupied-budget@umir.invalid", "free-budget@umir.invalid"} {
		for n := 0; n < 3; n++ {
			registrationBegin(t, e, email, fmt.Sprintf("%s-%d", email, n))
		}
		before := loadEnrollment(t, e)
		_, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: email + "-limited", Email: email, Purpose: "registration"})
		if !registrationRateLimit(err) || !reflect.DeepEqual(before, loadEnrollment(t, e)) {
			t.Fatalf("neutral budget differs for %s: %v", email, err)
		}
	}
}

func TestRegistrationOccupiedMixedCaseDomainIsNeutral(t *testing.T) {
	e := registrationSetup(t)
	a := loadEnrollment(t, e)
	previous := a.AggregateRevision
	a.Users[1].Email = "Existing@UMIR.INVALID"
	revision, ok := domain.VersionNumber(previous)
	if !ok {
		t.Fatal("invalid revision")
	}
	a.AggregateRevision = domain.Version(fmt.Sprint(revision + 1))
	if result, err := e.store.Commit(ctx, previous, validate(t, a)); err != nil || result.Outcome != application.Committed {
		t.Fatal(err)
	}
	registrationBegin(t, e, "Existing@umir.invalid", "mixed-domain")
}
