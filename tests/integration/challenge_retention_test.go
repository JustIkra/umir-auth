package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/httpapi"
	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

// The retention windows below are the ones fixed by the auth spec (4.1, C18):
// a challenge without a proof goes one hour after it expired, a challenge with a
// proof goes 24 hours after the proof expired. A challenge lives 10 minutes and
// a proof 24 hours.
const (
	challengeLife   = 10 * time.Minute
	withoutProofTTL = challengeLife + time.Hour
	withProofTTL    = 48 * time.Hour
)

func sweep(t *testing.T, e *enrollmentFixture) {
	t.Helper()
	if err := e.accounts.SweepEnrollment(ctx); err != nil {
		t.Fatal(err)
	}
}
func challengeByID(a domain.Aggregate, id domain.EntityID) (domain.Challenge, bool) {
	for _, c := range a.Challenges {
		if c.ChallengeID == id {
			return c, true
		}
	}
	return domain.Challenge{}, false
}
func jobsOf(a domain.Aggregate, id domain.EntityID) []domain.MailJob {
	var jobs []domain.MailJob
	for _, j := range a.MailJobs {
		if j.ChallengeID == id {
			jobs = append(jobs, j)
		}
	}
	return jobs
}
func commandRecord(t *testing.T, a domain.Aggregate, operation, command string) domain.IdempotencyRecord {
	t.Helper()
	for _, r := range a.Idempotency {
		if r.OperationID == operation && r.CommandID == command {
			return r
		}
	}
	t.Fatalf("no %s record for %s", operation, command)
	return domain.IdempotencyRecord{}
}
func assertGone(t *testing.T, e *enrollmentFixture, ids ...domain.EntityID) {
	t.Helper()
	a := loadEnrollment(t, e)
	for _, id := range ids {
		if _, ok := challengeByID(a, id); ok {
			t.Fatalf("challenge %s was not purged", id)
		}
		if len(jobsOf(a, id)) != 0 {
			t.Fatalf("jobs of challenge %s were not purged", id)
		}
	}
}
func assertKept(t *testing.T, e *enrollmentFixture, ids ...domain.EntityID) {
	t.Helper()
	a := loadEnrollment(t, e)
	for _, id := range ids {
		if _, ok := challengeByID(a, id); !ok {
			t.Fatalf("challenge %s was purged early", id)
		}
	}
}

// memoryRepo applies the same validation as the file store without the disk, so
// the 4000-commit flood below is not also bounded by fsync. It is test-only.
type memoryRepo struct {
	current domain.ValidatedAggregate
	clock   application.Clock
}

func (r *memoryRepo) Load(context.Context) (domain.ValidatedAggregate, error) { return r.current, nil }
func (r *memoryRepo) Commit(_ context.Context, expected domain.Version, next domain.ValidatedAggregate) (application.CommitResult, error) {
	if expected != r.current.Revision() {
		return application.CommitResult{}, application.ErrRevisionConflict
	}
	// next is already a ValidatedAggregate; only the replacement rules remain.
	if err := domain.ValidateReplacementAt(r.current, next, r.clock.Now()); err != nil {
		return application.CommitResult{}, err
	}
	r.current = next
	return application.CommitResult{Outcome: application.Committed, AggregateRevision: next.Revision()}, nil
}

// The flood of password resets for unknown addresses is the spec's 4.1 case:
// 60 per 10 minutes fills the 4096 rows in about 11.5 hours. Running 4100 live
// commits costs minutes under -race (every commit validates all stored command
// records), so the history of the first 11 hours is seeded as rows an earlier
// release left behind (expired, jobs suppressed), and the last two hours run live
// with the clock moving. Without purging, the seeded rows plus the live ones pass
// 4096 within an hour; with it, they leave on the first sweep.
func TestPasswordResetUnknownAddressesStayBounded(t *testing.T) {
	e := registrationSetup(t)
	current, err := e.store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := current.Snapshot()
	if a.SchemaVersion != 3 {
		t.Fatalf("schema %d; the seeded unknown-address rows need schema 3", a.SchemaVersion)
	}
	now := e.opts.Clock.Now()
	const seeded = 4000
	order := int64(1)
	if n := len(a.MailJobs); n > 0 {
		last, ok := domain.VersionNumber(a.MailJobs[n-1].EnqueueOrder)
		if !ok {
			t.Fatal("bad enqueue order")
		}
		order = last + 1
	}
	digest := application.TokenDigest("seeded-initiator")
	for i := 0; i < seeded; i++ {
		id, job := uid(100000+2*i), uid(100001+2*i)
		accepted := instant(now.Add(-11*time.Hour + time.Duration(i)*time.Second))
		expires := instant(now.Add(-11*time.Hour + time.Duration(i)*time.Second + challengeLife))
		a.Challenges = append(a.Challenges, domain.Challenge{ChallengeID: id, Purpose: "password_reset", SuppressedEmail: fmt.Sprintf("stale-%d@umir.invalid", i), InitiatorDigest: digest, CodeDigest: digest, ExpiresAt: expires, ResendAvailableAt: accepted, State: "expired", IssueCount: 1})
		a.MailJobs = append(a.MailJobs, domain.MailJob{Purpose: "otp", EnqueueOrder: domain.Version(fmt.Sprint(order)), JobID: job, ChallengeID: id, State: "suppressed", AcceptedAt: accepted})
		order++
	}
	validated, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	repo := &memoryRepo{current: validated, clock: e.opts.Clock}
	e.opts.Repository = repo
	if e.accounts, err = application.NewAccounts(ctx, e.opts); err != nil {
		t.Fatal(err)
	}
	rows := func() int { return len(repo.current.Snapshot().Challenges) }
	const windows = 4 // 60 password resets per 10 minutes
	for w := 0; w < windows; w++ {
		sweep(t, e)
		for n := 0; n < 60; n++ {
			in := application.EmailChallengeInput{CommandID: fmt.Sprintf("flood-%d-%d", w, n), Email: fmt.Sprintf("nobody-%d-%d@umir.invalid", w, n), Purpose: "password_reset"}
			if _, err := e.accounts.BeginEmailChallenge(ctx, e.actor, in); err != nil {
				t.Fatalf("window %d request %d: %v", w, n, err)
			}
		}
		e.advance(t, 10*time.Minute)
		sweep(t, e)
	}
	if n := rows(); n > 1000 {
		t.Fatalf("%d challenge rows retained; want at most 1000", n)
	}
	if _, err := e.accounts.BeginInvitationChallenge(ctx, e.actor, application.ChallengeBeginInput{CommandID: "after-flood", InvitationID: e.invitation.InvitationID}); err != nil {
		t.Fatalf("invitation challenge refused after the flood: %v", err)
	}
}

func TestVerifiedChallengeWithinProofWindowSurvives(t *testing.T) {
	e := registrationSetup(t)
	a := registrationBegin(t, e, "proof-a@umir.invalid", "begin-a")
	b := registrationBegin(t, e, "proof-b@umir.invalid", "begin-b")
	pa := registrationProof(t, e, a, "verify-a")
	registrationProof(t, e, b, "verify-b")
	e.advance(t, 24*time.Hour-time.Minute)
	sweep(t, e)
	assertKept(t, e, a.ChallengeID, b.ChallengeID)
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(pa, "complete-a")); err != nil {
		t.Fatalf("proof inside its window refused after a sweep: %v", err)
	}
	e.advance(t, withProofTTL-24*time.Hour+time.Minute-time.Minute) // one minute before the end of the proof retention
	sweep(t, e)
	assertKept(t, e, a.ChallengeID, b.ChallengeID)
	e.advance(t, time.Minute)
	sweep(t, e)
	assertGone(t, e, a.ChallengeID, b.ChallengeID)
}

func TestRecentWrongCodesSurviveSweep(t *testing.T) {
	e := registrationSetup(t)
	first := registrationBegin(t, e, "Target@umir.invalid", "wrong-begin-1")
	second := registrationBegin(t, e, "target@umir.invalid", "wrong-begin-2")
	e.advance(t, 9*time.Minute)
	for n, v := range []application.ChallengeView{first, second} {
		code := "000000"
		if e.code(t, v.ChallengeID) == code {
			code = "999999"
		}
		for j := 0; j < 5; j++ {
			_, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: fmt.Sprintf("wrong-%d-%d", n, j), ChallengeID: v.ChallengeID, Code: code})
			if j < 4 && !errors.Is(err, application.ErrChallengeInvalidCode) || j == 4 && !errors.Is(err, application.ErrChallengeLocked) {
				t.Fatal(err)
			}
		}
	}
	e.advance(t, withoutProofTTL-9*time.Minute-2*time.Minute) // 59 minutes after the last wrong code
	sweep(t, e)
	assertKept(t, e, first.ChallengeID, second.ChallengeID)
	a := loadEnrollment(t, e)
	for _, v := range []application.ChallengeView{first, second} {
		if c, _ := challengeByID(a, v.ChallengeID); len(c.WrongAttemptTimes) != 5 || c.WrongAttempts != 5 {
			t.Fatal("sweep erased recent wrong codes")
		}
	}
	third := registrationBegin(t, e, "target@umir.invalid", "wrong-begin-3")
	before := loadEnrollment(t, e)
	_, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "wrong-blocked", ChallengeID: third.ChallengeID, Code: e.code(t, third.ChallengeID)})
	if !registrationRateLimit(err) {
		t.Fatalf("address wrong-code budget was reset by the sweep: %v", err)
	}
	if !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatal("rate refusal mutated state")
	}
	e.advance(t, 2*time.Minute) // the last wrong code is now older than an hour
	sweep(t, e)
	assertGone(t, e, first.ChallengeID, second.ChallengeID)
	if _, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "wrong-allowed", ChallengeID: third.ChallengeID, Code: e.code(t, third.ChallengeID)}); err != nil {
		t.Fatalf("budget did not recover with the window: %v", err)
	}
}

func TestConsumedProofNotAcceptedAfterSweep(t *testing.T) {
	e := registrationSetup(t)
	consumed := registrationBegin(t, e, "consumed@umir.invalid", "begin-consumed")
	unused := registrationBegin(t, e, "unused@umir.invalid", "begin-unused")
	proofConsumed := registrationProof(t, e, consumed, "verify-consumed")
	proofUnused := registrationProof(t, e, unused, "verify-unused")
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(proofConsumed, "complete-consumed")); err != nil {
		t.Fatal(err)
	}
	e.advance(t, withProofTTL)
	sweep(t, e)
	assertGone(t, e, consumed.ChallengeID, unused.ChallengeID)
	before := loadEnrollment(t, e)
	for n, p := range []application.VerifiedChallenge{proofConsumed, proofUnused} {
		_, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, fmt.Sprintf("reuse-%d", n)))
		if !errors.Is(err, application.ErrChallengeUnavailable) {
			t.Fatalf("proof %d accepted after the sweep: %v", n, err)
		}
	}
	after := loadEnrollment(t, e)
	if len(after.Users) != len(before.Users) || len(after.Sessions) != len(before.Sessions) {
		t.Fatal("a purged proof created an account or session")
	}
}

type mailSenderFunc func() application.DeliveryResult

func (f mailSenderFunc) Send(_ context.Context, _ application.MailDelivery) application.DeliveryResult {
	return f()
}

func TestQueuedSendingUnknownJobsAndInWindowReplayKept(t *testing.T) {
	t.Run("queued job is never dropped with its challenge", func(t *testing.T) {
		e := registrationSetup(t)
		v := registrationBegin(t, e, "queued@umir.invalid", "begin-queued")
		e.advance(t, 3*time.Hour)
		sweep(t, e)
		assertKept(t, e, v.ChallengeID)
		if jobs := jobsOf(loadEnrollment(t, e), v.ChallengeID); len(jobs) != 1 || jobs[0].State == "queued" {
			t.Fatal("expired challenge left a queued job; it must be suppressed before the challenge goes")
		}
		sweep(t, e)
		assertGone(t, e, v.ChallengeID)
	})
	t.Run("sending job pins its challenge", func(t *testing.T) {
		e := registrationSetup(t)
		v := registrationBegin(t, e, "sending@umir.invalid", "begin-sending")
		entered, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			_, err := e.accounts.ProcessMail(ctx, mailSenderFunc(func() application.DeliveryResult {
				entered <- struct{}{}
				<-release
				return application.DeliveryResult{Success: true}
			}))
			done <- err
		}()
		<-entered
		e.advance(t, 3*time.Hour)
		sweep(t, e)
		sweep(t, e)
		assertKept(t, e, v.ChallengeID)
		if jobs := jobsOf(loadEnrollment(t, e), v.ChallengeID); len(jobs) != 1 || jobs[0].State != "sending" {
			t.Fatalf("sending job lost: %+v", jobs)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		sweep(t, e)
		assertGone(t, e, v.ChallengeID)
	})
	t.Run("unknown job is resolved before the challenge goes", func(t *testing.T) {
		e := registrationSetup(t)
		v := registrationBegin(t, e, "unknown@umir.invalid", "begin-unknown")
		if _, err := e.accounts.ProcessMail(ctx, mailSenderFunc(func() application.DeliveryResult { return application.DeliveryResult{Unknown: true} })); err != nil {
			t.Fatal(err)
		}
		if jobs := jobsOf(loadEnrollment(t, e), v.ChallengeID); len(jobs) != 1 || jobs[0].State != "unknown" {
			t.Fatalf("job is not unknown: %+v", jobs)
		}
		e.advance(t, 3*time.Hour)
		sweep(t, e)
		assertKept(t, e, v.ChallengeID)
		sweep(t, e)
		assertGone(t, e, v.ChallengeID)
	})
	t.Run("replay inside the window is unchanged", func(t *testing.T) {
		e := registrationSetup(t)
		in := application.EmailChallengeInput{CommandID: "begin-window", Email: "window@umir.invalid", Purpose: "registration"}
		v, err := e.accounts.BeginEmailChallenge(ctx, e.actor, in)
		if err != nil {
			t.Fatal(err)
		}
		e.advance(t, 30*time.Minute)
		sweep(t, e)
		before := loadEnrollment(t, e)
		again, err := e.accounts.BeginEmailChallenge(ctx, e.actor, in)
		if err != nil || again != v || !reflect.DeepEqual(before, loadEnrollment(t, e)) {
			t.Fatalf("replay inside the retention window changed: %v", err)
		}
	})
}

// purgeAfterExpiry lets the challenges expire, sweeps (this suppresses their
// jobs), waits out the retention and sweeps again, as the worker does.
func purgeAfterExpiry(t *testing.T, e *enrollmentFixture, age time.Duration) {
	t.Helper()
	e.advance(t, challengeLife+time.Minute)
	sweep(t, e)
	e.advance(t, age-challengeLife-time.Minute)
	sweep(t, e)
}

func TestReplayAfterSweepIsCommandConflictUnknown(t *testing.T) {
	e := registrationSetup(t)
	reset := application.EmailChallengeInput{CommandID: "tomb-reset", Email: "ghost@umir.invalid", Purpose: "password_reset"}
	resetView, err := e.accounts.BeginEmailChallenge(ctx, e.actor, reset)
	if err != nil {
		t.Fatal(err)
	}
	invite := application.ChallengeBeginInput{CommandID: "tomb-invite", InvitationID: e.invitation.InvitationID}
	inviteView, err := e.accounts.BeginInvitationChallenge(ctx, e.actor, invite)
	if err != nil {
		t.Fatal(err)
	}
	e.advance(t, 2*time.Minute)
	if _, err := e.accounts.ResendChallenge(ctx, e.actor, inviteView.ChallengeID, "tomb-resend"); err != nil {
		t.Fatal(err)
	}
	original := loadEnrollment(t, e)
	originals := map[string]domain.IdempotencyRecord{
		"beginEmailChallenge":      commandRecord(t, original, "beginEmailChallenge", reset.CommandID),
		"beginInvitationChallenge": commandRecord(t, original, "beginInvitationChallenge", invite.CommandID),
		"resendChallenge":          commandRecord(t, original, "resendChallenge", "tomb-resend"),
	}
	purgeAfterExpiry(t, e, withoutProofTTL+2*time.Minute)
	assertGone(t, e, resetView.ChallengeID, inviteView.ChallengeID)
	after := loadEnrollment(t, e)
	if len(after.Challenges) != 0 || len(after.MailJobs) != 0 {
		t.Fatalf("challenges %d, jobs %d remain", len(after.Challenges), len(after.MailJobs))
	}
	for op, was := range originals {
		got := commandRecord(t, after, op, was.CommandID)
		want := was
		want.EncryptedResponse, want.JobIDs = "", []domain.EntityID{}
		if got.EncryptedResponse != "" || len(got.JobIDs) != 0 || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s record is not the tombstone of the original: %+v", op, got)
		}
		if got.Fingerprint != was.Fingerprint {
			t.Fatalf("%s tombstone lost the fingerprint", op)
		}
	}
	e.reopen(t)
	if !reflect.DeepEqual(after, loadEnrollment(t, e)) {
		t.Fatal("tombstones did not survive a restart")
	}
	snapshot := loadEnrollment(t, e)
	cleared := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, application.ErrCommandResultCleared) || !errors.Is(err, application.ErrCommandConflict) {
			t.Fatalf("%s replay after purge = %v; want a cleared command conflict", name, err)
		}
		if !reflect.DeepEqual(snapshot, loadEnrollment(t, e)) {
			t.Fatalf("%s replay after purge changed state", name)
		}
	}
	_, err = e.accounts.BeginEmailChallenge(ctx, e.actor, reset)
	cleared("beginEmailChallenge", err)
	_, err = e.accounts.BeginInvitationChallenge(ctx, e.actor, invite)
	cleared("beginInvitationChallenge", err)
	_, err = e.accounts.ResendChallenge(ctx, e.actor, inviteView.ChallengeID, "tomb-resend")
	cleared("resendChallenge", err)
	// A different request under a cleared key is the ordinary conflict.
	other := reset
	other.Email = "other@umir.invalid"
	if _, err := e.accounts.BeginEmailChallenge(ctx, e.actor, other); !errors.Is(err, application.ErrCommandConflict) || errors.Is(err, application.ErrCommandResultCleared) {
		t.Fatalf("different input under a cleared key = %v", err)
	}
	namespace, err := application.Namespace(application.CommandNamespace{OperationID: "beginEmailChallenge"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.accounts.LookupCommand(ctx, e.actor, namespace, reset.CommandID)
	cleared("lookup", err)
}

func TestReplayAfterSweepIsCommandConflictUnknownOverHTTP(t *testing.T) {
	e := registrationSetup(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.New(jwt.Options{Clock: e.opts.Clock, IDs: e.opts.IDs, Active: jwt.SigningKey{KID: "retention", PrivateKey: key}})
	if err != nil {
		t.Fatal(err)
	}
	preauth, err := httpapi.NewPreauth([]byte(strings.Repeat("k", 32)), e.opts.Clock)
	if err != nil {
		t.Fatal(err)
	}
	gateway := strings.Repeat("a", 64)
	h, err := httpapi.New(httpapi.Options{Accounts: e.accounts, Signer: signer, Clock: e.opts.Clock, Preauth: preauth, ServiceKeys: map[string]string{"gateway": gateway, "serving": strings.Repeat("b", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	// A remember-me session (30 days) outlives the retention window; a preauth
	// token lasts only 30 minutes.
	registered := registrationProof(t, e, registrationBegin(t, e, "http-user@umir.invalid", "http-register"), "http-register-verify")
	owner, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(registered, "http-register-complete"))
	if err != nil {
		t.Fatal(err)
	}
	call := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/internal/auth/v1/public/email-challenges", bytes.NewReader([]byte(body)))
		r.Header.Set("X-Umir-Service-Key", gateway)
		r.Header.Set("X-Umir-Session", owner.Token)
		r.Header.Set("X-Umir-CSRF-Token", owner.CSRFToken)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	body := `{"commandID":"http-reset","email":"ghost@umir.invalid","purpose":"password_reset"}`
	first := call(body)
	if first.Code != http.StatusOK {
		t.Fatalf("begin = %d %s", first.Code, first.Body)
	}
	var view application.ChallengeView
	if err := json.Unmarshal(first.Body.Bytes(), &view); err != nil || view.ChallengeID == "" {
		t.Fatalf("begin answer: %v", err)
	}
	purgeAfterExpiry(t, e, withoutProofTTL+2*time.Minute)
	assertGone(t, e, view.ChallengeID)
	before := loadEnrollment(t, e)
	replay := call(body)
	var got struct {
		Code      string `json:"code"`
		Outcome   string `json:"outcome"`
		Retryable bool   `json:"retryable"`
	}
	if replay.Code != http.StatusConflict || json.Unmarshal(replay.Body.Bytes(), &got) != nil || got.Code != "CommandConflict" || got.Outcome != "unknown" {
		t.Fatalf("replay after purge = %d %s; want 409 CommandConflict outcome unknown", replay.Code, replay.Body)
	}
	if !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatal("replay after purge created a challenge or changed state")
	}
}

// A verify or complete command is not tombstoned: its stored result stays under
// the (unchanged) idempotency retention, so an exact repeat still replays it after
// the challenge itself is gone, and a different request under the key conflicts.
func TestVerifyAndCompleteReplayAfterChallengePurge(t *testing.T) {
	e := registrationSetup(t)
	v := registrationBegin(t, e, "replay-purge@umir.invalid", "replay-begin")
	code := e.code(t, v.ChallengeID)
	proof := registrationProof(t, e, v, "replay-verify")
	complete := registrationComplete(proof, "replay-complete")
	session, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, complete)
	if err != nil {
		t.Fatal(err)
	}
	e.advance(t, withProofTTL)
	sweep(t, e)
	assertGone(t, e, v.ChallengeID)
	snapshot := loadEnrollment(t, e)
	again, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "replay-verify", ChallengeID: v.ChallengeID, Code: "123456"})
	if !errors.Is(err, application.ErrCommandConflict) {
		t.Fatalf("verify with another code under the key = %v, %+v", err, again)
	}
	repeated, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "replay-verify", ChallengeID: v.ChallengeID, Code: code})
	if err != nil || repeated.Proof != proof.Proof {
		t.Fatalf("verify replay after the purge = %v", err)
	}
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, complete); errors.Is(err, application.ErrChallengeUnavailable) {
		t.Fatalf("complete replay after the purge reports an unknown challenge: %v", err)
	} else if err == nil && session.Token == "" {
		t.Fatal("complete replay returned no session")
	}
	if !reflect.DeepEqual(snapshot, loadEnrollment(t, e)) {
		t.Fatal("replays after the purge changed state")
	}
}
