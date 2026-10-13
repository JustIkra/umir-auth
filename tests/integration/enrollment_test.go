package integration_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/challengesecrets"
	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type enrollmentFixture struct {
	*membershipFixture
	crypto     *challengesecrets.ChallengeCrypto
	actor      application.ChallengeActor
	invitation domain.Invitation
}

func enrollmentSetup(t *testing.T) *enrollmentFixture {
	t.Helper()
	f := membershipsSetup(t)
	crypto, err := challengesecrets.New([]byte(strings.Repeat("p", 32)), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	f.opts.Challenges = crypto
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	e := &enrollmentFixture{membershipFixture: f, crypto: crypto, actor: application.ChallengeActor{PreauthDigest: application.TokenDigest("synthetic-invited-browser")}}
	e.invitation, err = e.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, application.CreateInvitationInput{CommandID: "invite-1", Email: "Invited@UMIR.INVALID", Assignments: []domain.InviteAssignment{{RestaurantID: f.r1, Roles: []string{"Warehouse", "Waiter"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func (e *enrollmentFixture) begin(t *testing.T) application.ChallengeView {
	t.Helper()
	v, err := e.accounts.BeginInvitationChallenge(ctx, e.actor, application.ChallengeBeginInput{CommandID: "begin-1", InvitationID: e.invitation.InvitationID})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func (e *enrollmentFixture) code(t *testing.T, id domain.EntityID) string {
	t.Helper()
	a, err := e.store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range a.Snapshot().Challenges {
		if c.ChallengeID == id {
			value, err := e.crypto.Open("code:"+string(id)+":"+c.Purpose, c.EncryptedCode)
			if err != nil {
				t.Fatal("cannot recover code privately")
			}
			return value
		}
	}
	t.Fatal("challenge absent")
	return ""
}
func (e *enrollmentFixture) reopen(t *testing.T) {
	t.Helper()
	if err := e.store.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := jsonstore.Open(ctx, e.path)
	if err != nil {
		t.Fatal(err)
	}
	e.store = r
	e.opts.Repository = r
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
}
func loadEnrollment(t *testing.T, e *enrollmentFixture) domain.Aggregate {
	t.Helper()
	v, err := e.store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return v.Snapshot()
}
func TestA4InvitationBoundAtomicJobReplayReopen(t *testing.T) {
	e := enrollmentSetup(t)
	v := e.begin(t)
	before := loadEnrollment(t, e)
	if len(before.Challenges) != 1 || len(before.MailJobs) != 1 {
		t.Fatal("challenge and mail did not commit together")
	}
	j := before.MailJobs[0]
	var record domain.IdempotencyRecord
	for _, r := range before.Idempotency {
		if r.OperationID == "beginInvitationChallenge" {
			record = r
		}
	}
	if len(record.JobIDs) != 1 || record.JobIDs[0] != j.JobID || j.ChallengeID != v.ChallengeID || record.AggregateRevision != before.AggregateRevision {
		t.Fatal("original command-to-job edge missing")
	}
	e.advance(t, 11*time.Minute)
	e.reopen(t)
	same := e.begin(t)
	after := loadEnrollment(t, e)
	if same != v || !reflect.DeepEqual(before, after) {
		t.Fatal("exact retained begin replay changed durable edge/deadline")
	}
	if _, err := e.accounts.BeginInvitationChallenge(ctx, application.ChallengeActor{PreauthDigest: application.TokenDigest("other-browser")}, application.ChallengeBeginInput{CommandID: "begin-1", InvitationID: e.invitation.InvitationID}); !errors.Is(err, application.ErrChallengeRateLimited) && err != nil {
		t.Fatal(err)
	}
}
func TestA4WrongCodeExactRetryLocksOnceAndSurvivesRestart(t *testing.T) {
	e := enrollmentSetup(t)
	v := e.begin(t)
	wrong := "000000"
	if e.code(t, v.ChallengeID) == wrong {
		wrong = "111111"
	}
	in := application.ChallengeVerifyInput{CommandID: "wrong-1", ChallengeID: v.ChallengeID, Code: wrong}
	for n := 0; n < 2; n++ {
		if _, err := e.accounts.VerifyChallenge(ctx, e.actor, in); !errors.Is(err, application.ErrChallengeInvalidCode) {
			t.Fatal("wrong code outcome not retained")
		}
		e.reopen(t)
	}
	a := loadEnrollment(t, e)
	if a.Challenges[0].WrongAttempts != 1 {
		t.Fatal("wrong-code retry consumed another attempt")
	}
	for n := 2; n <= 5; n++ {
		in.CommandID = string(rune('a' + n))
		_, err := e.accounts.VerifyChallenge(ctx, e.actor, in)
		if n < 5 && !errors.Is(err, application.ErrChallengeInvalidCode) || n == 5 && !errors.Is(err, application.ErrChallengeLocked) {
			t.Fatal("incorrect wrong-attempt boundary")
		}
	}
	a = loadEnrollment(t, e)
	if a.Challenges[0].WrongAttempts != 5 || a.Challenges[0].State != "locked" || a.MailJobs[0].State != "suppressed" || a.MailJobs[0].EncryptedPayload != "" || a.Challenges[0].EncryptedCode != "" {
		t.Fatal("lock failed to suppress/scrub unsent material")
	}
}
func TestA4ProofReplayAndAtomicInvitedCompletion(t *testing.T) {
	e := enrollmentSetup(t)
	v := e.begin(t)
	code := e.code(t, v.ChallengeID)
	verify := application.ChallengeVerifyInput{CommandID: "verify-1", ChallengeID: v.ChallengeID, Code: code}
	proof, err := e.accounts.VerifyChallenge(ctx, e.actor, verify)
	if err != nil {
		t.Fatal(err)
	}
	e.reopen(t)
	again, err := e.accounts.VerifyChallenge(ctx, e.actor, verify)
	if err != nil || again != proof {
		t.Fatal("proof replay lost after restart")
	}
	in := application.InvitationCompleteInput{CommandID: "complete-1", ChallengeID: v.ChallengeID, Proof: proof.Proof, Password: "invited-password", DisplayName: "Invited User"}
	issued, err := e.accounts.CompleteInvitedUser(ctx, e.actor, in)
	if err != nil {
		t.Fatal(err)
	}
	a := loadEnrollment(t, e)
	if len(a.Users) != 4 || len(a.Memberships) != 6 || a.Invitations[0].State != "accepted" || a.Challenges[0].State != "completed" {
		t.Fatal("account, membership, proof and session were not atomic")
	}
	e.advance(t, 25*time.Hour)
	e.reopen(t)
	_, err = e.accounts.CompleteInvitedUser(ctx, e.actor, in)
	if !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("replay returned expired saved session")
	}
	if issued.User.Email != e.invitation.Email {
		t.Fatal("verified delivery address was not preserved")
	}
}
func TestA4UnknownCommitRecoversOriginalEdge(t *testing.T) {
	e := enrollmentSetup(t)
	f := &faultRepo{AggregateRepository: e.store, mode: application.Unknown, persist: true}
	e.opts.Repository = f
	var err error
	e.accounts, err = application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	in := application.ChallengeBeginInput{CommandID: "lost-begin", InvitationID: e.invitation.InvitationID}
	if _, err := e.accounts.BeginInvitationChallenge(ctx, e.actor, in); !errors.Is(err, application.ErrUpdateOutcomeUnknown) {
		t.Fatal("lost durable outcome was reported as success")
	}
	e.reopen(t)
	a := loadEnrollment(t, e)
	v, err := e.accounts.BeginInvitationChallenge(ctx, e.actor, in)
	if err != nil {
		t.Fatal(err)
	}
	after := loadEnrollment(t, e)
	if !reflect.DeepEqual(a, after) || len(after.MailJobs) != 1 || after.MailJobs[0].ChallengeID != v.ChallengeID {
		t.Fatal("recovery replaced original challenge/job")
	}
}

type mailCapture struct {
	mu         sync.Mutex
	deliveries []application.MailDelivery
	result     application.DeliveryResult
}
type interruptedSender struct{ cancel context.CancelFunc }

func (s interruptedSender) Send(context.Context, application.MailDelivery) application.DeliveryResult {
	s.cancel()
	return application.DeliveryResult{Unknown: true}
}
func TestA4InterruptedSendingReopensAsUnknown(t *testing.T) {
	e := enrollmentSetup(t)
	e.begin(t)
	attempt, cancel := context.WithCancel(ctx)
	defer cancel()
	if _, err := e.accounts.ProcessMail(attempt, interruptedSender{cancel}); !errors.Is(err, context.Canceled) {
		t.Fatal("worker did not preserve interrupted send")
	}
	a := loadEnrollment(t, e)
	if a.MailJobs[0].State != "sending" {
		t.Fatal("test did not interrupt a durable send")
	}
	id := a.MailJobs[0].JobID
	e.reopen(t)
	a = loadEnrollment(t, e)
	if a.MailJobs[0].State != "unknown" || a.MailJobs[0].Attempts != 1 || a.MailJobs[0].JobID != id {
		t.Fatal("restart did not recover the real interrupted job")
	}
}

func (m *mailCapture) Send(_ context.Context, d application.MailDelivery) application.DeliveryResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deliveries = append(m.deliveries, d)
	return m.result
}
func TestA4OutboxUnknownRetryStableJobAndCooldown(t *testing.T) {
	e := enrollmentSetup(t)
	e.begin(t)
	sender := &mailCapture{result: application.DeliveryResult{Unknown: true}}
	if worked, err := e.accounts.ProcessMail(ctx, sender); err != nil || !worked {
		t.Fatal("worker failed")
	}
	a := loadEnrollment(t, e)
	if a.MailJobs[0].State != "unknown" || a.MailJobs[0].Attempts != 1 {
		t.Fatal("ambiguous delivery was not durable")
	}
	e.reopen(t)
	if worked, err := e.accounts.ProcessMail(ctx, sender); err != nil || worked {
		t.Fatal("retry ignored physical delay")
	}
	e.advance(t, time.Minute)
	sender.result = application.DeliveryResult{Success: true}
	if worked, err := e.accounts.ProcessMail(ctx, sender); err != nil || !worked {
		t.Fatal("retry not sent")
	}
	if len(sender.deliveries) != 2 || sender.deliveries[0].JobID != sender.deliveries[1].JobID || sender.deliveries[0].Mail.ChallengeID != sender.deliveries[1].Mail.ChallengeID {
		t.Fatal("transport retry changed durable correlation")
	}
	a = loadEnrollment(t, e)
	if a.MailJobs[0].State != "delivered" || a.MailJobs[0].EncryptedPayload != "" {
		t.Fatal("confirmed delivery not scrubbed")
	}
}
func TestA4InvitationExpiryAndCrossBrowserProofDenied(t *testing.T) {
	e := enrollmentSetup(t)
	v := e.begin(t)
	in := application.ChallengeVerifyInput{CommandID: "verify", ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)}
	if _, err := e.accounts.VerifyChallenge(ctx, application.ChallengeActor{PreauthDigest: application.TokenDigest("foreign-browser")}, in); !errors.Is(err, application.ErrChallengeUnavailable) {
		t.Fatal("cross-browser verification admitted")
	}
	e.advance(t, 10*time.Minute)
	if _, err := e.accounts.VerifyChallenge(ctx, e.actor, in); !errors.Is(err, application.ErrChallengeUnavailable) {
		t.Fatal("expiry equality admitted")
	}
	e.advance(t, 7*24*time.Hour)
	if _, err := e.accounts.BeginInvitationChallenge(ctx, e.actor, application.ChallengeBeginInput{CommandID: "expired", InvitationID: e.invitation.InvitationID}); !errors.Is(err, application.ErrInvitationUnavailable) {
		t.Fatal("expired invitation admitted")
	}
}
func TestA4ResendCommandKeepsOriginalJobEdge(t *testing.T) {
	e := enrollmentSetup(t)
	v := e.begin(t)
	if _, err := e.accounts.ResendChallenge(ctx, e.actor, v.ChallengeID, "resend"); !errors.Is(err, application.ErrChallengeRateLimited) {
		t.Fatal("resend cooldown ignored")
	}
	e.advance(t, time.Minute)
	next, err := e.accounts.ResendChallenge(ctx, e.actor, v.ChallengeID, "resend")
	if err != nil {
		t.Fatal(err)
	}
	a := loadEnrollment(t, e)
	if next.ExpiresAt != v.ExpiresAt || len(a.MailJobs) != 2 {
		t.Fatal("resend moved expiry or lost mail")
	}
	e.reopen(t)
	same, err := e.accounts.ResendChallenge(ctx, e.actor, v.ChallengeID, "resend")
	if err != nil || same != next || !reflect.DeepEqual(a, loadEnrollment(t, e)) {
		t.Fatal("resend replay changed original job")
	}
}
func TestA4ConcurrentInvitedCompletionCreatesOneUser(t *testing.T) {
	e := enrollmentSetup(t)
	v := e.begin(t)
	proof, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "verify", ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	success := make(chan bool, 2)
	for _, command := range []string{"complete-a", "complete-b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.accounts.CompleteInvitedUser(ctx, e.actor, application.InvitationCompleteInput{CommandID: command, ChallengeID: v.ChallengeID, Proof: proof.Proof, Password: "invited-password", DisplayName: "Invited User"})
			success <- err == nil
		}()
	}
	wg.Wait()
	close(success)
	n := 0
	for ok := range success {
		if ok {
			n++
		}
	}
	if n != 1 || len(loadEnrollment(t, e).Users) != 4 {
		t.Fatal("proof consumed by multiple completions")
	}
}
func TestA4NoPlaintextCodeOrProofInAuthority(t *testing.T) {
	e := enrollmentSetup(t)
	v := e.begin(t)
	code := e.code(t, v.ChallengeID)
	proof, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "verify", ChallengeID: v.ChallengeID, Code: code})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), proof.Proof) || strings.Contains(string(b), `"Code":"`+code+`"`) {
		t.Fatal("plaintext secret persisted")
	}
}
func TestA4WrongRetainedOTPKeyFailsStartup(t *testing.T) {
	e := enrollmentSetup(t)
	e.begin(t)
	wrong, err := challengesecrets.New([]byte(strings.Repeat("x", 32)), []byte(strings.Repeat("y", 32)))
	if err != nil {
		t.Fatal(err)
	}
	e.opts.Challenges = wrong
	if _, err := application.NewAccounts(ctx, e.opts); !errors.Is(err, application.ErrAuthUnavailable) {
		t.Fatal("startup accepted unrecoverable OTP/job material")
	}
}
func TestA4ExpiredMailAdmissionScrubsCodeAndRetainsEdge(t *testing.T) {
	e := enrollmentSetup(t)
	e.begin(t)
	e.advance(t, 10*time.Minute)
	sender := &mailCapture{result: application.DeliveryResult{Success: true}}
	if _, err := e.accounts.ProcessMail(ctx, sender); err != nil {
		t.Fatal(err)
	}
	a := loadEnrollment(t, e)
	if len(sender.deliveries) != 0 || a.Challenges[0].State != "expired" || a.Challenges[0].EncryptedCode != "" || a.MailJobs[0].State != "suppressed" {
		t.Fatal("expired material remained active or escaped admission")
	}
}

func (e *enrollmentFixture) advance(t *testing.T, d time.Duration) {
	t.Helper()
	c, ok := e.opts.Clock.(*clock)
	if !ok {
		t.Fatal("owner clock binding lost")
	}
	c.advance(d)
}
