package integration_test

import (
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
)

// gatedHasher holds the first Hash call until released, so a test can look at
// the service while a password is being hashed.
type gatedHasher struct {
	application.PasswordHasher
	calls            atomic.Int64
	armed            atomic.Bool
	entered, release chan struct{}
}

func newGatedHasher(inner application.PasswordHasher) *gatedHasher {
	h := &gatedHasher{PasswordHasher: inner, entered: make(chan struct{}), release: make(chan struct{})}
	h.armed.Store(true)
	return h
}
func (h *gatedHasher) Hash(p string) (string, error) {
	h.calls.Add(1)
	if h.armed.CompareAndSwap(true, false) {
		close(h.entered)
		<-h.release
	}
	return h.PasswordHasher.Hash(p)
}

type hashFlow struct {
	name string
	// prepare returns the completion command, run against a gated hasher.
	prepare func(t *testing.T, e *enrollmentFixture) func() (application.SessionView, error)
	// users is how many users a completed flow adds.
	users int
}

func hashFlows() []hashFlow {
	return []hashFlow{
		{name: "invited user", users: 1, prepare: func(t *testing.T, e *enrollmentFixture) func() (application.SessionView, error) {
			v := e.begin(t)
			proof, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "gate-verify", ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)})
			if err != nil {
				t.Fatal(err)
			}
			in := application.InvitationCompleteInput{CommandID: "gate-enroll", ChallengeID: v.ChallengeID, Proof: proof.Proof, Password: "invited-password", DisplayName: "Invited User"}
			return func() (application.SessionView, error) { return e.accounts.CompleteInvitedUser(ctx, e.actor, in) }
		}},
		{name: "password reset", users: 0, prepare: func(t *testing.T, e *enrollmentFixture) func() (application.SessionView, error) {
			v := e.begin(t)
			proof, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "gate-pre-verify", ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)})
			if err != nil {
				t.Fatal(err)
			}
			created, err := e.accounts.CompleteInvitedUser(ctx, e.actor, application.InvitationCompleteInput{CommandID: "gate-pre-enroll", ChallengeID: v.ChallengeID, Proof: proof.Proof, Password: "invited-password", DisplayName: "Invited User"})
			if err != nil {
				t.Fatal(err)
			}
			actor := application.ChallengeActor{PreauthDigest: application.TokenDigest("synthetic-reset-browser")}
			reset, err := e.accounts.BeginEmailChallenge(ctx, actor, application.EmailChallengeInput{CommandID: "gate-reset-begin", Email: created.User.Email, Purpose: "password_reset"})
			if err != nil {
				t.Fatal(err)
			}
			resetProof, err := e.accounts.VerifyChallenge(ctx, actor, application.ChallengeVerifyInput{CommandID: "gate-reset-verify", ChallengeID: reset.ChallengeID, Code: e.code(t, reset.ChallengeID)})
			if err != nil {
				t.Fatal(err)
			}
			in := application.EmailCompleteInput{CommandID: "gate-reset", ChallengeID: reset.ChallengeID, Proof: resetProof.Proof, Purpose: "password_reset", NewPassword: "replacement-password"}
			return func() (application.SessionView, error) { return e.accounts.CompleteEmailChallenge(ctx, actor, in) }
		}},
	}
}

// gatedSetup returns a fixture whose accounts use a gated hasher; arming happens
// after prepare, so only the completion's own hash is held.
func gatedSetup(t *testing.T, flow hashFlow) (*enrollmentFixture, *gatedHasher, func() (application.SessionView, error)) {
	t.Helper()
	e := enrollmentSetup(t)
	gate := newGatedHasher(e.opts.Passwords)
	gate.armed.Store(false)
	e.opts.Passwords = gate
	var err error
	if e.accounts, err = application.NewAccounts(ctx, e.opts); err != nil {
		t.Fatal(err)
	}
	run := flow.prepare(t, e)
	gate.calls.Store(0)
	gate.armed.Store(true)
	return e, gate, run
}

func runAsync(run func() (application.SessionView, error)) <-chan error {
	out := make(chan error, 1)
	go func() { _, err := run(); out <- err }()
	return out
}

func within(t *testing.T, what string, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish while a password was being hashed", what)
	}
}

func TestPasswordHashingDoesNotHoldTheAccountsMutex(t *testing.T) {
	for _, flow := range hashFlows() {
		t.Run(flow.name, func(t *testing.T) {
			e, gate, run := gatedSetup(t, flow)
			result := runAsync(run)
			t.Cleanup(func() {
				select {
				case <-gate.release:
				default:
					close(gate.release)
				}
			})
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the completion never reached the hasher")
			}
			within(t, "Peek", 2*time.Second, func() {
				if _, err := e.accounts.Peek(ctx, e.owner.Token); err != nil {
					t.Error(err)
				}
			})
			within(t, "another user's login", 2*time.Second, func() {
				if _, err := e.accounts.Login(ctx, application.LoginInput{Login: "second", Password: "password"}); err != nil {
					t.Error(err)
				}
			})
			close(gate.release)
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPasswordHashingIsSkippedForAnExactRepeatAndRaces(t *testing.T) {
	for _, flow := range hashFlows() {
		t.Run(flow.name, func(t *testing.T) {
			e, gate, run := gatedSetup(t, flow)
			before := len(loadEnrollment(t, e).Users)
			first := runAsync(run)
			t.Cleanup(func() {
				select {
				case <-gate.release:
				default:
					close(gate.release)
				}
			})
			<-gate.entered
			// The same command arrives and completes while the first still hashes.
			var second application.SessionView
			var secondErr error
			within(t, "a repeat of the same command", 10*time.Second, func() { second, secondErr = run() })
			if secondErr != nil {
				t.Fatal(secondErr)
			}
			close(gate.release)
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			after := loadEnrollment(t, e)
			if len(after.Users) != before+flow.users {
				t.Fatalf("%d users after two copies of one command; want %d", len(after.Users)-before, flow.users)
			}
			stored := loadEnrollment(t, e)
			calls := gate.calls.Load()
			again, err := run()
			if err != nil || again.Token != second.Token || gate.calls.Load() != calls || !reflect.DeepEqual(stored, loadEnrollment(t, e)) {
				t.Fatalf("an exact repeat hashed again or changed state: %v", err)
			}
		})
	}
}

func TestPasswordHashingLeavesNoTraceWhenTheProofExpiredMeanwhile(t *testing.T) {
	for _, flow := range hashFlows() {
		t.Run(flow.name, func(t *testing.T) {
			e, gate, run := gatedSetup(t, flow)
			result := runAsync(run)
			t.Cleanup(func() {
				select {
				case <-gate.release:
				default:
					close(gate.release)
				}
			})
			<-gate.entered
			e.advance(t, 25*time.Hour)
			before := loadEnrollment(t, e)
			close(gate.release)
			if err := <-result; err == nil {
				t.Fatal("a completion with an expired proof succeeded")
			}
			if !reflect.DeepEqual(before, loadEnrollment(t, e)) {
				t.Fatal("a refused completion left a trace")
			}
		})
	}
}
