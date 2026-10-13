package integration_test

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/adapters/sessionsecrets"
	"github.com/JustIkra/umir-auth/internal/application"
)

func TestLoginCommandLostResponseExactReplayAndConflict(t *testing.T) {
	_, r, c, m, p := setup(t)
	secrets, err := sessionsecrets.New([]byte(strings.Repeat("s", 32)), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newService := func(repo application.AggregateRepository) *application.Accounts {
		s, err := application.NewAccounts(ctx, application.AccountOptions{Repository: repo, Passwords: m, Clock: c, IDs: m, Tokens: m, Results: secrets})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	f := &faultRepo{AggregateRepository: r, mode: application.Unknown, persist: true}
	s := newService(f)
	in := application.LoginInput{Login: "owner", Password: "password", CommandID: "login-once", PreauthDigest: application.TokenDigest("initiating-browser")}
	if got, err := s.Login(ctx, in); !errors.Is(err, application.ErrUpdateOutcomeUnknown) || got.Token != "" {
		t.Fatal("unknown reply installed session")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = jsonstore.Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	s = newService(r)
	before, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Login(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.Login(ctx, in)
	if err != nil || same.Token != got.Token || same.Session.SessionID != got.Session.SessionID {
		t.Fatal("login replay generated another session")
	}
	after, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision() != after.Revision() || len(after.Snapshot().Sessions) != 1 || len(after.Snapshot().Idempotency) != 1 {
		t.Fatal("replay wrote authority")
	}
	changed := in
	changed.Password = "different"
	if _, err := s.Login(ctx, changed); !errors.Is(err, application.ErrCommandConflict) {
		t.Fatal("changed input overwrote command")
	}
	if err := s.Logout(ctx, got.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, in); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("saved login resurrected revoked auth")
	}
}
func TestPasswordAndProfileCommandReplay(t *testing.T) {
	_, r, c, m, _ := setup(t)
	secrets, err := sessionsecrets.New([]byte(strings.Repeat("s", 32)), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: m, Clock: c, IDs: m, Tokens: m, Results: secrets})
	if err != nil {
		t.Fatal(err)
	}
	one := login(t, s, "owner", false)
	u, err := s.UpdateDisplayNameCommand(ctx, one.Token, "Updated", "profile-once")
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.UpdateDisplayNameCommand(ctx, one.Token, "Updated", "profile-once")
	if err != nil || same != u {
		t.Fatal("profile replay differs")
	}
	if _, err := s.UpdateDisplayNameCommand(ctx, one.Token, "Changed", "profile-once"); !errors.Is(err, application.ErrCommandConflict) {
		t.Fatal("profile conflict admitted")
	}
	if err := s.ChangePasswordCommand(ctx, one.Token, "password", "newpassword", "password-once"); err != nil {
		t.Fatal(err)
	}
	newDevice := login(t, s, "owner", false)
	before, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checks := m.verifications
	if err := s.ChangePasswordCommand(ctx, newDevice.Token, "password", "newpassword", "password-once"); err != nil {
		t.Fatal(err)
	}
	after, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision() != after.Revision() || m.verifications != checks {
		t.Fatal("exact password retry changed authority or reverified")
	}
	if _, err := s.Peek(ctx, newDevice.Token); err != nil {
		t.Fatal("old password replay revoked new device")
	}
}
func TestPasswordReplayRequiresRecoverableAuthenticatedResult(t *testing.T) {
	_, r, c, m, _ := setup(t)
	key, err := sessionsecrets.New([]byte(strings.Repeat("s", 32)), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: m, Clock: c, IDs: m, Tokens: m, Results: key})
	if err != nil {
		t.Fatal(err)
	}
	one := login(t, s, "owner", false)
	if err := s.ChangePasswordCommand(ctx, one.Token, "password", "newpassword", "once"); err != nil {
		t.Fatal(err)
	}
	newDevice := login(t, s, "owner", false)
	wrongKey, err := sessionsecrets.New([]byte(strings.Repeat("x", 32)), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err = application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: m, Clock: c, IDs: m, Tokens: m, Results: wrongKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePasswordCommand(ctx, newDevice.Token, "password", "newpassword", "once"); err == nil {
		t.Fatal("unrecoverable encrypted password result accepted")
	}
}

type unreadableResults struct{ application.ResultSecrets }

func (unreadableResults) Open(string) ([]byte, error) {
	return nil, errors.New("synthetic recovery failure")
}
func TestPasswordReplayDoesNotInferSuccessFromMetadata(t *testing.T) {
	_, r, c, m, _ := setup(t)
	key, err := sessionsecrets.New([]byte(strings.Repeat("s", 32)), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: m, Clock: c, IDs: m, Tokens: m, Results: key})
	if err != nil {
		t.Fatal(err)
	}
	one := login(t, s, "owner", false)
	if err := s.ChangePasswordCommand(ctx, one.Token, "password", "newpassword", "once"); err != nil {
		t.Fatal(err)
	}
	newDevice := login(t, s, "owner", false)
	s, err = application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: m, Clock: c, IDs: m, Tokens: m, Results: unreadableResults{key}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePasswordCommand(ctx, newDevice.Token, "password", "newpassword", "once"); err == nil {
		t.Fatal("unreadable result metadata became success")
	}
}
func TestLoginReplayDoesNotFingerprintFreshCookie(t *testing.T) {
	_, r, c, m, _ := setup(t)
	key, err := sessionsecrets.New([]byte(strings.Repeat("s", 32)), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: m, Clock: c, IDs: m, Tokens: m, Results: key})
	if err != nil {
		t.Fatal(err)
	}
	in := application.LoginInput{Login: "owner", Password: "password", CommandID: "same-input", PreauthDigest: application.TokenDigest("browser")}
	v, err := s.Login(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	in.PreviousToken = v.Token
	again, err := s.Login(ctx, in)
	if err != nil || again.Token != v.Token {
		t.Fatal("fresh cookie changed canonical login fingerprint")
	}
}
