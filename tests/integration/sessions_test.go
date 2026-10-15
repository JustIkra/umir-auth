package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/adapters/password"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

var ctx = context.Background()

func uid(n int) domain.EntityID {
	return domain.EntityID(fmt.Sprintf("%08x-1111-4111-8111-111111111111", n))
}
func instant(t time.Time) domain.Instant { return domain.Instant(t.Format(time.RFC3339Nano)) }
func fixture(t *testing.T) domain.Aggregate {
	t.Helper()
	b, err := os.ReadFile("../testdata/aggregate.json")
	if err != nil {
		t.Fatal(err)
	}
	var a domain.Aggregate
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	a.Sessions = []domain.Session{}
	a.Invitations = []domain.Invitation{}
	a.Challenges = []domain.Challenge{}
	a.MailJobs = []domain.MailJob{}
	a.Idempotency = []domain.IdempotencyRecord{}
	a.LifecycleIntents = []domain.LifecycleIntent{}
	return a
}
func validate(t *testing.T, a domain.Aggregate) domain.ValidatedAggregate {
	t.Helper()
	v, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.at = c.at.Add(d) }

type mechanisms struct {
	mu                    sync.Mutex
	n                     int
	hashes, verifications int
	hook                  func()
	wrong                 bool
}

func (m *mechanisms) NewID() (domain.EntityID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	return uid(100 + m.n), nil
}
func (m *mechanisms) NewToken() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	return fmt.Sprintf("test-only-token-%d", m.n), nil
}
func (m *mechanisms) Hash(p string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hashes++
	return verifier, nil
}
func (m *mechanisms) Check(string) error { return nil }
func (m *mechanisms) Verify(p, e string) (bool, error) {
	m.mu.Lock()
	m.verifications++
	hook, wrong := m.hook, m.wrong
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
	return p == "password" && !wrong, nil
}

const verifier = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU"

func service(t *testing.T, r application.AggregateRepository, c *clock, m *mechanisms) *application.Accounts {
	t.Helper()
	s, err := application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: m, Clock: c, IDs: m, Tokens: m})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func setup(t *testing.T) (*application.Accounts, *jsonstore.Store, *clock, *mechanisms, string) {
	t.Helper()
	a := fixture(t)
	a.Users = append(a.Users, domain.User{UserID: uid(50), Login: "second", DisplayName: "Second", CredentialVersion: "1", Verifier: verifier})
	p := filepath.Join(t.TempDir(), "auth.json")
	r, err := jsonstore.Initialize(ctx, p, validate(t, a))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	c := &clock{at: time.Date(2026, 10, 13, 1, 0, 0, 0, time.FixedZone("Europe/Moscow", 3*3600))}
	m := &mechanisms{}
	return service(t, r, c, m), r, c, m, p
}
func login(t *testing.T, s *application.Accounts, name string, remember bool) application.SessionView {
	t.Helper()
	v, err := s.Login(ctx, application.LoginInput{Login: name, Password: "password", RememberMe: remember})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestMultipleUsersSessionsAndRestartLogout(t *testing.T) {
	s, r, c, m, p := setup(t)
	one := login(t, s, "owner", false)
	two := login(t, s, "owner", false)
	other := login(t, s, "second", false)
	if one.User.UserID != two.User.UserID || one.Session.SessionID == two.Session.SessionID || one.User.UserID == other.User.UserID {
		t.Fatal("global device/user identity lost")
	}
	if err := s.Logout(ctx, one.Token); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := jsonstore.Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	}()
	s = service(t, reopened, c, m)
	if _, err := s.Peek(ctx, one.Token); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("logout resurrected")
	}
	if err := s.Logout(ctx, one.Token); err != nil {
		t.Fatal(err)
	}
	for _, v := range []application.SessionView{two, other} {
		if _, err := s.Peek(ctx, v.Token); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.LogoutAll(ctx, two.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Peek(ctx, two.Token); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("logout all missed calling user")
	}
	if _, err := s.Peek(ctx, other.Token); err != nil {
		t.Fatal("logout all revoked another user")
	}
}
func TestFixedDeadlinesActivityAndExpiry(t *testing.T) {
	for _, remember := range []bool{false, true} {
		t.Run(fmt.Sprint(remember), func(t *testing.T) {
			s, _, c, _, _ := setup(t)
			v := login(t, s, "owner", remember)
			created := c.Now()
			want := created.Add(8 * time.Hour)
			idle := created.Add(30 * time.Minute)
			if remember {
				want = created.Add(30 * 24 * time.Hour)
				idle = want
			}
			if v.Session.AbsoluteExpiresAt != instant(want) || v.Session.IdleExpiresAt != instant(idle) {
				t.Fatal("deadline changed")
			}
			c.advance(10 * time.Minute)
			peek, err := s.Peek(ctx, v.Token)
			if err != nil || peek.Session.IdleExpiresAt != v.Session.IdleExpiresAt {
				t.Fatal("background extends")
			}
			renew, err := s.Authenticate(ctx, v.Token)
			if err != nil {
				t.Fatal(err)
			}
			if renew.Session.AbsoluteExpiresAt != v.Session.AbsoluteExpiresAt {
				t.Fatal("absolute extended")
			}
			if remember && renew.Session.IdleExpiresAt != v.Session.IdleExpiresAt {
				t.Fatal("remember extended")
			}
			if !remember && renew.Session.IdleExpiresAt != instant(created.Add(40*time.Minute)) {
				t.Fatal("idle extension missing")
			}
			if remember {
				c.advance(30*24*time.Hour - 10*time.Minute)
			} else {
				c.advance(30 * time.Minute)
			}
			if _, err := s.Peek(ctx, v.Token); !errors.Is(err, application.ErrUnauthenticated) {
				t.Fatal("expiry boundary authorized")
			}
		})
	}
}
func TestPasswordBoundsRevocationAndRateLimit(t *testing.T) {
	s, r, _, m, _ := setup(t)
	one := login(t, s, "owner", false)
	two := login(t, s, "owner", false)
	other := login(t, s, "second", false)
	before := m.verifications
	for range 7 {
		err := s.ChangePassword(ctx, one.Token, strings.Repeat("x", 33), "nextpass")
		var field *application.FieldError
		if !errors.As(err, &field) || field.Field != "currentPassword" || field.Code != "TooLong" {
			t.Fatalf("oversize outcome: %v", err)
		}
	}
	if m.verifications != before {
		t.Fatal("oversize verified or counted")
	}
	if err := s.ChangePassword(ctx, one.Token, "password", "newpassword"); err != nil {
		t.Fatal(err)
	}
	for _, v := range []application.SessionView{one, two} {
		if _, err := s.Peek(ctx, v.Token); !errors.Is(err, application.ErrUnauthenticated) {
			t.Fatal("password did not revoke")
		}
	}
	if _, err := s.Peek(ctx, other.Token); err != nil {
		t.Fatal(err)
	}
	a, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a.Snapshot().Users[0].CredentialVersion != "2" {
		t.Fatal("credential version unchanged")
	}
	s, _, _, m, _ = setup(t)
	one = login(t, s, "owner", false)
	two = login(t, s, "owner", false)
	m.wrong = true
	for i := 0; i < 5; i++ {
		err := s.ChangePassword(ctx, one.Token, "wrong", "newpassword")
		if i < 4 && !errors.Is(err, application.ErrCurrentPasswordIncorrect) {
			t.Fatal(err)
		}
		if i == 4 {
			var limit *application.PasswordChangeLimitError
			if !errors.As(err, &limit) || !limit.SessionRevoked || limit.RetryAfter != time.Minute {
				t.Fatal("fifth failure must revoke calling session")
			}
		}
	}
	before = m.verifications
	err = s.ChangePassword(ctx, two.Token, "password", "newpassword")
	var limit *application.PasswordChangeLimitError
	if !errors.As(err, &limit) || limit.SessionRevoked || m.verifications != before {
		t.Fatal("cooldown checked too late or revoked other device")
	}
}

type faultRepo struct {
	application.AggregateRepository
	mode    application.CommitOutcome
	persist bool
}

func (r *faultRepo) Commit(c context.Context, v domain.Version, n domain.ValidatedAggregate) (application.CommitResult, error) {
	if r.mode == "" {
		return r.AggregateRepository.Commit(c, v, n)
	}
	if r.persist {
		if _, err := r.AggregateRepository.Commit(c, v, n); err != nil {
			return application.CommitResult{}, err
		}
	}
	return application.CommitResult{Outcome: r.mode}, application.ErrStorageUnavailable
}
func TestUnknownNeverAuthorizesAndLostLogoutRecovers(t *testing.T) {
	s, r, c, m, p := setup(t)
	v := login(t, s, "owner", false)
	f := &faultRepo{AggregateRepository: r, mode: application.Unknown, persist: true}
	s = service(t, f, c, m)
	if err := s.Logout(ctx, v.Token); !errors.Is(err, application.ErrUpdateOutcomeUnknown) {
		t.Fatal("lost logout classified definite")
	}
	if _, err := s.Peek(ctx, v.Token); !errors.Is(err, application.ErrAuthUnavailable) {
		t.Fatal("unknown became auth")
	}
	if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "password"}); !errors.Is(err, application.ErrAuthUnavailable) {
		t.Fatal("recovery new login")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := jsonstore.Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	}()
	s = service(t, reopened, c, m)
	if _, err := s.Peek(ctx, v.Token); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("lost logout restarted as auth")
	}
}
func TestDefiniteExtensionFailureAndCurrentFallback(t *testing.T) {
	s, r, c, m, _ := setup(t)
	v := login(t, s, "owner", false)
	f := &faultRepo{AggregateRepository: r, mode: application.NotCommitted}
	s = service(t, f, c, m)
	c.advance(time.Minute)
	if _, err := s.Authenticate(ctx, v.Token); !errors.Is(err, application.ErrStorageUnavailable) {
		t.Fatal("dispatch with failed extension")
	}
	got, err := s.Current(ctx, v.Token)
	if err != nil || got.Session.IdleExpiresAt != v.Session.IdleExpiresAt {
		t.Fatal("me fallback changed persisted deadline")
	}
	if _, err := s.Peek(ctx, v.Token); err != nil {
		t.Fatal("definite failure killed auth")
	}
}
func TestStaleCredentialAndCapacity(t *testing.T) {
	s, r, c, m, _ := setup(t)
	first := login(t, s, "owner", false)
	last := first
	for range 32 {
		c.advance(time.Second)
		last = login(t, s, "owner", false)
	}
	if _, err := s.Peek(ctx, last.Token); err != nil {
		t.Fatal("stale credential test must start with a live token")
	}
	if _, err := s.Peek(ctx, first.Token); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("oldest not evicted")
	}
	a, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next := a.Snapshot()
	revision, ok := domain.VersionNumber(a.Revision())
	if !ok {
		t.Fatal("invalid captured revision")
	}
	next.AggregateRevision = domain.Version(strconv.FormatInt(revision+1, 10))
	next.Users[0].CredentialVersion = "2"
	if _, err := r.Commit(ctx, a.Revision(), validate(t, next)); err != nil {
		t.Fatal(err)
	}
	s = service(t, r, c, m)
	if _, err := s.Peek(ctx, last.Token); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("stale credential accepted")
	}
}
func TestActualArgonSessionAndPasswordRestart(t *testing.T) {
	h, err := password.New(password.Baseline, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := fixture(t)
	hash, err := h.Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	a.Users[0].Verifier = hash
	p := filepath.Join(t.TempDir(), "auth.json")
	r, err := jsonstore.Initialize(ctx, p, validate(t, a))
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{at: time.Date(2026, 10, 13, 1, 0, 0, 0, time.FixedZone("Europe/Moscow", 3*3600))}
	m := &mechanisms{}
	s, err := application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: h, Clock: c, IDs: m, Tokens: m})
	if err != nil {
		t.Fatal(err)
	}
	v := login(t, s, "owner", false)
	if err := s.ChangePassword(ctx, v.Token, "password", "newpassword"); err != nil {
		t.Fatal(err)
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
	s, err = application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: h, Clock: c, IDs: m, Tokens: m})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "password"}); !errors.Is(err, application.ErrInvalidCredentials) {
		t.Fatal("old password restored")
	}
	if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "newpassword"}); err != nil {
		t.Fatal(err)
	}
}

func TestCSRFAndConcurrentSessionCommits(t *testing.T) {
	s, r, _, _, _ := setup(t)
	one := login(t, s, "owner", false)
	before, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(ctx, one.Token, "wrong-csrf", true); !errors.Is(err, application.ErrInvalidCSRFToken) {
		t.Fatal("csrf mismatch admitted")
	}
	after, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision() != after.Revision() {
		t.Fatal("bad csrf wrote authority")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	loginSlots := make(chan struct{}, 6)
	for range 12 {
		wg.Go(func() {
			loginSlots <- struct{}{}
			defer func() { <-loginSlots }()
			_, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "password"})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	a, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Snapshot().Sessions) != 13 {
		t.Fatal("concurrent sessions lost")
	}
}
func TestOversizedUnicodeAndNewPasswordValidation(t *testing.T) {
	for _, tc := range []struct{ value, code string }{{"", "Required"}, {"1234567", "TooShort"}, {strings.Repeat("я", 33), "TooLong"}, {string([]byte{0xff}), "InvalidCharacters"}} {
		var e *application.FieldError
		if err := application.CheckPassword(tc.value); !errors.As(err, &e) || e.Code != tc.code {
			t.Fatal("password outcome changed")
		}
	}
	for _, p := range []string{" password ", strings.Repeat("я", 32), "е\u0301234567"} {
		if err := application.CheckPassword(p); err != nil {
			t.Fatal("accepted unicode password rejected")
		}
	}
}
func TestDisplayNameCompatibilityAndDurableCommand(t *testing.T) {
	s, r, _, _, _ := setup(t)
	v := login(t, s, "owner", false)
	before, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var field *application.FieldError
	if _, err := s.UpdateDisplayName(ctx, v.Token, "\x00bad"); !errors.As(err, &field) || field.Code != "InvalidCharacters" {
		t.Fatal("invalid display name accepted")
	}
	after, err := r.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision() != before.Revision() {
		t.Fatal("rejected profile persisted")
	}
	u, err := s.UpdateDisplayName(ctx, v.Token, "  Cafe\u0301  ")
	if err != nil || u.DisplayName != "Café" {
		t.Fatal("canonical public profile changed")
	}
	a, err := r.Load(ctx)
	if err != nil || a.Snapshot().Users[0].DisplayName != "Café" {
		t.Fatal("profile not durable")
	}
}
func TestLoginCooldownIsIsolatedByLogin(t *testing.T) {
	s, _, c, m, _ := setup(t)
	for range 5 {
		if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "wrong"}); !errors.Is(err, application.ErrInvalidCredentials) {
			t.Fatal(err)
		}
	}
	before := m.verifications
	if _, err := s.Login(ctx, application.LoginInput{Login: "second", Password: "password"}); err != nil || m.verifications != before+1 {
		t.Fatal("another login inherited the first login's cooldown", err)
	}
	if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "password"}); !errors.Is(err, application.ErrLoginRateLimited) || m.verifications != before+1 {
		t.Fatal("another login reset the first login's cooldown", err)
	}
	c.advance(time.Minute)
	if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "password"}); err != nil {
		t.Fatal("expired login cooldown did not recover", err)
	}
}
