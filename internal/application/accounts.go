package application

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/domain"
)

type Clock interface{ Now() time.Time }
type IDGenerator interface {
	NewID() (domain.EntityID, error)
}
type TokenSource interface{ NewToken() (string, error) }
type PasswordHasher interface {
	Hash(string) (string, error)
	Verify(string, string) (bool, error)
	Check(string) error
}
type RegistrationOptions struct {
	Enabled                      bool `json:"enabled"`
	MailLimitPer10Minutes        int  `json:"mailLimitPer10Minutes"`
	OrganizationsPerUser         int  `json:"organizationsPerUser"`
	OrganizationCreationsPerHour int  `json:"organizationCreationsPerHour"`
	WrongCodesPerAddressPerHour  int  `json:"wrongCodesPerAddressPerHour"`
}

type AccountOptions struct {
	EmailLoginEnabled bool
	Registration      RegistrationOptions
	LinkURLs          InvitationURLPolicy
	InvitationMail    InvitationMailOptions
	Repository        AggregateRepository
	Passwords         PasswordHasher
	Clock             Clock
	PageClock         Clock
	PageAfter         func(time.Duration, func()) PageExpiryTimer
	IDs               IDGenerator
	Tokens            TokenSource
	Results           ResultSecrets
	Challenges        ChallengeSecrets
	Issuer            UserTokenIssuer
	TimeZones         TimeZoneCatalog
	Runtimes          RuntimePeers
}
type Accounts struct {
	opts              AccountOptions
	mu                sync.Mutex
	reconciling       chan struct{}
	recovering        bool
	gate              *verificationGate
	changing          chan struct{}
	loginFailures     loginThrottles
	passwordFailures  map[domain.EntityID]*failureThrottle
	organizationPages organizationPages
	statusFlights     statusFlights
}

var (
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrUnauthenticated          = errors.New("unauthenticated")
	ErrAuthUnavailable          = errors.New("authentication unavailable")
	ErrUpdateOutcomeUnknown     = errors.New("auth update outcome unknown")
	ErrCurrentPasswordIncorrect = errors.New("current password incorrect")
	ErrInvalidCSRFToken         = errors.New("invalid csrf token")
)

type LoginInput struct {
	Login, Password, PreviousToken, CommandID, PreauthDigest string
	RememberMe                                               bool
}
type UserView struct {
	CredentialVersion domain.Version  `json:"credentialVersion"`
	Email             string          `json:"email,omitempty"`
	UserID            domain.EntityID `json:"userID"`
	Login             string          `json:"login"`
	DisplayName       string          `json:"displayName"`
}
type SessionView struct {
	User              UserView
	Session           domain.Session
	Token, CSRFToken  string
	AggregateRevision domain.Version
}

func NewAccounts(ctx context.Context, o AccountOptions) (*Accounts, error) {
	if o.Repository == nil || o.Passwords == nil || o.Clock == nil || o.IDs == nil || o.Tokens == nil {
		return nil, ErrAuthUnavailable
	}
	if err := registrationDefaults(&o.Registration); err != nil {
		return nil, err
	}
	a, err := o.Repository.Load(ctx)
	if err != nil {
		return nil, errors.Join(ErrAuthUnavailable, err)
	}
	if _, err := domain.Validate(a.Snapshot()); err != nil {
		return nil, errors.Join(ErrAuthUnavailable, err)
	}
	if o.Issuer != nil && o.TimeZones == nil {
		return nil, ErrTimeZoneDataUnavailable
	}
	if o.TimeZones != nil {
		if _, err := o.TimeZones.Ready(); err != nil {
			return nil, errors.Join(ErrTimeZoneDataUnavailable, err)
		}
		for _, org := range a.Snapshot().Organizations {
			if err := o.TimeZones.Validate(org.Settings.TimeZone); err != nil {
				return nil, err
			}
		}
	}
	for _, u := range a.Snapshot().Users {
		if err := o.Passwords.Check(u.Verifier); err != nil {
			return nil, ErrAuthUnavailable
		}
	}
	if o.Challenges != nil {
		if err := validateEnrollmentSecrets(a.Snapshot(), o.Challenges, o.LinkURLs); err != nil {
			return nil, ErrAuthUnavailable
		}
	}
	if a.Snapshot().SchemaVersion < 3 {
		upgraded, err := domain.UpgradeRegistration(a.Snapshot())
		if err != nil {
			return nil, errors.Join(ErrAuthUnavailable, err)
		}
		upgraded.AggregateRevision, err = nextVersion(a.Revision())
		if err != nil {
			return nil, err
		}
		next, err := domain.Validate(upgraded)
		if err != nil {
			return nil, errors.Join(ErrAuthUnavailable, err)
		}
		result, err := o.Repository.Commit(ctx, a.Revision(), next)
		if result.Outcome != Committed || err != nil || result.AggregateRevision != next.Revision() {
			if result.Outcome == NotCommitted && !errors.Is(err, ErrRecoveryRequired) {
				return nil, errors.Join(ErrStorageUnavailable, err)
			}
			return nil, errors.Join(ErrUpdateOutcomeUnknown, err)
		}
	}
	s := &Accounts{opts: o, gate: newVerificationGate(2, 8), changing: make(chan struct{}, 1), reconciling: make(chan struct{}, 1), passwordFailures: map[domain.EntityID]*failureThrottle{}}
	if s.opts.PageClock == nil {
		s.opts.PageClock = o.Clock
	}
	s.organizationPages = organizationPages{captures: map[*organizationCapture]bool{}, cursors: map[string]organizationCursor{}, orgBytes: map[domain.EntityID]int{}, orgCounts: map[domain.EntityID]int{}}
	if o.Challenges != nil {
		if err := s.RecoverMail(ctx); err != nil {
			return nil, err
		}
	}
	return s, nil
}
func (s *Accounts) load(ctx context.Context) (domain.Aggregate, error) {
	if s.recovering {
		return domain.Aggregate{}, ErrAuthUnavailable
	}
	a, err := s.opts.Repository.Load(ctx)
	if err != nil {
		if errors.Is(err, ErrRecoveryRequired) {
			s.recovering = true
		}
		return domain.Aggregate{}, errors.Join(ErrAuthUnavailable, err)
	}
	return a.Snapshot(), nil
}

// inspect runs fn over the stored aggregate without cloning it; see
// domain.ValidatedAggregate.Inspect for what fn may do. The caller holds s.mu.
func (s *Accounts) inspect(ctx context.Context, fn func(*domain.Aggregate)) error {
	if s.recovering {
		return ErrAuthUnavailable
	}
	a, err := s.opts.Repository.Load(ctx)
	if err != nil {
		if errors.Is(err, ErrRecoveryRequired) {
			s.recovering = true
		}
		return errors.Join(ErrAuthUnavailable, err)
	}
	a.Inspect(fn)
	return nil
}
func (s *Accounts) commit(ctx context.Context, a domain.Aggregate) error {
	old := a.AggregateRevision
	next, err := nextVersion(old)
	if err != nil {
		return err
	}
	a.AggregateRevision = next
	v, err := domain.Validate(a)
	if err != nil {
		return errors.Join(ErrStorageUnavailable, err)
	}
	r, err := s.opts.Repository.Commit(ctx, old, v)
	if r.Outcome == Committed && err == nil && r.AggregateRevision == next {
		return nil
	}
	if r.Outcome == NotCommitted && !errors.Is(err, ErrRecoveryRequired) {
		return errors.Join(ErrStorageUnavailable, err)
	}
	s.recovering = true
	return errors.Join(ErrUpdateOutcomeUnknown, err)
}
func (s *Accounts) Login(ctx context.Context, in LoginInput) (SessionView, error) {
	s.mu.Lock()
	a, err := s.load(ctx)
	if err != nil {
		s.mu.Unlock()
		return SessionView{}, err
	}
	_, replay, err := s.loginCommand(a, in)
	if err != nil {
		s.mu.Unlock()
		return SessionView{}, err
	}
	if replay != nil {
		s.mu.Unlock()
		return *replay, nil
	}
	if !utf8.ValidString(in.Password) || utf8.RuneCountInString(in.Password) > 32 {
		// No password this long or malformed is ever stored, so the attempt costs no
		// hashing: it creates and moves no throttle entry.
		s.mu.Unlock()
		return SessionView{}, ErrInvalidCredentials
	}
	var user domain.User
	known := false
	for _, u := range a.Users {
		if loginMatches(u.Login, in.Login) {
			user = u
			known = true
			break
		}
	}
	if !known && len(a.Users) > 0 {
		user = a.Users[0]
	}
	if user.UserID == "" {
		s.mu.Unlock()
		return SessionView{}, ErrInvalidCredentials
	}
	budgetLogin := normalizedEmailLogin(in.Login)
	th, err := s.loginFailures.acquire(budgetLogin, s.opts.Clock.Now())
	if err != nil {
		s.mu.Unlock()
		return SessionView{}, err
	}
	defer func() {
		s.mu.Lock()
		s.loginFailures.release(th)
		s.mu.Unlock()
	}()
	if wait := th.wait(s.opts.Clock.Now()); wait > 0 {
		s.mu.Unlock()
		return SessionView{}, rateLimited(wait)
	}
	s.mu.Unlock()
	release, err := s.gate.acquire(ctx, true)
	if err != nil {
		return SessionView{}, err
	}
	defer release()
	s.mu.Lock()
	if s.recovering {
		s.mu.Unlock()
		return SessionView{}, ErrAuthUnavailable
	}
	if wait := th.wait(s.opts.Clock.Now()); wait > 0 {
		s.mu.Unlock()
		return SessionView{}, rateLimited(wait)
	}
	s.mu.Unlock()
	ok, err := s.opts.Passwords.Verify(in.Password, user.Verifier)
	if err != nil {
		return SessionView{}, ErrAuthUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err = s.load(ctx)
	if err != nil {
		return SessionView{}, err
	}
	fp, replay, err := s.loginCommand(a, in)
	if err != nil {
		return SessionView{}, err
	}
	if replay != nil {
		return *replay, nil
	}
	if wait := th.wait(s.opts.Clock.Now()); wait > 0 {
		return SessionView{}, rateLimited(wait)
	}
	if !ok || !known {
		th.fail(s.opts.Clock.Now(), 5, time.Minute, time.Minute)
		return SessionView{}, ErrInvalidCredentials
	}
	current, exists := findUser(a, user.UserID)
	if !exists || current.CredentialVersion != user.CredentialVersion || current.Verifier != user.Verifier {
		return SessionView{}, ErrInvalidCredentials
	}
	token, err := s.opts.Tokens.NewToken()
	if err != nil || token == "" {
		return SessionView{}, ErrAuthUnavailable
	}
	digest := TokenDigest(token)
	for _, st := range a.Sessions {
		if st.Digest == digest {
			return SessionView{}, ErrAuthUnavailable
		}
	}
	id, err := s.opts.IDs.NewID()
	if err != nil {
		return SessionView{}, ErrAuthUnavailable
	}
	now := s.opts.Clock.Now()
	absolute, idle := now.Add(8*time.Hour), now.Add(30*time.Minute)
	if in.RememberMe {
		absolute = now.Add(30 * 24 * time.Hour)
		idle = absolute
	}
	for i := range a.Sessions {
		st := &a.Sessions[i]
		if st.UserID == user.UserID && (st.Digest == TokenDigest(in.PreviousToken) && in.PreviousToken != "" || !sessionLive(*st, current, now)) {
			st.Revoked = true
		}
	}
	evictSessions(&a, user.UserID, 31)
	st := domain.Session{SessionID: id, UserID: user.UserID, SessionVersion: "1", CredentialVersion: user.CredentialVersion, Digest: digest, CSRFTokenDigest: TokenDigest(sessionCSRF(token)), CreatedAt: formatInstant(now), IdleExpiresAt: formatInstant(idle), AbsoluteExpiresAt: formatInstant(absolute), RememberMe: in.RememberMe}
	a.Sessions = append(a.Sessions, st)
	revision, err := nextVersion(a.AggregateRevision)
	if err != nil {
		return SessionView{}, err
	}
	result := view(current, st, token, revision)
	if err := s.saveLoginCommand(&a, in, fp, result); err != nil {
		return SessionView{}, err
	}
	if err := s.commit(ctx, a); err != nil {
		return SessionView{}, err
	}
	th.failures = th.failures[:0]
	return result, nil
}
func (s *Accounts) throttle(m map[domain.EntityID]*failureThrottle, id domain.EntityID) *failureThrottle {
	t, ok := m[id]
	if !ok {
		t = &failureThrottle{}
		m[id] = t
	}
	return t
}
func findUser(a domain.Aggregate, id domain.EntityID) (domain.User, bool) {
	for _, u := range a.Users {
		if u.UserID == id {
			return u, true
		}
	}
	return domain.User{}, false
}
func formatInstant(t time.Time) domain.Instant { return domain.Instant(t.Format(time.RFC3339Nano)) }
func nextVersion(v domain.Version) (domain.Version, error) {
	n, ok := domain.VersionNumber(v)
	if !ok || n == 9223372036854775807 {
		return "", ErrStorageUnavailable
	}
	return domain.Version(fmt.Sprint(n + 1)), nil
}
