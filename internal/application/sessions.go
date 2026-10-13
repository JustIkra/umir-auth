package application

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func sessionCSRF(token string) string {
	sum := sha256.Sum256([]byte("umir-operator-csrf\x00" + token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func sessionLive(st domain.Session, u domain.User, now time.Time) bool {
	idle, err := time.Parse(time.RFC3339Nano, string(st.IdleExpiresAt))
	if err != nil {
		return false
	}
	absolute, err := time.Parse(time.RFC3339Nano, string(st.AbsoluteExpiresAt))
	return err == nil && !st.Revoked && st.CredentialVersion == u.CredentialVersion && now.Before(idle) && now.Before(absolute)
}
func active(a domain.Aggregate, token string, now time.Time) (domain.User, int, error) {
	if token == "" {
		return domain.User{}, 0, ErrUnauthenticated
	}
	digest := TokenDigest(token)
	for i, st := range a.Sessions {
		if st.Digest == digest {
			u, ok := findUser(a, st.UserID)
			if ok && sessionLive(st, u, now) {
				return u, i, nil
			}
			break
		}
	}
	return domain.User{}, 0, ErrUnauthenticated
}
func view(u domain.User, st domain.Session, token string, rev domain.Version) SessionView {
	return SessionView{User: userView(u), Session: st, Token: token, CSRFToken: sessionCSRF(token), AggregateRevision: rev}
}
func (s *Accounts) Peek(ctx context.Context, token string) (SessionView, error) {
	return s.session(ctx, token, "", false, false, false)
}
func (s *Accounts) Authenticate(ctx context.Context, token string) (SessionView, error) {
	return s.session(ctx, token, "", false, true, false)
}
func (s *Accounts) Current(ctx context.Context, token string) (SessionView, error) {
	return s.session(ctx, token, "", false, true, true)
}
func (s *Accounts) Authorize(ctx context.Context, token, csrf string, foreground bool) (SessionView, error) {
	return s.session(ctx, token, csrf, true, foreground, false)
}
func (s *Accounts) session(ctx context.Context, token, csrf string, unsafe, foreground, fallback bool) (SessionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.load(ctx)
	if err != nil {
		return SessionView{}, err
	}
	now := s.opts.Clock.Now()
	u, i, err := active(a, token, now)
	if err != nil {
		return SessionView{}, err
	}
	st := a.Sessions[i]
	if unsafe && (csrf == "" || subtle.ConstantTimeCompare([]byte(sessionCSRF(token)), []byte(csrf)) != 1 || !st.LegacyCSRF && TokenDigest(csrf) != st.CSRFTokenDigest) {
		return SessionView{}, ErrInvalidCSRFToken
	}
	if !foreground || st.RememberMe {
		return view(u, st, token, a.AggregateRevision), nil
	}
	absolute, err := time.Parse(time.RFC3339Nano, string(st.AbsoluteExpiresAt))
	if err != nil {
		return SessionView{}, ErrAuthUnavailable
	}
	idle, err := time.Parse(time.RFC3339Nano, string(st.IdleExpiresAt))
	if err != nil {
		return SessionView{}, ErrAuthUnavailable
	}
	next := now.Add(30 * time.Minute)
	if next.After(absolute) {
		next = absolute
	}
	if !next.After(idle) {
		return view(u, st, token, a.AggregateRevision), nil
	}
	a.Sessions[i].IdleExpiresAt = formatInstant(next)
	version, err := nextVersion(st.SessionVersion)
	if err != nil {
		return SessionView{}, err
	}
	a.Sessions[i].SessionVersion = version
	if err := s.commit(ctx, a); err != nil {
		if fallback && errors.Is(err, ErrStorageUnavailable) && !s.recovering {
			return view(u, st, token, a.AggregateRevision), nil
		}
		return SessionView{}, err
	}
	rev, err := nextVersion(a.AggregateRevision)
	if err != nil {
		return SessionView{}, err
	}
	return view(u, a.Sessions[i], token, rev), nil
}
func (s *Accounts) SessionCSRF(ctx context.Context, token string) (string, error) {
	v, err := s.Peek(ctx, token)
	return v.CSRFToken, err
}
func (s *Accounts) Logout(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.load(ctx)
	if err != nil {
		if token == "" {
			return nil
		}
		return err
	}
	_, i, err := active(a, token, s.opts.Clock.Now())
	if errors.Is(err, ErrUnauthenticated) {
		return nil
	}
	if err != nil {
		return err
	}
	a.Sessions[i].Revoked = true
	v, err := nextVersion(a.Sessions[i].SessionVersion)
	if err != nil {
		return err
	}
	a.Sessions[i].SessionVersion = v
	return s.commit(ctx, a)
}
func (s *Accounts) LogoutAll(ctx context.Context, token string) error {
	_, e := s.LogoutAllCommand(ctx, token, "")
	return e
}
func revokeUserSessions(a *domain.Aggregate, id domain.EntityID) error {
	for i := range a.Sessions {
		st := &a.Sessions[i]
		if st.UserID == id && !st.Revoked {
			v, err := nextVersion(st.SessionVersion)
			if err != nil {
				return err
			}
			st.Revoked = true
			st.SessionVersion = v
		}
	}
	return nil
}
func evictSessions(a *domain.Aggregate, id domain.EntityID, keep int) {
	for {
		count, oldest := 0, -1
		for i, st := range a.Sessions {
			if st.UserID == id && !st.Revoked {
				count++
				if oldest < 0 || sessionOlder(st, a.Sessions[oldest]) {
					oldest = i
				}
			}
		}
		if count <= keep {
			return
		}
		a.Sessions[oldest].Revoked = true
	}
}

func sessionOlder(a, b domain.Session) bool {
	left, err := time.Parse(time.RFC3339Nano, string(a.CreatedAt))
	if err != nil {
		return false
	}
	right, err := time.Parse(time.RFC3339Nano, string(b.CreatedAt))
	if err != nil {
		return false
	}
	return left.Before(right) || left.Equal(right) && a.SessionID < b.SessionID
}
