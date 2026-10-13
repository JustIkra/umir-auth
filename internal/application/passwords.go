package application

import (
	"context"
	"encoding/json"
	"time"
	"unicode/utf8"
)

type FieldError struct{ Field, Code string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Code }
func CheckPassword(p string) error {
	if !utf8.ValidString(p) {
		return &FieldError{Field: "newPassword", Code: "InvalidCharacters"}
	}
	n := utf8.RuneCountInString(p)
	code := ""
	switch {
	case n == 0:
		code = "Required"
	case n < 8:
		code = "TooShort"
	case n > 32:
		code = "TooLong"
	}
	if code != "" {
		return &FieldError{Field: "newPassword", Code: code}
	}
	return nil
}
func (s *Accounts) ChangePassword(ctx context.Context, token, current, next string) error {
	return s.ChangePasswordCommand(ctx, token, current, next, "")
}
func (s *Accounts) ChangePasswordCommand(ctx context.Context, token, current, next, commandID string) error {
	select {
	case s.changing <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.changing }()
	s.mu.Lock()
	a, err := s.load(ctx)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	u, _, err := active(a, token, s.opts.Clock.Now())
	if err != nil {
		s.mu.Unlock()
		return err
	}
	sensitive, err := json.Marshal(struct{ Current, Next string }{current, next})
	if err != nil {
		s.mu.Unlock()
		return ErrAuthUnavailable
	}
	fp, record, err := s.userCommand(a, u.UserID, "password", commandID, sensitive)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if record != nil {
		s.mu.Unlock()
		plain, err := s.opts.Results.Open(record.EncryptedResponse)
		if err != nil || record.HTTPStatus != 204 || record.ResponseSchema != "NoContent" || string(plain) != `{"type":"NoContent"}` {
			return ErrAuthUnavailable
		}
		return nil
	}
	th := s.throttle(s.passwordFailures, u.UserID)
	if wait := th.wait(s.opts.Clock.Now()); wait > 0 {
		s.mu.Unlock()
		return &PasswordChangeLimitError{RetryAfter: wholeSeconds(wait)}
	}
	s.mu.Unlock()
	if err := CheckPassword(next); err != nil {
		return err
	}
	if !utf8.ValidString(current) {
		return &FieldError{Field: "currentPassword", Code: "InvalidCharacters"}
	}
	if utf8.RuneCountInString(current) > 32 {
		return &FieldError{Field: "currentPassword", Code: "TooLong"}
	}
	release, err := s.gate.acquire(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	ok, err := s.opts.Passwords.Verify(current, u.Verifier)
	if err != nil {
		return ErrAuthUnavailable
	}
	var hash string
	if ok {
		hash, err = s.opts.Passwords.Hash(next)
		if err != nil {
			return ErrStorageUnavailable
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err = s.load(ctx)
	if err != nil {
		return err
	}
	fresh, i, err := active(a, token, s.opts.Clock.Now())
	if err != nil {
		return err
	}
	if fresh.CredentialVersion != u.CredentialVersion || fresh.Verifier != u.Verifier {
		return ErrUnauthenticated
	}
	if !ok {
		if !th.fail(s.opts.Clock.Now(), 5, time.Minute, time.Minute) {
			return ErrCurrentPasswordIncorrect
		}
		a.Sessions[i].Revoked = true
		v, err := nextVersion(a.Sessions[i].SessionVersion)
		if err != nil {
			return err
		}
		a.Sessions[i].SessionVersion = v
		if err := s.commit(ctx, a); err != nil {
			return err
		}
		return &PasswordChangeLimitError{RetryAfter: time.Minute, SessionRevoked: true}
	}
	for i := range a.Users {
		if a.Users[i].UserID == u.UserID {
			v, err := nextVersion(u.CredentialVersion)
			if err != nil {
				return err
			}
			a.Users[i].CredentialVersion = v
			a.Users[i].Verifier = hash
		}
	}
	if err := revokeUserSessions(&a, u.UserID); err != nil {
		return err
	}
	revision, err := nextVersion(a.AggregateRevision)
	if err != nil {
		return err
	}
	if err := s.saveUserResult(&a, u.UserID, "password", commandID, fp, revision, 204, "NoContent", UserView{}); err != nil {
		return err
	}
	if err := s.commit(ctx, a); err != nil {
		return err
	}
	th.failures = th.failures[:0]
	return nil
}
