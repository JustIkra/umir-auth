package application

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func CanonicalDisplayName(raw string) (string, error) {
	fail := func(code string) (string, error) { return "", &FieldError{Field: "displayName", Code: code} }
	if !utf8.ValidString(raw) {
		return fail("InvalidCharacters")
	}
	name := norm.NFC.String(strings.TrimFunc(raw, unicode.IsSpace))
	if strings.ContainsFunc(name, unicode.IsControl) {
		return fail("InvalidCharacters")
	}
	n := utf8.RuneCountInString(name)
	switch {
	case n == 0:
		return fail("Required")
	case n < 2:
		return fail("TooShort")
	case n > 80:
		return fail("TooLong")
	}
	return name, nil
}
func (s *Accounts) UpdateDisplayName(ctx context.Context, token, raw string) (UserView, error) {
	return s.UpdateDisplayNameCommand(ctx, token, raw, "")
}
func (s *Accounts) UpdateDisplayNameCommand(ctx context.Context, token, raw, commandID string) (UserView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.load(ctx)
	if err != nil {
		return UserView{}, err
	}
	u, _, err := active(a, token, s.opts.Clock.Now())
	if err != nil {
		return UserView{}, err
	}
	name, err := CanonicalDisplayName(raw)
	if err != nil {
		return UserView{}, err
	}
	fp, record, err := s.userCommand(a, u.UserID, "displayName", commandID, []byte(name))
	if err != nil {
		return UserView{}, err
	}
	if record != nil {
		var old UserView
		if err := s.openUserResult(*record, &old); err != nil {
			return UserView{}, err
		}
		if old.UserID != u.UserID {
			return UserView{}, ErrAuthUnavailable
		}
		return old, nil
	}
	for i := range a.Users {
		if a.Users[i].UserID == u.UserID {
			a.Users[i].DisplayName = name
		}
	}
	u.DisplayName = name
	result := userView(u)
	revision, err := nextVersion(a.AggregateRevision)
	if err != nil {
		return UserView{}, err
	}
	if err := s.saveUserResult(&a, u.UserID, "displayName", commandID, fp, revision, 200, "User", result); err != nil {
		return UserView{}, err
	}
	if err := s.commit(ctx, a); err != nil {
		return UserView{}, err
	}
	return result, nil
}
func userView(u domain.User) UserView {
	return UserView{UserID: u.UserID, Login: u.Login, DisplayName: u.DisplayName, CredentialVersion: u.CredentialVersion, Email: u.Email}
}
