package application

import (
	"context"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func (s *Accounts) registrationAccess(_ domain.Aggregate, who enrollmentActor) error {
	if !s.opts.Registration.Enabled || who.user.UserID != "" {
		return ErrForbidden
	}
	return nil
}
func (s *Accounts) completeRegistration(ctx context.Context, actor ChallengeActor, in EmailCompleteInput) (SessionView, error) {
	if !s.opts.Registration.Enabled {
		return SessionView{}, ErrForbidden
	}
	if in.NewPassword != "" {
		return SessionView{}, &FieldError{Field: "newPassword", Code: "InvalidFormat"}
	}
	name, err := CanonicalDisplayName(in.DisplayName)
	if err != nil {
		return SessionView{}, err
	}
	if err := CheckPassword(in.Password); err != nil {
		return SessionView{}, err
	}
	in.DisplayName = name
	return enrollmentCommand(s, ctx, actor, "completeEmailChallenge", "", in.CommandID, in, "SessionIssued", 200,
		func(a domain.Aggregate, who enrollmentActor) error {
			if err := s.registrationAccess(a, who); err != nil {
				return err
			}
			return s.challengeAccess(a, who, in.ChallengeID)
		},
		func(a *domain.Aggregate, _ enrollmentActor) (enrollmentChange[SessionView], error) {
			i, err := challengeIndex(*a, in.ChallengeID)
			if err != nil {
				return enrollmentChange[SessionView]{}, err
			}
			c := a.Challenges[i]
			if c.Purpose != "registration" || c.RegistrationSuppressed {
				return enrollmentChange[SessionView]{}, ErrChallengeUnavailable
			}
			if err := s.checkProof(*a, c, in.Proof); err != nil {
				return enrollmentChange[SessionView]{}, err
			}
			for _, u := range a.Users {
				if domain.ComparisonEmail(u.Email) == c.RegistrationEmail || u.Login == c.RegistrationEmail {
					return enrollmentChange[SessionView]{}, ErrCommandConflict
				}
			}
			hash, err := s.opts.Passwords.Hash(in.Password)
			if err != nil {
				return enrollmentChange[SessionView]{}, ErrAuthUnavailable
			}
			id, err := s.newEnrollmentID()
			if err != nil {
				return enrollmentChange[SessionView]{}, err
			}
			login := c.RegistrationEmail
			if len([]rune(login)) > 128 {
				login = string(id)
			}
			u := domain.User{UserID: id, Login: login, Email: c.RegistrationEmail, DisplayName: name, CredentialVersion: "1", Verifier: hash}
			a.Users = append(a.Users, u)
			a.Challenges[i].State = "completed"
			issued, err := s.issueEnrollmentSession(a, u, in.RememberMe)
			return enrollmentChange[SessionView]{value: issued}, err
		})
}
