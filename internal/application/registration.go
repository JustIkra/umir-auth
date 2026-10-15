package application

import (
	"context"
	"errors"

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
		var field *FieldError
		if errors.As(err, &field) {
			return SessionView{}, &FieldError{Field: "password", Code: field.Code}
		}
		return SessionView{}, err
	}
	in.DisplayName = name
	hash, err := s.registrationPassword(ctx, actor, in)
	if err != nil {
		return SessionView{}, err
	}
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
				if sameEmail(u.Email, c.RegistrationEmail) || sameEmail(u.Login, c.RegistrationEmail) {
					return enrollmentChange[SessionView]{}, ErrCommandConflict
				}
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

func (s *Accounts) registrationPassword(ctx context.Context, actor ChallengeActor, in EmailCompleteInput) (string, error) {
	if !domain.ValidClientCommandID(in.CommandID) {
		return "", &FieldError{Field: "commandID", Code: "InvalidFormat"}
	}
	replay, err := s.registrationPasswordAccess(ctx, actor, in)
	if err != nil || replay {
		return "", err
	}
	release, err := s.gate.acquire(ctx, true)
	if err != nil {
		return "", err
	}
	defer release()
	hash, err := s.opts.Passwords.Hash(in.Password)
	if err != nil {
		return "", ErrAuthUnavailable
	}
	return hash, nil
}
func (s *Accounts) registrationPasswordAccess(ctx context.Context, actor ChallengeActor, in EmailCompleteInput) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.load(ctx)
	if err != nil {
		return false, err
	}
	who, err := s.enrollmentActor(a, actor)
	if err != nil {
		return false, err
	}
	if err := s.registrationAccess(a, who); err != nil {
		return false, err
	}
	if err := s.challengeAccess(a, who, in.ChallengeID); err != nil {
		return false, err
	}
	for _, r := range a.Idempotency {
		if r.OperationID == "completeEmailChallenge" && r.CommandID == in.CommandID && r.PreauthDigest == who.preauth && r.ActorID == who.user.UserID {
			return true, nil
		}
	}
	i, err := challengeIndex(a, in.ChallengeID)
	if err != nil {
		return false, err
	}
	c := a.Challenges[i]
	if c.Purpose != "registration" || c.RegistrationSuppressed {
		return false, ErrChallengeUnavailable
	}
	return false, s.checkProof(a, c, in.Proof)
}
