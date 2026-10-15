package application

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/JustIkra/umir-auth/internal/domain"
)

var (
	ErrChallengeUnavailable = errors.New("challenge unavailable")
	ErrChallengeInvalidCode = errors.New("challenge code invalid")
	ErrChallengeLocked      = errors.New("challenge locked")
	ErrChallengeRateLimited = errors.New("challenge rate limited")
	ErrChallengeCapacity    = errors.New("challenge capacity exceeded")
)

func challengeError(code string) error {
	switch code {
	case "InvalidArgument":
		return ErrChallengeInvalidCode
	case "ChallengeLocked":
		return ErrChallengeLocked
	default:
		return ErrAuthUnavailable
	}
}
func challengeErrorCode(err error) string {
	if errors.Is(err, ErrChallengeLocked) {
		return "ChallengeLocked"
	}
	return "InvalidArgument"
}

type ChallengeView struct {
	ChallengeID       domain.EntityID `json:"challengeID"`
	ExpiresAt         domain.Instant  `json:"expiresAt"`
	ResendAvailableAt domain.Instant  `json:"resendAvailableAt"`
	State             string          `json:"state"`
}
type VerifiedChallenge struct {
	Challenge   ChallengeView  `json:"challenge"`
	Proof       string         `json:"proof"`
	RetainUntil domain.Instant `json:"retainUntil"`
}
type ChallengeBeginInput struct {
	CommandID    string          `json:"commandID"`
	InvitationID domain.EntityID `json:"invitationID"`
}
type ChallengeVerifyInput struct {
	CommandID   string          `json:"commandID"`
	ChallengeID domain.EntityID `json:"challengeID"`
	Code        string          `json:"code"`
}
type InvitationCompleteInput struct {
	CommandID   string          `json:"commandID"`
	ChallengeID domain.EntityID `json:"challengeID"`
	Proof       string          `json:"proof"`
	Password    string          `json:"password"`
	DisplayName string          `json:"displayName"`
}
type InvitationAcceptInput struct {
	CommandID   string          `json:"commandID"`
	ChallengeID domain.EntityID `json:"challengeID"`
	Proof       string          `json:"proof"`
}
type EmailChallengeInput struct {
	CommandID string `json:"commandID"`
	Email     string `json:"email"`
	Purpose   string `json:"purpose"`
}
type EmailCompleteInput struct {
	DisplayName string          `json:"displayName,omitempty"`
	Password    string          `json:"password,omitempty"`
	CommandID   string          `json:"commandID"`
	ChallengeID domain.EntityID `json:"challengeID"`
	Proof       string          `json:"proof"`
	Purpose     string          `json:"purpose"`
	RememberMe  bool            `json:"rememberMe,omitempty"`
	NewPassword string          `json:"newPassword,omitempty"`
}

func challengeView(c domain.Challenge) ChallengeView {
	return ChallengeView{c.ChallengeID, c.ExpiresAt, c.ResendAvailableAt, c.State}
}
func challengeIndex(a domain.Aggregate, id domain.EntityID) (int, error) {
	for i, c := range a.Challenges {
		if c.ChallengeID == id {
			return i, nil
		}
	}
	return 0, ErrChallengeUnavailable
}
func (s *Accounts) challengeAccess(a domain.Aggregate, who enrollmentActor, id domain.EntityID) error {
	i, err := challengeIndex(a, id)
	if err != nil {
		return err
	}
	c := a.Challenges[i]
	if c.Purpose == "registration" {
		if err := s.registrationAccess(a, who); err != nil {
			return err
		}
	}
	if c.InitiatorDigest != who.initiator {
		return ErrChallengeUnavailable
	}
	if c.InvitationID != "" {
		i, err := invitationIndex(a, c.InvitationID)
		if err != nil {
			return err
		}
		if err := invitationScope(a, a.Invitations[i]); err != nil {
			return err
		}
		if a.Invitations[i].State == "revoked" || a.Invitations[i].State == "suppressed" {
			return ErrInvitationUnavailable
		}
	}
	return nil
}
func validCode(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func codeScope(id domain.EntityID, purpose string) string {
	return "code:" + string(id) + ":" + purpose
}
func proofScope(id domain.EntityID, purpose string) string {
	return "proof:" + string(id) + ":" + purpose
}
func (s *Accounts) issueLimit(a domain.Aggregate, email string, now time.Time) error {
	var global, target []time.Time
	for _, j := range a.MailJobs {
		at, err := time.Parse(time.RFC3339Nano, string(j.AcceptedAt))
		if err != nil {
			return ErrAuthUnavailable
		}
		if now.Sub(at) >= 10*time.Minute {
			continue
		}
		global = append(global, at)
		other := ""
		if j.Purpose == "invitation_link" {
			ii, err := invitationIndex(a, j.InvitationID)
			if err != nil {
				return ErrAuthUnavailable
			}
			other = a.Invitations[ii].ComparisonEmail
		} else {
			ci, err := challengeIndex(a, j.ChallengeID)
			if err != nil {
				return ErrAuthUnavailable
			}
			c := a.Challenges[ci]
			if c.InvitationID != "" {
				ii, err := invitationIndex(a, c.InvitationID)
				if err != nil {
					return ErrAuthUnavailable
				}
				other = a.Invitations[ii].ComparisonEmail
			} else if c.Purpose == "registration" {
				other = domain.ComparisonEmail(c.RegistrationEmail)
			} else {
				u, ok := findUser(a, c.UserID)
				if !ok {
					return ErrAuthUnavailable
				}
				other = domain.ComparisonEmail(u.Email)
			}
		}
		if other == email {
			target = append(target, at)
		}
	}
	if delay := max(rollingIssueDelay(global, 60, 10*time.Minute, now), rollingIssueDelay(target, 3, 10*time.Minute, now)); delay > 0 {
		return &InvitationRateLimitError{RetryAfter: delay}
	}
	return nil
}

func rollingIssueDelay(times []time.Time, limit int, window time.Duration, now time.Time) time.Duration {
	if len(times) < limit {
		return 0
	}
	slices.SortFunc(times, func(a, b time.Time) int { return a.Compare(b) })
	return times[len(times)-limit].Add(window).Sub(now)
}
func (s *Accounts) newChallenge(a *domain.Aggregate, who enrollmentActor, purpose, email string, invite domain.EntityID, user domain.User) (enrollmentChange[ChallengeView], error) {
	if s.opts.Challenges == nil {
		return enrollmentChange[ChallengeView]{}, ErrAuthUnavailable
	}
	if len(a.Challenges) >= 4096 {
		return enrollmentChange[ChallengeView]{}, ErrChallengeCapacity
	}
	now := s.opts.Clock.Now()
	if err := s.issueLimit(*a, domain.ComparisonEmail(email), now); err != nil {
		return enrollmentChange[ChallengeView]{}, err
	}
	id, err := s.newEnrollmentID()
	if err != nil {
		return enrollmentChange[ChallengeView]{}, err
	}
	code, err := s.opts.Challenges.NewCode()
	if err != nil || !validCode(code) {
		return enrollmentChange[ChallengeView]{}, ErrAuthUnavailable
	}
	sealed, err := s.opts.Challenges.Seal(codeScope(id, purpose), code)
	if err != nil {
		return enrollmentChange[ChallengeView]{}, ErrAuthUnavailable
	}
	c := domain.Challenge{ChallengeID: id, Purpose: purpose, InvitationID: invite, UserID: user.UserID, CredentialVersion: user.CredentialVersion, InitiatorDigest: who.initiator, CodeDigest: s.opts.Challenges.Digest(codeScope(id, purpose), code), EncryptedCode: sealed, ExpiresAt: formatInstant(now.Add(10 * time.Minute)), ResendAvailableAt: formatInstant(now.Add(time.Minute)), State: "pending", IssueCount: 1}
	if purpose == "registration" {
		c.RegistrationEmail = domain.ComparisonEmail(email)
		c.RegistrationSuppressed = user.UserID != ""
		c.UserID = ""
		c.CredentialVersion = ""
	}
	a.Challenges = append(a.Challenges, c)
	job, err := s.enqueueChallenge(a, c, email, code)
	if err != nil {
		return enrollmentChange[ChallengeView]{}, err
	}
	return enrollmentChange[ChallengeView]{value: challengeView(c), jobs: []domain.EntityID{job}}, nil
}
func (s *Accounts) BeginInvitationChallenge(ctx context.Context, actor ChallengeActor, in ChallengeBeginInput) (ChallengeView, error) {
	return enrollmentCommand(s, ctx, actor, "beginInvitationChallenge", "", in.CommandID, in, "Challenge", 200,
		func(a domain.Aggregate, _ enrollmentActor) error {
			i, err := invitationIndex(a, in.InvitationID)
			if err != nil {
				return err
			}
			if a.Invitations[i].State == "revoked" || a.Invitations[i].State == "suppressed" {
				return ErrInvitationUnavailable
			}
			return invitationScope(a, a.Invitations[i])
		},
		func(a *domain.Aggregate, who enrollmentActor) (enrollmentChange[ChallengeView], error) {
			i, err := invitationIndex(*a, in.InvitationID)
			if err != nil {
				return enrollmentChange[ChallengeView]{}, err
			}
			invite := a.Invitations[i]
			if invite.State != "pending" || !before(s.opts.Clock.Now(), invite.ExpiresAt) {
				return enrollmentChange[ChallengeView]{}, ErrInvitationUnavailable
			}
			return s.newChallenge(a, who, "invitation", invite.Email, invite.InvitationID, domain.User{})
		})
}
func (s *Accounts) BeginEmailChallenge(ctx context.Context, actor ChallengeActor, in EmailChallengeInput) (ChallengeView, error) {
	if in.Purpose == "registration" && !s.opts.Registration.Enabled {
		return ChallengeView{}, ErrForbidden
	}
	_, comparison, err := CanonicalEmail(in.Email)
	if err != nil {
		return ChallengeView{}, err
	}
	in.Email = comparison
	if in.Purpose != "login" && in.Purpose != "password_reset" && in.Purpose != "registration" {
		return ChallengeView{}, &FieldError{Field: "purpose", Code: "InvalidFormat"}
	}
	return enrollmentCommand(s, ctx, actor, "beginEmailChallenge", "", in.CommandID, in, "Challenge", 200, func(a domain.Aggregate, who enrollmentActor) error {
		if in.Purpose == "registration" {
			return s.registrationAccess(a, who)
		}
		return nil
	},
		func(a *domain.Aggregate, who enrollmentActor) (enrollmentChange[ChallengeView], error) {
			for _, u := range a.Users {
				if u.Email != "" && domain.ComparisonEmail(u.Email) == comparison {
					return s.newChallenge(a, who, in.Purpose, u.Email, "", u)
				}
			}
			if in.Purpose == "registration" {
				return s.newChallenge(a, who, in.Purpose, in.Email, "", domain.User{})
			}
			return enrollmentChange[ChallengeView]{}, ErrChallengeUnavailable
		})
}
func (s *Accounts) ResendChallenge(ctx context.Context, actor ChallengeActor, id domain.EntityID, command string) (ChallengeView, error) {
	return enrollmentCommand(s, ctx, actor, "resendChallenge", "", command, id, "Challenge", 200,
		func(a domain.Aggregate, who enrollmentActor) error { return s.challengeAccess(a, who, id) },
		func(a *domain.Aggregate, _ enrollmentActor) (enrollmentChange[ChallengeView], error) {
			i, err := challengeIndex(*a, id)
			if err != nil {
				return enrollmentChange[ChallengeView]{}, err
			}
			c := &a.Challenges[i]
			now := s.opts.Clock.Now()
			if c.State != "pending" || !before(now, c.ExpiresAt) {
				return enrollmentChange[ChallengeView]{}, ErrChallengeUnavailable
			}
			if c.IssueCount >= 4 || before(now, c.ResendAvailableAt) {
				return enrollmentChange[ChallengeView]{}, ErrChallengeRateLimited
			}
			if c.InvitationID != "" {
				ii, err := invitationIndex(*a, c.InvitationID)
				if err != nil {
					return enrollmentChange[ChallengeView]{}, err
				}
				if before(now, a.Invitations[ii].ResendAvailableAt) {
					at, err := time.Parse(time.RFC3339Nano, string(a.Invitations[ii].ResendAvailableAt))
					if err != nil {
						return enrollmentChange[ChallengeView]{}, ErrAuthUnavailable
					}
					return enrollmentChange[ChallengeView]{}, &InvitationRateLimitError{RetryAfter: at.Sub(now)}
				}
			}
			email, err := challengeEmail(*a, *c, now)
			if err != nil {
				return enrollmentChange[ChallengeView]{}, err
			}
			if err := s.issueLimit(*a, domain.ComparisonEmail(email), now); err != nil {
				return enrollmentChange[ChallengeView]{}, err
			}
			if s.opts.Challenges == nil {
				return enrollmentChange[ChallengeView]{}, ErrAuthUnavailable
			}
			code, err := s.opts.Challenges.Open(codeScope(id, c.Purpose), c.EncryptedCode)
			if err != nil || !validCode(code) {
				return enrollmentChange[ChallengeView]{}, ErrAuthUnavailable
			}
			c.IssueCount++
			next := now.Add(time.Minute)
			expires, err := time.Parse(time.RFC3339Nano, string(c.ExpiresAt))
			if err != nil {
				return enrollmentChange[ChallengeView]{}, ErrAuthUnavailable
			}
			if next.After(expires) {
				next = expires
			}
			c.ResendAvailableAt = formatInstant(next)
			if c.InvitationID != "" {
				ii, err := invitationIndex(*a, c.InvitationID)
				if err != nil {
					return enrollmentChange[ChallengeView]{}, err
				}
				invite := &a.Invitations[ii]
				invite.ResendAvailableAt = formatInstant(now.Add(time.Minute))
				if !before(now.Add(time.Minute), invite.ExpiresAt) {
					invite.ResendAvailableAt = invite.ExpiresAt
				}
				invite.Version, err = nextVersion(invite.Version)
				if err != nil {
					return enrollmentChange[ChallengeView]{}, err
				}
			}
			v := *c
			job, err := s.enqueueChallenge(a, v, email, code)
			if err != nil {
				return enrollmentChange[ChallengeView]{}, err
			}
			return enrollmentChange[ChallengeView]{value: challengeView(v), jobs: []domain.EntityID{job}}, nil
		})
}
func (s *Accounts) VerifyChallenge(ctx context.Context, actor ChallengeActor, in ChallengeVerifyInput) (VerifiedChallenge, error) {
	if !validCode(in.Code) {
		return VerifiedChallenge{}, &FieldError{Field: "code", Code: "InvalidFormat"}
	}
	return enrollmentCommand(s, ctx, actor, "verifyChallenge", "", in.CommandID, in, "VerifiedChallenge", 200,
		func(a domain.Aggregate, who enrollmentActor) error { return s.challengeAccess(a, who, in.ChallengeID) },
		func(a *domain.Aggregate, _ enrollmentActor) (enrollmentChange[VerifiedChallenge], error) {
			i, err := challengeIndex(*a, in.ChallengeID)
			if err != nil {
				return enrollmentChange[VerifiedChallenge]{}, err
			}
			c := &a.Challenges[i]
			now := s.opts.Clock.Now()
			if c.State == "locked" {
				return enrollmentChange[VerifiedChallenge]{}, ErrChallengeLocked
			}
			if c.State != "pending" || !before(now, c.ExpiresAt) {
				return enrollmentChange[VerifiedChallenge]{}, ErrChallengeUnavailable
			}
			if _, err := challengeEmail(*a, *c, now); err != nil {
				return enrollmentChange[VerifiedChallenge]{}, err
			}
			count := 0
			for _, r := range a.Idempotency {
				if r.OperationID == "verifyChallenge" && r.RecordedAt != "" {
					at, e := time.Parse(time.RFC3339Nano, string(r.RecordedAt))
					if e != nil {
						return enrollmentChange[VerifiedChallenge]{}, ErrAuthUnavailable
					}
					if now.Sub(at) < time.Minute {
						count++
					}
				}
			}
			if count >= 300 {
				return enrollmentChange[VerifiedChallenge]{}, ErrChallengeRateLimited
			}
			if s.opts.Challenges == nil {
				return enrollmentChange[VerifiedChallenge]{}, ErrAuthUnavailable
			}
			digest := s.opts.Challenges.Digest(codeScope(c.ChallengeID, c.Purpose), in.Code)
			if len(digest) != 64 || subtle.ConstantTimeCompare([]byte(digest), []byte(c.CodeDigest)) != 1 || c.RegistrationSuppressed {
				c.WrongAttempts++
				err := ErrChallengeInvalidCode
				if c.WrongAttempts == 5 {
					c.State = "locked"
					c.EncryptedCode = ""
					err = ErrChallengeLocked
					suppressChallengeJobs(a, c.ChallengeID)
				}
				return enrollmentChange[VerifiedChallenge]{retainedError: err}, nil
			}
			proof, err := s.opts.Challenges.NewProof()
			if err != nil || len(proof) < 32 || len(proof) > 128 {
				return enrollmentChange[VerifiedChallenge]{}, ErrAuthUnavailable
			}
			sealed, err := s.opts.Challenges.Seal(proofScope(c.ChallengeID, c.Purpose), proof)
			if err != nil {
				return enrollmentChange[VerifiedChallenge]{}, ErrAuthUnavailable
			}
			c.State = "verified"
			c.ProofDigest = s.opts.Challenges.Digest(proofScope(c.ChallengeID, c.Purpose), proof)
			c.EncryptedProof = sealed
			c.ProofExpiresAt = formatInstant(now.Add(24 * time.Hour))
			c.EncryptedCode = ""
			v := *c
			suppressChallengeJobs(a, c.ChallengeID)
			return enrollmentChange[VerifiedChallenge]{value: VerifiedChallenge{Challenge: challengeView(v), Proof: proof, RetainUntil: v.ProofExpiresAt}}, nil
		})
}
func challengeEmail(a domain.Aggregate, c domain.Challenge, now time.Time) (string, error) {
	if c.Purpose == "registration" {
		return c.RegistrationEmail, nil
	}
	if c.InvitationID != "" {
		i, err := invitationIndex(a, c.InvitationID)
		if err != nil {
			return "", err
		}
		v := a.Invitations[i]
		if v.State != "pending" || !before(now, v.ExpiresAt) {
			return "", ErrInvitationUnavailable
		}
		if err := invitationScope(a, v); err != nil {
			return "", err
		}
		return v.Email, nil
	}
	u, ok := findUser(a, c.UserID)
	if !ok || u.Email == "" || u.CredentialVersion != c.CredentialVersion {
		return "", ErrChallengeUnavailable
	}
	return u.Email, nil
}
func suppressChallengeJobs(a *domain.Aggregate, id domain.EntityID) {
	for i := range a.MailJobs {
		j := &a.MailJobs[i]
		if j.ChallengeID == id && (j.State == "queued" || j.State == "unknown") {
			j.State = "suppressed"
			j.EncryptedPayload = ""
			j.NextAttemptAt = ""
		}
	}
}
func (s *Accounts) checkProof(a domain.Aggregate, c domain.Challenge, proof string) error {
	if s.opts.Challenges == nil || c.State != "verified" || !before(s.opts.Clock.Now(), c.ProofExpiresAt) || len(proof) < 32 || len(proof) > 128 {
		return ErrChallengeUnavailable
	}
	if _, err := challengeEmail(a, c, s.opts.Clock.Now()); err != nil {
		return err
	}
	digest := s.opts.Challenges.Digest(proofScope(c.ChallengeID, c.Purpose), proof)
	if len(digest) != 64 || subtle.ConstantTimeCompare([]byte(digest), []byte(c.ProofDigest)) != 1 {
		return ErrChallengeUnavailable
	}
	return nil
}
func (s *Accounts) CompleteInvitedUser(ctx context.Context, actor ChallengeActor, in InvitationCompleteInput) (SessionView, error) {
	name, err := CanonicalDisplayName(in.DisplayName)
	if err != nil {
		return SessionView{}, err
	}
	if err := CheckPassword(in.Password); err != nil {
		return SessionView{}, err
	}
	in.DisplayName = name
	return enrollmentCommand(s, ctx, actor, "completeInvitedUser", "", in.CommandID, in, "SessionIssued", 200,
		func(a domain.Aggregate, who enrollmentActor) error { return s.challengeAccess(a, who, in.ChallengeID) },
		func(a *domain.Aggregate, who enrollmentActor) (enrollmentChange[SessionView], error) {
			if who.user.UserID != "" {
				return enrollmentChange[SessionView]{}, ErrForbidden
			}
			i, err := challengeIndex(*a, in.ChallengeID)
			if err != nil {
				return enrollmentChange[SessionView]{}, err
			}
			c := a.Challenges[i]
			if c.Purpose != "invitation" {
				return enrollmentChange[SessionView]{}, ErrChallengeUnavailable
			}
			if err := s.checkProof(*a, c, in.Proof); err != nil {
				return enrollmentChange[SessionView]{}, err
			}
			ii, err := invitationIndex(*a, c.InvitationID)
			if err != nil {
				return enrollmentChange[SessionView]{}, err
			}
			v := a.Invitations[ii]
			for _, u := range a.Users {
				if domain.ComparisonEmail(u.Email) == v.ComparisonEmail {
					return enrollmentChange[SessionView]{}, ErrInvitationConflict
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
			login := v.ComparisonEmail
			if len([]rune(login)) > 128 {
				login = string(id)
			}
			u := domain.User{UserID: id, Login: login, DisplayName: name, Email: v.Email, CredentialVersion: "1", Verifier: hash}
			a.Users = append(a.Users, u)
			if _, err := s.acceptMembership(a, u, v); err != nil {
				return enrollmentChange[SessionView]{}, err
			}
			a.Invitations[ii].State = "accepted"
			suppressInvitationJobs(a, v.InvitationID)
			a.Invitations[ii].Version, err = nextVersion(v.Version)
			if err != nil {
				return enrollmentChange[SessionView]{}, err
			}
			a.Challenges[i].State = "completed"
			issued, err := s.issueEnrollmentSession(a, u, false)
			return enrollmentChange[SessionView]{value: issued}, err
		})
}
func (s *Accounts) AcceptInvitation(ctx context.Context, actor ChallengeActor, invitationID domain.EntityID, in InvitationAcceptInput) (domain.Membership, error) {
	return enrollmentCommand(s, ctx, actor, "acceptInvitation", "", in.CommandID, struct {
		InvitationID domain.EntityID
		Input        InvitationAcceptInput
	}{invitationID, in}, "Membership", 200,
		func(a domain.Aggregate, who enrollmentActor) error {
			if who.user.UserID == "" {
				return ErrUnauthenticated
			}
			return s.challengeAccess(a, who, in.ChallengeID)
		},
		func(a *domain.Aggregate, who enrollmentActor) (enrollmentChange[domain.Membership], error) {
			i, err := challengeIndex(*a, in.ChallengeID)
			if err != nil {
				return enrollmentChange[domain.Membership]{}, err
			}
			c := a.Challenges[i]
			if c.InvitationID != invitationID || c.Purpose != "invitation" {
				return enrollmentChange[domain.Membership]{}, ErrChallengeUnavailable
			}
			if err := s.checkProof(*a, c, in.Proof); err != nil {
				return enrollmentChange[domain.Membership]{}, err
			}
			ii, err := invitationIndex(*a, invitationID)
			if err != nil {
				return enrollmentChange[domain.Membership]{}, err
			}
			v := a.Invitations[ii]
			if who.user.Email != "" && domain.ComparisonEmail(who.user.Email) != v.ComparisonEmail {
				return enrollmentChange[domain.Membership]{}, ErrForbidden
			}
			for _, u := range a.Users {
				if u.UserID != who.user.UserID && u.Email != "" && domain.ComparisonEmail(u.Email) == v.ComparisonEmail {
					return enrollmentChange[domain.Membership]{}, ErrInvitationConflict
				}
			}
			m, err := s.acceptMembership(a, who.user, v)
			if err != nil {
				return enrollmentChange[domain.Membership]{}, err
			}
			for j := range a.Users {
				if a.Users[j].UserID == who.user.UserID && a.Users[j].Email == "" {
					a.Users[j].Email = v.Email
				}
			}
			a.Invitations[ii].State = "accepted"
			suppressInvitationJobs(a, v.InvitationID)
			a.Invitations[ii].Version, err = nextVersion(v.Version)
			if err != nil {
				return enrollmentChange[domain.Membership]{}, err
			}
			a.Challenges[i].State = "completed"
			return enrollmentChange[domain.Membership]{value: m}, nil
		})
}
func (s *Accounts) acceptMembership(a *domain.Aggregate, u domain.User, v domain.Invitation) (domain.Membership, error) {
	for _, m := range a.Memberships {
		if m.UserID == u.UserID && m.OrgID == v.OrgID {
			return domain.Membership{}, ErrInvitationConflict
		}
	}
	id, err := s.newEnrollmentID()
	if err != nil {
		return domain.Membership{}, err
	}
	m := domain.Membership{MembershipID: id, MembershipVersion: "1", UserID: u.UserID, OrgID: v.OrgID, State: "active", OrgRoles: []string{}, Assignments: []domain.Assignment{}}
	for _, as := range v.Assignments {
		id, err := s.newEnrollmentID()
		if err != nil {
			return domain.Membership{}, err
		}
		m.Assignments = append(m.Assignments, domain.Assignment{RestaurantID: as.RestaurantID, AssignmentID: id, AssignmentVersion: "1", Roles: as.Roles})
	}
	a.Memberships = append(a.Memberships, m)
	return m, nil
}
func (s *Accounts) CompleteEmailChallenge(ctx context.Context, actor ChallengeActor, in EmailCompleteInput) (SessionView, error) {
	if in.Purpose == "registration" {
		return s.completeRegistration(ctx, actor, in)
	}
	if in.DisplayName != "" || in.Password != "" {
		return SessionView{}, &FieldError{Field: "purpose", Code: "InvalidFormat"}
	}
	if in.Purpose != "login" && in.Purpose != "password_reset" || in.Purpose == "login" && in.NewPassword != "" || in.Purpose == "password_reset" && (in.RememberMe || in.NewPassword == "") {
		return SessionView{}, &FieldError{Field: "purpose", Code: "InvalidFormat"}
	}
	if in.Purpose == "password_reset" {
		if err := CheckPassword(in.NewPassword); err != nil {
			return SessionView{}, err
		}
	}
	return enrollmentCommand(s, ctx, actor, "completeEmailChallenge", "", in.CommandID, in, "SessionIssued", 200,
		func(a domain.Aggregate, who enrollmentActor) error { return s.challengeAccess(a, who, in.ChallengeID) },
		func(a *domain.Aggregate, _ enrollmentActor) (enrollmentChange[SessionView], error) {
			i, err := challengeIndex(*a, in.ChallengeID)
			if err != nil {
				return enrollmentChange[SessionView]{}, err
			}
			c := a.Challenges[i]
			if c.Purpose != in.Purpose {
				return enrollmentChange[SessionView]{}, ErrChallengeUnavailable
			}
			if err := s.checkProof(*a, c, in.Proof); err != nil {
				return enrollmentChange[SessionView]{}, err
			}
			u, ok := findUser(*a, c.UserID)
			if !ok {
				return enrollmentChange[SessionView]{}, ErrChallengeUnavailable
			}
			if in.Purpose == "password_reset" {
				hash, err := s.opts.Passwords.Hash(in.NewPassword)
				if err != nil {
					return enrollmentChange[SessionView]{}, ErrAuthUnavailable
				}
				u.Verifier = hash
				u.CredentialVersion, err = nextVersion(u.CredentialVersion)
				if err != nil {
					return enrollmentChange[SessionView]{}, err
				}
				for j := range a.Users {
					if a.Users[j].UserID == u.UserID {
						a.Users[j] = u
					}
				}
				if err := revokeUserSessions(a, u.UserID); err != nil {
					return enrollmentChange[SessionView]{}, err
				}
			}
			a.Challenges[i].State = "completed"
			issued, err := s.issueEnrollmentSession(a, u, in.RememberMe)
			return enrollmentChange[SessionView]{value: issued}, err
		})
}
func (s *Accounts) issueEnrollmentSession(a *domain.Aggregate, u domain.User, remember bool) (SessionView, error) {
	token, err := s.opts.Tokens.NewToken()
	if err != nil || token == "" {
		return SessionView{}, ErrAuthUnavailable
	}
	for _, st := range a.Sessions {
		if st.Digest == TokenDigest(token) {
			return SessionView{}, ErrAuthUnavailable
		}
	}
	id, err := s.newEnrollmentID()
	if err != nil {
		return SessionView{}, err
	}
	now := s.opts.Clock.Now()
	absolute, idle := now.Add(8*time.Hour), now.Add(30*time.Minute)
	if remember {
		absolute = now.Add(30 * 24 * time.Hour)
		idle = absolute
	}
	evictSessions(a, u.UserID, 31)
	st := domain.Session{SessionID: id, UserID: u.UserID, SessionVersion: "1", CredentialVersion: u.CredentialVersion, Digest: TokenDigest(token), CSRFTokenDigest: TokenDigest(sessionCSRF(token)), CreatedAt: formatInstant(now), IdleExpiresAt: formatInstant(idle), AbsoluteExpiresAt: formatInstant(absolute), RememberMe: remember}
	a.Sessions = append(a.Sessions, st)
	rev, err := nextVersion(a.AggregateRevision)
	if err != nil {
		return SessionView{}, err
	}
	return view(u, st, token, rev), nil
}

func payloadScope(id domain.EntityID) string { return fmt.Sprint("mail:", id) }
