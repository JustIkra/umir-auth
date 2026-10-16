package application

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/JustIkra/umir-auth/internal/domain"
)

type ChallengeSecrets interface {
	NewCode() (string, error)
	NewProof() (string, error)
	Digest(string, string) string
	Seal(string, string) (string, error)
	Open(string, string) (string, error)
}
type ChallengeActor struct {
	Token, CSRFToken, PreauthDigest string
}
type enrollmentActor struct {
	user               domain.User
	preauth, initiator string
}

func (s *Accounts) enrollmentActor(a domain.Aggregate, in ChallengeActor) (enrollmentActor, error) {
	if in.Token != "" {
		u, err := s.membershipActor(a, in.Token, in.CSRFToken)
		return enrollmentActor{user: u, initiator: TokenDigest(in.Token)}, err
	}
	if len(in.PreauthDigest) != 64 || strings.ContainsFunc(in.PreauthDigest, func(r rune) bool { return r < '0' || r > '9' && r < 'a' || r > 'f' }) {
		return enrollmentActor{}, ErrInvalidCSRFToken
	}
	return enrollmentActor{preauth: in.PreauthDigest, initiator: in.PreauthDigest}, nil
}

type enrollmentChange[T any] struct {
	value         T
	jobs          []domain.EntityID
	retainedError error
}

func enrollmentCommand[T any](s *Accounts, ctx context.Context, actor ChallengeActor, operation string, org domain.EntityID, command string, input any, schema string, status int, access func(domain.Aggregate, enrollmentActor) error, change func(*domain.Aggregate, enrollmentActor) (enrollmentChange[T], error)) (T, error) {
	var zero T
	if !domain.ValidClientCommandID(command) {
		return zero, &FieldError{Field: "commandID", Code: "InvalidFormat"}
	}
	if s.opts.Results == nil {
		return zero, ErrAuthUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		a, err := s.load(ctx)
		if err != nil {
			return zero, err
		}
		who, err := s.enrollmentActor(a, actor)
		if err != nil {
			return zero, err
		}
		accessErr := access(a, who)
		if accessErr != nil && !errors.Is(accessErr, ErrChallengeUnavailable) {
			return zero, accessErr
		}
		profile := "C2"
		if operation == "createInvitation" || operation == "resendInvitationLink" {
			profile = "UA1"
		}
		for _, r := range a.Idempotency {
			if r.ActorID == who.user.UserID && r.PreauthDigest == who.preauth && r.OperationID == operation && r.OrgID == org && r.RestaurantID == "" && r.CommandID == command {
				profile = r.ContractProfile
				break
			}
		}
		fp, err := s.enrollmentFingerprint(who, operation, org, input, profile)
		if err != nil {
			return zero, err
		}
		for _, r := range a.Idempotency {
			if r.ActorID != who.user.UserID || r.PreauthDigest != who.preauth || r.OperationID != operation || r.OrgID != org || r.RestaurantID != "" || r.CommandID != command {
				continue
			}
			if r.Fingerprint != fp {
				return zero, ErrCommandConflict
			}
			if domain.IsCommandTombstone(r) {
				return zero, ErrCommandResultCleared
			}
			plain, err := s.opts.Results.Open(r.EncryptedResponse)
			if err != nil {
				return zero, ErrAuthUnavailable
			}
			defer clear(plain)
			if r.ResponseSchema == "Error" {
				var rejected enrollmentErrorResult
				if json.Unmarshal(plain, &rejected) != nil {
					return zero, ErrAuthUnavailable
				}
				return zero, challengeError(rejected.Code)
			}
			if r.ResponseSchema != schema || r.HTTPStatus != status || json.Unmarshal(plain, &zero) != nil {
				return zero, ErrAuthUnavailable
			}
			if schema == "SessionIssued" {
				var issued SessionView
				if json.Unmarshal(plain, &issued) != nil {
					return zero, ErrAuthUnavailable
				}
				u, i, err := active(a, issued.Token, s.opts.Clock.Now())
				if err != nil {
					return zero, err
				}
				if u.UserID != issued.User.UserID || a.Sessions[i].SessionID != issued.Session.SessionID || issued.Session.Digest != TokenDigest(issued.Token) || issued.CSRFToken != sessionCSRF(issued.Token) {
					return zero, ErrAuthUnavailable
				}
			}
			return zero, nil
		}
		if accessErr != nil {
			// The challenge may be gone (purged) while the key has no record.
			return zero, accessErr
		}
		changed, err := change(&a, who)
		if err != nil {
			return zero, err
		}
		plain, err := json.Marshal(changed.value)
		storedSchema, storedStatus := schema, status
		if changed.retainedError != nil {
			storedSchema, storedStatus = "Error", 400
			plain, err = json.Marshal(enrollmentErrorResult{Code: challengeErrorCode(changed.retainedError), Outcome: Committed, Message: "Challenge verification rejected", Retryable: false})
		}
		if err != nil {
			return zero, ErrAuthUnavailable
		}
		sealed, err := s.opts.Results.Seal(plain)
		clear(plain)
		if err != nil {
			return zero, ErrAuthUnavailable
		}
		rev, err := nextVersion(a.AggregateRevision)
		if err != nil {
			return zero, err
		}
		if changed.jobs == nil {
			changed.jobs = []domain.EntityID{}
		}
		a.Idempotency = append(a.Idempotency, domain.IdempotencyRecord{ContractProfile: profile, ActorID: who.user.UserID, PreauthDigest: who.preauth, OperationID: operation, OrgID: org, CommandID: command, Fingerprint: fp, AggregateRevision: rev, HTTPStatus: storedStatus, ResponseSchema: storedSchema, EncryptedResponse: sealed, JobIDs: changed.jobs, RecordedAt: formatInstant(s.opts.Clock.Now())})
		if err := s.commit(ctx, a); err != nil {
			if errors.Is(err, ErrRevisionConflict) && !s.recovering {
				continue
			}
			return zero, err
		}
		if changed.retainedError != nil {
			return zero, changed.retainedError
		}
		return changed.value, nil
	}
}

// enrollmentPasswordHash hashes a password for an enrollment command outside the
// Accounts mutex and behind the bounded password gate. Under the mutex it only
// looks: an exact repeat of the command (same operation, key and caller) is
// answered from its stored result and needs no hash, and precheck refuses what
// the command would refuse anyway, so a hopeless request costs no hashing. The
// command re-checks everything at commit time and must not be given a hash for a
// state that has since changed; a hash that is not used leaves no trace.
func (s *Accounts) enrollmentPasswordHash(ctx context.Context, actor ChallengeActor, operation, command, password string, precheck func(domain.Aggregate, enrollmentActor) error) (string, error) {
	if !domain.ValidClientCommandID(command) {
		return "", &FieldError{Field: "commandID", Code: "InvalidFormat"}
	}
	if s.opts.Results == nil {
		return "", ErrAuthUnavailable
	}
	s.mu.Lock()
	a, err := s.load(ctx)
	if err != nil {
		s.mu.Unlock()
		return "", err
	}
	who, err := s.enrollmentActor(a, actor)
	if err != nil {
		s.mu.Unlock()
		return "", err
	}
	for _, r := range a.Idempotency {
		if r.OperationID == operation && r.CommandID == command && r.PreauthDigest == who.preauth && r.ActorID == who.user.UserID {
			s.mu.Unlock()
			return "", nil
		}
	}
	err = precheck(a, who)
	s.mu.Unlock()
	if err != nil {
		return "", err
	}
	release, err := s.gate.acquire(ctx, true)
	if err != nil {
		return "", err
	}
	defer release()
	hash, err := s.opts.Passwords.Hash(password)
	if err != nil {
		return "", ErrAuthUnavailable
	}
	return hash, nil
}

// enrollmentFingerprint is the fingerprint of one enrollment command: the same
// subject, operation, scope and input digest always give the same value.
func (s *Accounts) enrollmentFingerprint(who enrollmentActor, operation string, org domain.EntityID, input any, profile string) (string, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", ErrAuthUnavailable
	}
	digest, err := s.opts.Results.Digest(encoded)
	clear(encoded)
	if err != nil {
		return "", ErrAuthUnavailable
	}
	initiator := who.initiator
	if operation == "createInvitation" || operation == "cancelInvitation" || operation == "resendInvitation" || operation == "resendInvitationLink" {
		initiator = ""
	}
	version := "1"
	if profile == "UA1" {
		version = "UA1"
	}
	tuple, err := json.Marshal(struct{ Version, Operation, Actor, Initiator, Org, Input string }{version, operation, string(who.user.UserID), initiator, string(org), digest})
	if err != nil {
		return "", ErrAuthUnavailable
	}
	return TokenDigest(string(tuple)), nil
}

type enrollmentErrorResult struct {
	Code      string        `json:"code"`
	Outcome   CommitOutcome `json:"outcome"`
	Message   string        `json:"message"`
	Retryable bool          `json:"retryable"`
}

func publicScope(a domain.Aggregate, org domain.EntityID) error {
	for _, o := range a.Organizations {
		if o.OrgID == org && o.Lifecycle == "active" {
			return nil
		}
	}
	return ErrForbidden
}
func (s *Accounts) newEnrollmentID() (domain.EntityID, error) {
	id, err := s.opts.IDs.NewID()
	if err != nil {
		return "", ErrAuthUnavailable
	}
	return id, nil
}
