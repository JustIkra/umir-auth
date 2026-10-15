package application

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

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
	if command == "" || !utf8.ValidString(command) || strings.HasPrefix(command, "expiration/") || len(command) > 1<<20 {
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
		if err := access(a, who); err != nil {
			return zero, err
		}
		encoded, err := json.Marshal(input)
		if err != nil {
			return zero, ErrAuthUnavailable
		}
		digest, err := s.opts.Results.Digest(encoded)
		clear(encoded)
		if err != nil {
			return zero, ErrAuthUnavailable
		}
		initiator := who.initiator
		if operation == "createInvitation" || operation == "cancelInvitation" || operation == "resendInvitation" || operation == "resendInvitationLink" {
			initiator = ""
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
		version := "1"
		if profile == "UA1" {
			version = "UA1"
		}
		tuple, err := json.Marshal(struct{ Version, Operation, Actor, Initiator, Org, Input string }{version, operation, string(who.user.UserID), initiator, string(org), digest})
		if err != nil {
			return zero, ErrAuthUnavailable
		}
		fp := TokenDigest(string(tuple))
		for _, r := range a.Idempotency {
			if r.ActorID != who.user.UserID || r.PreauthDigest != who.preauth || r.OperationID != operation || r.OrgID != org || r.RestaurantID != "" || r.CommandID != command {
				continue
			}
			if r.Fingerprint != fp {
				return zero, ErrCommandConflict
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
