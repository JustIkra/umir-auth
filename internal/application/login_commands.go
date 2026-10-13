package application

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/domain"
)

var ErrCommandConflict = errors.New("auth command conflict")

type ResultSecrets interface {
	Digest([]byte) (string, error)
	Seal([]byte) (string, error)
	Open(string) ([]byte, error)
}

func (s *Accounts) loginCommand(a domain.Aggregate, in LoginInput) (string, *SessionView, error) {
	if in.CommandID == "" {
		return "", nil, nil
	}
	if s.opts.Results == nil {
		return "", nil, ErrAuthUnavailable
	}
	if !utf8.ValidString(in.CommandID) || strings.HasPrefix(in.CommandID, "expiration/") || len(in.CommandID) > 1<<20 {
		return "", nil, &FieldError{Field: "commandID", Code: "InvalidFormat"}
	}
	if len(in.PreauthDigest) != 64 || strings.ContainsFunc(in.PreauthDigest, func(r rune) bool { return r < '0' || r > '9' && r < 'a' || r > 'f' }) {
		return "", nil, ErrInvalidCSRFToken
	}
	sensitive, err := s.opts.Results.Digest([]byte(in.Password))
	if err != nil {
		return "", nil, ErrAuthUnavailable
	}
	tuple := struct {
		Version, Operation, Preauth, Login, PasswordDigest string
		RememberMe                                         bool
	}{"1", "login", in.PreauthDigest, in.Login, sensitive, in.RememberMe}
	b, err := json.Marshal(tuple)
	if err != nil {
		return "", nil, ErrAuthUnavailable
	}
	fp := TokenDigest(string(b))
	for _, r := range a.Idempotency {
		if r.PreauthDigest != in.PreauthDigest || r.OperationID != "login" || r.CommandID != in.CommandID {
			continue
		}
		if r.Fingerprint != fp {
			return "", nil, ErrCommandConflict
		}
		if r.HTTPStatus != 200 || r.ResponseSchema != "SessionIssued" {
			return "", nil, ErrAuthUnavailable
		}
		plain, err := s.opts.Results.Open(r.EncryptedResponse)
		if err != nil {
			return "", nil, ErrAuthUnavailable
		}
		var v SessionView
		if err := json.Unmarshal(plain, &v); err != nil {
			return "", nil, ErrAuthUnavailable
		}
		u, i, err := active(a, v.Token, s.opts.Clock.Now())
		if err != nil {
			return "", nil, err
		}
		if u.UserID != v.User.UserID || a.Sessions[i].SessionID != v.Session.SessionID || v.Session.Digest != TokenDigest(v.Token) || v.CSRFToken != sessionCSRF(v.Token) {
			return "", nil, ErrAuthUnavailable
		}
		return fp, &v, nil
	}
	return fp, nil, nil
}
func (s *Accounts) saveLoginCommand(a *domain.Aggregate, in LoginInput, fp string, v SessionView) error {
	if in.CommandID == "" {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ErrAuthUnavailable
	}
	sealed, err := s.opts.Results.Seal(b)
	if err != nil {
		return ErrAuthUnavailable
	}
	a.Idempotency = append(a.Idempotency, domain.IdempotencyRecord{PreauthDigest: in.PreauthDigest, OperationID: "login", CommandID: in.CommandID, Fingerprint: fp, AggregateRevision: v.AggregateRevision, HTTPStatus: 200, ResponseSchema: "SessionIssued", EncryptedResponse: sealed, JobIDs: []domain.EntityID{}})
	return nil
}
