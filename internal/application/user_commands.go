package application

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func (s *Accounts) userCommand(a domain.Aggregate, actor domain.EntityID, operation, commandID string, input []byte) (string, *domain.IdempotencyRecord, error) {
	if commandID == "" {
		return "", nil, nil
	}
	if s.opts.Results == nil {
		return "", nil, ErrAuthUnavailable
	}
	if !utf8.ValidString(commandID) || strings.HasPrefix(commandID, "expiration/") || len(commandID) > 1<<20 {
		return "", nil, &FieldError{Field: "commandID", Code: "InvalidFormat"}
	}
	digest, err := s.opts.Results.Digest(input)
	if err != nil {
		return "", nil, ErrAuthUnavailable
	}
	tuple := struct {
		Version, Operation string
		Actor              domain.EntityID
		InputDigest        string
	}{"1", operation, actor, digest}
	b, err := json.Marshal(tuple)
	if err != nil {
		return "", nil, ErrAuthUnavailable
	}
	fp := TokenDigest(string(b))
	for _, r := range a.Idempotency {
		if r.ActorID == actor && r.OperationID == operation && r.CommandID == commandID && r.OrgID == "" && r.RestaurantID == "" {
			if r.Fingerprint != fp {
				return "", nil, ErrCommandConflict
			}
			return fp, &r, nil
		}
	}
	return fp, nil, nil
}
func (s *Accounts) openUserResult(r domain.IdempotencyRecord, target *UserView) error {
	plain, err := s.opts.Results.Open(r.EncryptedResponse)
	if err != nil || r.HTTPStatus != 200 || r.ResponseSchema != "User" {
		return ErrAuthUnavailable
	}
	if err := json.Unmarshal(plain, target); err != nil {
		return ErrAuthUnavailable
	}
	return nil
}
func (s *Accounts) saveUserResult(a *domain.Aggregate, actor domain.EntityID, operation, commandID, fp string, revision domain.Version, status int, schema string, result UserView) error {
	if commandID == "" {
		return nil
	}
	b, err := json.Marshal(result)
	if err != nil {
		return ErrAuthUnavailable
	}
	if schema == "NoContent" {
		b = []byte(`{"type":"NoContent"}`)
	}
	sealed, err := s.opts.Results.Seal(b)
	if err != nil {
		return ErrAuthUnavailable
	}
	a.Idempotency = append(a.Idempotency, domain.IdempotencyRecord{ContractProfile: "C2", ActorID: actor, OperationID: operation, CommandID: commandID, Fingerprint: fp, AggregateRevision: revision, HTTPStatus: status, ResponseSchema: schema, EncryptedResponse: sealed, JobIDs: []domain.EntityID{}})
	return nil
}
