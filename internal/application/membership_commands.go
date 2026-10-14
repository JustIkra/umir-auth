package application

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func (s *Accounts) membershipCommand(a domain.Aggregate, actor domain.EntityID, operation string, orgID, membershipID, assignmentID domain.EntityID, commandID string, input []byte) (string, *domain.IdempotencyRecord, error) {
	if commandID == "" || !utf8.ValidString(commandID) || strings.HasPrefix(commandID, "expiration/") || len(commandID) > 1<<20 {
		return "", nil, &FieldError{Field: "commandID", Code: "InvalidFormat"}
	}
	if s.opts.Results == nil {
		return "", nil, ErrAuthUnavailable
	}
	tuple := struct {
		Version      string          `json:"version"`
		Operation    string          `json:"operation"`
		ActorID      domain.EntityID `json:"actorID"`
		OrgID        domain.EntityID `json:"orgID"`
		MembershipID domain.EntityID `json:"membershipID"`
		AssignmentID domain.EntityID `json:"assignmentID,omitempty"`
		Input        json.RawMessage `json:"input"`
	}{"1", operation, actor, orgID, membershipID, assignmentID, input}
	b, err := json.Marshal(tuple)
	if err != nil {
		return "", nil, ErrAuthUnavailable
	}
	fp := TokenDigest(string(b))
	for _, r := range a.Idempotency {
		if r.ActorID == actor && r.OperationID == operation && r.OrgID == orgID && r.RestaurantID == "" && r.CommandID == commandID {
			if r.Fingerprint != fp {
				return "", nil, ErrCommandConflict
			}
			return fp, &r, nil
		}
	}
	return fp, nil, nil
}

type membershipResult interface {
	domain.Membership | DurableResult | domain.Settings
}

func openMembershipResult[T membershipResult](s *Accounts, r domain.IdempotencyRecord, schema string, target *T) error {
	if r.HTTPStatus != 200 || r.ResponseSchema != schema {
		return ErrAuthUnavailable
	}
	plain, err := s.opts.Results.Open(r.EncryptedResponse)
	if err != nil {
		return ErrAuthUnavailable
	}
	if err := json.Unmarshal(plain, target); err != nil {
		return ErrAuthUnavailable
	}
	return nil
}
func saveMembershipResult[T membershipResult](s *Accounts, a *domain.Aggregate, actor domain.EntityID, operation string, orgID domain.EntityID, commandID, fp, schema string, result T) error {
	b, err := json.Marshal(result)
	if err != nil {
		return ErrAuthUnavailable
	}
	sealed, err := s.opts.Results.Seal(b)
	if err != nil {
		return ErrAuthUnavailable
	}
	revision, err := nextVersion(a.AggregateRevision)
	if err != nil {
		return err
	}
	a.Idempotency = append(a.Idempotency, domain.IdempotencyRecord{ContractProfile: "C2", ActorID: actor, OperationID: operation, OrgID: orgID, CommandID: commandID, Fingerprint: fp, AggregateRevision: revision, HTTPStatus: 200, ResponseSchema: schema, EncryptedResponse: sealed, JobIDs: []domain.EntityID{}})
	return nil
}
