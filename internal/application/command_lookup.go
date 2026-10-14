package application

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/JustIkra/umir-auth/internal/domain"
)

type CommandNamespace struct {
	OperationID  string          `json:"operationID"`
	OrgID        domain.EntityID `json:"orgID"`
	RestaurantID domain.EntityID `json:"restaurantID"`
}

func Namespace(n CommandNamespace) (string, error) {
	b, e := json.Marshal(n)
	if e != nil {
		return "", ErrAuthUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type StoredResponse struct {
	Type         string
	User         *UserView
	Session      *SessionView
	Organization *domain.Organization
	Membership   *domain.Membership
	Invitation   *domain.Invitation
	Challenge    *ChallengeView
	Verified     *VerifiedChallenge
	Durable      *DurableResult
	Lifecycle    *LifecycleResult
}
type CommandResult struct {
	State       string          `json:"state"`
	CommandID   string          `json:"commandID,omitempty"`
	OperationID string          `json:"operationID,omitempty"`
	HTTPStatus  int             `json:"httpStatus,omitempty"`
	Response    *StoredResponse `json:"response,omitempty"`
	Revision    domain.Version  `json:"aggregateRevision,omitempty"`
	Restore     *bool           `json:"requiresSessionRestore,omitempty"`
}

func (s *Accounts) LookupCommand(ctx context.Context, actor ChallengeActor, namespace, command string) (CommandResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if command == "" || namespace == "" {
		return CommandResult{}, ErrForbidden
	}
	b, e := base64.RawURLEncoding.DecodeString(namespace)
	if e != nil || len(b) > 1024 {
		return CommandResult{}, ErrForbidden
	}
	var n CommandNamespace
	if json.Unmarshal(b, &n) != nil || n.OperationID == "" {
		return CommandResult{}, ErrForbidden
	}
	canonical, e := Namespace(n)
	if e != nil || canonical != namespace {
		return CommandResult{}, ErrForbidden
	}
	a, e := s.load(ctx)
	if e != nil {
		return CommandResult{}, e
	}
	who, e := s.enrollmentActor(a, actor)
	if e != nil {
		return CommandResult{}, e
	}
	var found *domain.IdempotencyRecord
	for i := range a.Idempotency {
		rec := &a.Idempotency[i]
		if rec.CommandID != command || rec.OperationID != n.OperationID || rec.OrgID != n.OrgID || rec.RestaurantID != n.RestaurantID {
			continue
		}
		if who.user.UserID != "" && rec.ActorID != who.user.UserID || who.user.UserID == "" && rec.PreauthDigest != who.preauth {
			continue
		}
		if found != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		found = rec
	}
	if found == nil {
		return CommandResult{State: "unseen"}, nil
	}
	if n.OrgID != "" && n.OperationID != "deleteOrganization" && n.OperationID != "deleteRestaurant" {
		if !domain.IsOrgAdmin(a, who.user.UserID, n.OrgID) {
			return CommandResult{}, ErrForbidden
		}
		if e = publicScope(a, n.OrgID); e != nil {
			return CommandResult{}, e
		}
	}
	if s.opts.Results == nil {
		return CommandResult{}, ErrAuthUnavailable
	}
	plain, e := s.opts.Results.Open(found.EncryptedResponse)
	if e != nil {
		return CommandResult{}, ErrAuthUnavailable
	}
	defer clear(plain)
	response := &StoredResponse{Type: found.ResponseSchema}
	restore := false
	switch found.ResponseSchema {
	case "SessionIssued":
		var v SessionView
		if json.Unmarshal(plain, &v) != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		response.Type = "UserView"
		response.Session = &v
		restore = true
	case "User":
		var v UserView
		if json.Unmarshal(plain, &v) != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		response.User = &v
	case "NoContent":
	case "Organization":
		var v domain.Organization
		if json.Unmarshal(plain, &v) != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		response.Organization = &v
	case "Settings":
		var settings domain.Settings
		if json.Unmarshal(plain, &settings) != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		foundOrg := false
		for _, o := range a.Organizations {
			if o.OrgID == n.OrgID {
				o.Settings = settings
				response.Type = "Organization"
				response.Organization = &o
				foundOrg = true
				break
			}
		}
		if !foundOrg {
			return CommandResult{}, ErrAuthUnavailable
		}
	case "Membership":
		var v domain.Membership
		if json.Unmarshal(plain, &v) != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		response.Membership = &v
	case "Invitation":
		var v domain.Invitation
		if json.Unmarshal(plain, &v) != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		response.Invitation = &v
	case "Challenge":
		var v ChallengeView
		if json.Unmarshal(plain, &v) != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		if e = s.challengeAccess(a, who, v.ChallengeID); e != nil {
			return CommandResult{}, e
		}
		response.Challenge = &v
	case "VerifiedChallenge":
		var v VerifiedChallenge
		if json.Unmarshal(plain, &v) != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		if e = s.challengeAccess(a, who, v.Challenge.ChallengeID); e != nil {
			return CommandResult{}, e
		}
		response.Verified = &v
	case "DurableResult":
		var v DurableResult
		if json.Unmarshal(plain, &v) != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		response.Durable = &v
	case "LifecycleResult":
		var v LifecycleResult
		if json.Unmarshal(plain, &v) != nil {
			return CommandResult{}, ErrAuthUnavailable
		}
		if n.OperationID != "deleteOrganization" && n.OperationID != "deleteRestaurant" && !domain.IsOrgAdmin(a, who.user.UserID, v.OrgID) {
			return CommandResult{}, ErrForbidden
		}
		peers := []domain.PeerReadiness{}
		for _, p := range v.Services {
			if p.Epoch != "" {
				peers = append(peers, p)
			}
		}
		v.Services = peers
		response.Lifecycle = &v
	default:
		return CommandResult{}, ErrAuthUnavailable
	}
	return CommandResult{State: "completed", CommandID: command, OperationID: n.OperationID, HTTPStatus: found.HTTPStatus, Response: response, Revision: found.AggregateRevision, Restore: &restore}, nil
}
func (s *Accounts) LogoutAllCommand(ctx context.Context, token, command string) (DurableResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, e := s.load(ctx)
	if e != nil {
		return DurableResult{}, e
	}
	u, _, e := active(a, token, s.opts.Clock.Now())
	if e != nil {
		return DurableResult{}, e
	}
	fp, rec, e := s.userCommand(a, u.UserID, "logoutAll", command, []byte("logoutAll"))
	if e != nil {
		return DurableResult{}, e
	}
	if rec != nil {
		plain, e := s.opts.Results.Open(rec.EncryptedResponse)
		if e != nil {
			return DurableResult{}, ErrAuthUnavailable
		}
		defer clear(plain)
		var v DurableResult
		if json.Unmarshal(plain, &v) != nil {
			return DurableResult{}, ErrAuthUnavailable
		}
		return v, nil
	}
	if strings.HasPrefix(command, "expiration/") {
		return DurableResult{}, ErrForbidden
	}
	if e = revokeUserSessions(&a, u.UserID); e != nil {
		return DurableResult{}, e
	}
	if command == "" {
		e = s.commit(ctx, a)
		return DurableResult{}, e
	}
	rev, e := nextVersion(a.AggregateRevision)
	if e != nil {
		return DurableResult{}, e
	}
	v := DurableResult{CommandID: command, Outcome: Committed, AggregateRevision: rev, ResourceID: u.UserID, MailJobs: []MailJobView{}}
	b, e := json.Marshal(v)
	if e != nil {
		return DurableResult{}, ErrAuthUnavailable
	}
	sealed, e := s.opts.Results.Seal(b)
	if e != nil {
		return DurableResult{}, ErrAuthUnavailable
	}
	a.Idempotency = append(a.Idempotency, domain.IdempotencyRecord{ContractProfile: "C2", ActorID: u.UserID, OperationID: "logoutAll", CommandID: command, Fingerprint: fp, AggregateRevision: rev, HTTPStatus: 200, ResponseSchema: "DurableResult", EncryptedResponse: sealed, JobIDs: []domain.EntityID{}})
	e = s.commit(ctx, a)
	return v, e
}
