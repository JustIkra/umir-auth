package application

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"slices"

	"github.com/JustIkra/umir-auth/internal/domain"
)

var (
	ErrForbidden          = errors.New("auth forbidden")
	ErrLastAdmin          = errors.New("last active organization admin")
	ErrMembershipConflict = errors.New("auth membership version conflict")
)

type UpdateMembershipInput struct {
	CommandID                 string                    `json:"commandID"`
	ExpectedMembershipVersion domain.Version            `json:"expectedMembershipVersion"`
	OrgRoles                  []string                  `json:"orgRoles"`
	Assignments               []domain.InviteAssignment `json:"assignments"`
}
type RevokeMembershipInput struct {
	CommandID                 string         `json:"commandID"`
	ExpectedMembershipVersion domain.Version `json:"expectedMembershipVersion"`
}
type RevokeAssignmentInput struct {
	CommandID                 string         `json:"commandID"`
	ExpectedAssignmentVersion domain.Version `json:"expectedAssignmentVersion"`
}
type MailJobView struct {
	JobID         domain.EntityID `json:"jobID"`
	State         string          `json:"state"`
	Attempts      int             `json:"attempts"`
	AcceptedAt    domain.Instant  `json:"acceptedAt"`
	NextAttemptAt domain.Instant  `json:"nextAttemptAt,omitempty"`
}
type DurableResult struct {
	CommandID         string          `json:"commandID"`
	Outcome           CommitOutcome   `json:"outcome"`
	AggregateRevision domain.Version  `json:"aggregateRevision"`
	ResourceID        domain.EntityID `json:"resourceID"`
	MailJobs          []MailJobView   `json:"mailJobs"`
}

func (s *Accounts) RestaurantAccess(ctx context.Context, token string, restaurantID domain.EntityID) (domain.RestaurantAccess, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var observed map[string]RuntimeStatus
	for {
		if err := ctx.Err(); err != nil {
			return domain.RestaurantAccess{}, err
		}
		a, err := s.load(ctx)
		if err != nil {
			return domain.RestaurantAccess{}, err
		}
		u, _, err := active(a, token, s.opts.Clock.Now())
		if err != nil {
			return domain.RestaurantAccess{}, err
		}
		if _, err := domain.RestaurantPermissions(a, u.UserID, restaurantID); err != nil {
			return domain.RestaurantAccess{}, ErrForbidden
		}
		if _, err := s.runtimeAccess(ctx, a, restaurantID, &observed); err != nil {
			if errors.Is(err, ErrRevisionConflict) {
				continue
			}
			return domain.RestaurantAccess{}, err
		}
		u, _, err = active(a, token, s.opts.Clock.Now())
		if err != nil {
			return domain.RestaurantAccess{}, err
		}
		result, err := domain.RestaurantPermissions(a, u.UserID, restaurantID)
		if err != nil {
			return domain.RestaurantAccess{}, ErrForbidden
		}
		return result, nil
	}
}
func (s *Accounts) Memberships(ctx context.Context, token string, orgID domain.EntityID) ([]domain.Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	u, _, err := active(a, token, s.opts.Clock.Now())
	if err != nil {
		return nil, err
	}
	if !domain.IsOrgAdmin(a, u.UserID, orgID) {
		return nil, ErrForbidden
	}
	result := []domain.Membership{}
	for _, m := range a.Memberships {
		if m.OrgID == orgID {
			result = append(result, m)
		}
	}
	return result, nil
}
func (s *Accounts) membershipActor(a domain.Aggregate, token, csrf string) (domain.User, error) {
	u, i, err := active(a, token, s.opts.Clock.Now())
	if err != nil {
		return domain.User{}, err
	}
	st := a.Sessions[i]
	if csrf == "" || subtle.ConstantTimeCompare([]byte(sessionCSRF(token)), []byte(csrf)) != 1 || !st.LegacyCSRF && TokenDigest(csrf) != st.CSRFTokenDigest {
		return domain.User{}, ErrInvalidCSRFToken
	}
	return u, nil
}
func membershipIndex(a domain.Aggregate, orgID, id domain.EntityID) (int, error) {
	for i, m := range a.Memberships {
		if m.MembershipID == id && m.OrgID == orgID {
			return i, nil
		}
	}
	return 0, ErrForbidden
}
func retainsAdmin(a domain.Aggregate, orgID domain.EntityID) bool {
	for _, m := range a.Memberships {
		if m.OrgID == orgID && m.State == "active" && slices.Contains(m.OrgRoles, "Admin") {
			return true
		}
	}
	return false
}
func (s *Accounts) UpdateMembership(ctx context.Context, token, csrf string, orgID, id domain.EntityID, in UpdateMembershipInput) (domain.Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := json.Marshal(in)
	if err != nil {
		return domain.Membership{}, ErrAuthUnavailable
	}
	for {
		if err := ctx.Err(); err != nil {
			return domain.Membership{}, err
		}
		a, err := s.load(ctx)
		if err != nil {
			return domain.Membership{}, err
		}
		u, err := s.membershipActor(a, token, csrf)
		if err != nil {
			return domain.Membership{}, err
		}
		if !domain.IsOrgAdmin(a, u.UserID, orgID) {
			return domain.Membership{}, ErrForbidden
		}
		if _, ok := domain.VersionNumber(in.ExpectedMembershipVersion); !ok {
			return domain.Membership{}, &FieldError{Field: "expectedMembershipVersion", Code: "InvalidFormat"}
		}
		fp, record, err := s.membershipCommand(a, u.UserID, "updateMembership", orgID, id, "", in.CommandID, payload)
		if err != nil {
			return domain.Membership{}, err
		}
		if record != nil {
			var result domain.Membership
			err = openMembershipResult(s, *record, "Membership", &result)
			return result, err
		}
		i, err := membershipIndex(a, orgID, id)
		if err != nil {
			return domain.Membership{}, err
		}
		old := a.Memberships[i]
		if old.State != "active" || old.MembershipVersion != in.ExpectedMembershipVersion {
			return domain.Membership{}, ErrMembershipConflict
		}
		if err := validateMembershipInput(a, orgID, in); err != nil {
			return domain.Membership{}, err
		}
		version, err := nextVersion(old.MembershipVersion)
		if err != nil {
			return domain.Membership{}, err
		}
		next := old
		next.MembershipVersion = version
		next.OrgRoles = slices.Clone(in.OrgRoles)
		next.Assignments = []domain.Assignment{}
		for _, input := range in.Assignments {
			as, err := s.updatedAssignment(old, input)
			if err != nil {
				return domain.Membership{}, err
			}
			next.Assignments = append(next.Assignments, as)
		}
		a.Memberships[i] = next
		if !retainsAdmin(a, orgID) {
			return domain.Membership{}, ErrLastAdmin
		}
		if err := saveMembershipResult(s, &a, u.UserID, "updateMembership", orgID, in.CommandID, fp, "Membership", next); err != nil {
			return domain.Membership{}, err
		}
		if err := s.commit(ctx, a); err != nil {
			if errors.Is(err, ErrRevisionConflict) {
				continue
			}
			return domain.Membership{}, err
		}
		return next, nil
	}
}
func validateMembershipInput(a domain.Aggregate, orgID domain.EntityID, in UpdateMembershipInput) error {
	if in.OrgRoles == nil || len(in.OrgRoles) > 1 || len(in.OrgRoles) == 1 && in.OrgRoles[0] != "Admin" || in.Assignments == nil || len(in.Assignments) > 500 {
		return &FieldError{Field: "membership", Code: "InvalidFormat"}
	}
	seen := map[domain.EntityID]bool{}
	for _, as := range in.Assignments {
		found := false
		for _, r := range a.Restaurants {
			if r.RestaurantID == as.RestaurantID && r.OrgID == orgID && (r.Lifecycle == "ready" || r.Lifecycle == "registering") {
				found = true
				break
			}
		}
		if !found {
			return ErrForbidden
		}
		if seen[as.RestaurantID] || len(as.Roles) == 0 || len(as.Roles) > 2 {
			return &FieldError{Field: "assignments", Code: "InvalidFormat"}
		}
		seen[as.RestaurantID] = true
		for i, role := range as.Roles {
			if role != "Warehouse" && role != "Waiter" || i > 0 && role == as.Roles[0] {
				return &FieldError{Field: "roles", Code: "InvalidFormat"}
			}
		}
	}
	return nil
}
func (s *Accounts) updatedAssignment(old domain.Membership, in domain.InviteAssignment) (domain.Assignment, error) {
	for _, as := range old.Assignments {
		if as.RestaurantID == in.RestaurantID {
			if !slices.Equal(as.Roles, in.Roles) {
				v, err := nextVersion(as.AssignmentVersion)
				if err != nil {
					return domain.Assignment{}, err
				}
				as.AssignmentVersion = v
			}
			as.Roles = slices.Clone(in.Roles)
			return as, nil
		}
	}
	id, err := s.opts.IDs.NewID()
	if err != nil {
		return domain.Assignment{}, ErrAuthUnavailable
	}
	return domain.Assignment{RestaurantID: in.RestaurantID, AssignmentID: id, AssignmentVersion: "1", Roles: slices.Clone(in.Roles)}, nil
}
func (s *Accounts) RevokeMembership(ctx context.Context, token, csrf string, orgID, id domain.EntityID, in RevokeMembershipInput) (DurableResult, error) {
	payload, err := json.Marshal(in)
	if err != nil {
		return DurableResult{}, ErrAuthUnavailable
	}
	return s.revokeMembershipScope(ctx, token, csrf, orgID, id, "", in.CommandID, in.ExpectedMembershipVersion, payload)
}
func (s *Accounts) RevokeAssignment(ctx context.Context, token, csrf string, orgID, id, assignmentID domain.EntityID, in RevokeAssignmentInput) (DurableResult, error) {
	if assignmentID == "" {
		return DurableResult{}, ErrForbidden
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return DurableResult{}, ErrAuthUnavailable
	}
	return s.revokeMembershipScope(ctx, token, csrf, orgID, id, assignmentID, in.CommandID, in.ExpectedAssignmentVersion, payload)
}
func (s *Accounts) revokeMembershipScope(ctx context.Context, token, csrf string, orgID, id, assignmentID domain.EntityID, commandID string, expected domain.Version, input []byte) (DurableResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := "revokeMembership"
	resourceID := id
	if assignmentID != "" {
		operation = "revokeAssignment"
		resourceID = assignmentID
	}
	for {
		if err := ctx.Err(); err != nil {
			return DurableResult{}, err
		}
		a, err := s.load(ctx)
		if err != nil {
			return DurableResult{}, err
		}
		u, err := s.membershipActor(a, token, csrf)
		if err != nil {
			return DurableResult{}, err
		}
		if !domain.IsOrgAdmin(a, u.UserID, orgID) {
			return DurableResult{}, ErrForbidden
		}
		if _, ok := domain.VersionNumber(expected); !ok {
			field := "expectedMembershipVersion"
			if assignmentID != "" {
				field = "expectedAssignmentVersion"
			}
			return DurableResult{}, &FieldError{Field: field, Code: "InvalidFormat"}
		}
		fp, record, err := s.membershipCommand(a, u.UserID, operation, orgID, id, assignmentID, commandID, input)
		if err != nil {
			return DurableResult{}, err
		}
		if record != nil {
			var result DurableResult
			err = openMembershipResult(s, *record, "DurableResult", &result)
			return result, err
		}
		i, err := membershipIndex(a, orgID, id)
		if err != nil {
			return DurableResult{}, err
		}
		m := &a.Memberships[i]
		if m.State != "active" {
			return DurableResult{}, ErrMembershipConflict
		}
		if assignmentID == "" {
			if m.MembershipVersion != expected {
				return DurableResult{}, ErrMembershipConflict
			}
			m.State = "revoked"
		} else {
			found := false
			for j, as := range m.Assignments {
				if as.AssignmentID == assignmentID {
					if as.AssignmentVersion != expected {
						return DurableResult{}, ErrMembershipConflict
					}
					m.Assignments = slices.Delete(m.Assignments, j, j+1)
					found = true
					break
				}
			}
			if !found {
				return DurableResult{}, ErrMembershipConflict
			}
		}
		m.MembershipVersion, err = nextVersion(m.MembershipVersion)
		if err != nil {
			return DurableResult{}, err
		}
		if !retainsAdmin(a, orgID) {
			return DurableResult{}, ErrLastAdmin
		}
		revision, err := nextVersion(a.AggregateRevision)
		if err != nil {
			return DurableResult{}, err
		}
		result := DurableResult{CommandID: commandID, Outcome: Committed, AggregateRevision: revision, ResourceID: resourceID, MailJobs: []MailJobView{}}
		if err := saveMembershipResult(s, &a, u.UserID, operation, orgID, commandID, fp, "DurableResult", result); err != nil {
			return DurableResult{}, err
		}
		if err := s.commit(ctx, a); err != nil {
			if errors.Is(err, ErrRevisionConflict) {
				continue
			}
			return DurableResult{}, err
		}
		return result, nil
	}
}
