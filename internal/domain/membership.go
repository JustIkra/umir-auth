package domain

import "slices"

func ValidateMembershipReplacement(before, after Aggregate) error {
	owners := map[EntityID]EntityID{}
	for _, m := range after.Memberships {
		for _, as := range m.Assignments {
			owners[as.AssignmentID] = m.MembershipID
		}
	}
	for _, m := range before.Memberships {
		for _, as := range m.Assignments {
			if owner, ok := owners[as.AssignmentID]; ok && owner != m.MembershipID {
				return ErrInvalidAggregate
			}
		}
	}
	current := map[EntityID]Membership{}
	for _, m := range after.Memberships {
		current[m.MembershipID] = m
	}
	for _, old := range before.Memberships {
		next, ok := current[old.MembershipID]
		if !ok || old.OrgID != next.OrgID || old.UserID != next.UserID {
			return ErrInvalidAggregate
		}
		ov, _ := VersionNumber(old.MembershipVersion)
		nv, _ := VersionNumber(next.MembershipVersion)
		changed := old.State != next.State || !slices.Equal(old.OrgRoles, next.OrgRoles) || !sameAssignments(old.Assignments, next.Assignments)
		if nv < ov || changed && nv <= ov {
			return ErrInvalidAggregate
		}
		assignments := map[EntityID]Assignment{}
		for _, as := range next.Assignments {
			assignments[as.AssignmentID] = as
		}
		for _, as := range old.Assignments {
			n, kept := assignments[as.AssignmentID]
			if !kept {
				continue
			}
			av, _ := VersionNumber(as.AssignmentVersion)
			bv, _ := VersionNumber(n.AssignmentVersion)
			if as.RestaurantID != n.RestaurantID || bv < av || !slices.Equal(as.Roles, n.Roles) && bv <= av {
				return ErrInvalidAggregate
			}
		}
	}
	return nil
}
func sameAssignments(a, b []Assignment) bool {
	if len(a) != len(b) {
		return false
	}
	for i, as := range a {
		n := b[i]
		if as.RestaurantID != n.RestaurantID || as.AssignmentID != n.AssignmentID || as.AssignmentVersion != n.AssignmentVersion || !slices.Equal(as.Roles, n.Roles) {
			return false
		}
	}
	return true
}
