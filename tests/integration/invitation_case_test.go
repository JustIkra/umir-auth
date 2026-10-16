package integration_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

// Two spellings of one address that differ only in case are one pending
// invitation (L3), as address ownership elsewhere already compares them.
func TestInvitationAddressesThatDifferInCaseAreOnePendingInvitation(t *testing.T) {
	e := enrollmentSetup(t)
	assignments := []domain.InviteAssignment{{RestaurantID: e.r1, Roles: []string{"Waiter"}}}
	first, err := e.accounts.CreateInvitation(ctx, e.owner.Token, e.owner.CSRFToken, e.org, application.CreateInvitationInput{CommandID: "case-first", Email: "Casey@umir.invalid", Assignments: assignments})
	if err != nil {
		t.Fatal(err)
	}
	before := loadEnrollment(t, e)
	for n, spelling := range []string{"casey@umir.invalid", "CASEY@umir.invalid", "casey@UMIR.invalid"} {
		_, err = e.accounts.CreateInvitation(ctx, e.owner.Token, e.owner.CSRFToken, e.org, application.CreateInvitationInput{CommandID: "case-second-" + string(rune('a'+n)), Email: spelling, Assignments: assignments})
		if !errors.Is(err, application.ErrInvitationConflict) {
			t.Fatalf("%q beside a pending %q = %v; want an invitation conflict", spelling, "Casey@umir.invalid", err)
		}
	}
	after := loadEnrollment(t, e)
	pending := 0
	for _, v := range after.Invitations {
		if v.State == "pending" && sameInvitee(v.ComparisonEmail, "casey@umir.invalid") {
			pending++
		}
	}
	if pending != 1 || len(after.Invitations) != len(before.Invitations) || first.InvitationID == "" {
		t.Fatalf("%d pending invitations for one address", pending)
	}
}

func sameInvitee(a, b string) bool { return strings.EqualFold(a, b) }
