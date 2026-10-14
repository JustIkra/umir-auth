package protocol

import (
	"context"
	"errors"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestUA1ControlRejectsPayloadDifferentFromContextObservation(t *testing.T) {
	o := newUA1ControlOwner(t)
	a := application.CreateInvitationInput{CommandID: "payload-bound", Email: "original@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: o.org.RestaurantIDs[0], Roles: []string{"Waiter"}}}}
	sel := UA1CommandSelector{OperationID: "createInvitation", CommandID: a.CommandID, ActorID: o.session.User.UserID, OrgID: o.org.OrgID, BodySHA256: ua1Body(t, a)}
	id := ua1ControlID(t)
	o.arm(t, UA1ControlArm{ControlID: id, Point: "storage-before-commit", LifetimeMS: 30000, Command: &sel})
	b := a
	b.Email = "changed@umir.invalid"
	if _, err := o.r.Accounts.CreateInvitation(o.command(t, context.Background(), sel, a), o.session.Token, o.session.CSRFToken, o.org.OrgID, b); err != nil {
		t.Fatal("unrelated real payload hit the control", err)
	}
	if o.read(t, id).Hits != 0 {
		t.Fatal("candidate payload was not verified")
	}
	got, err := o.r.Store.Load(context.Background())
	if err != nil || len(got.Snapshot().MailJobs) != 1 {
		t.Fatal("positive unrelated command did not commit")
	}
}

func TestUA1ControlFingerprintUsesActualCanonicalBusinessInput(t *testing.T) {
	o := newUA1ControlOwner(t)
	in := application.CreateInvitationInput{CommandID: "canonical-payload", Email: " Canonical@UMIR.invalid ", Assignments: []domain.InviteAssignment{{RestaurantID: o.org.RestaurantIDs[0], Roles: []string{"Warehouse", "Waiter"}}}}
	sel := UA1CommandSelector{OperationID: "createInvitation", CommandID: in.CommandID, ActorID: o.session.User.UserID, OrgID: o.org.OrgID, BodySHA256: ua1Body(t, in)}
	id := ua1ControlID(t)
	o.arm(t, UA1ControlArm{ControlID: id, Point: "storage-before-commit", LifetimeMS: 30000, Command: &sel})
	_, err := o.r.Accounts.CreateInvitation(o.command(t, context.Background(), sel, in), o.session.Token, o.session.CSRFToken, o.org.OrgID, in)
	if !errors.Is(err, application.ErrStorageUnavailable) || o.read(t, id).Hits != 1 {
		t.Fatal("actual canonical input failed its control binding", err)
	}
}

func TestUA1ControlFingerprintRejectsForeignActualActorAndScope(t *testing.T) {
	for _, field := range []string{"actor", "org"} {
		t.Run(field, func(t *testing.T) {
			o := newUA1ControlOwner(t)
			in := application.CreateInvitationInput{CommandID: "foreign-payload", Email: "foreign@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: o.org.RestaurantIDs[0], Roles: []string{"Waiter"}}}}
			sel := UA1CommandSelector{OperationID: "createInvitation", CommandID: in.CommandID, ActorID: o.session.User.UserID, OrgID: o.org.OrgID, BodySHA256: ua1Body(t, in)}
			if field == "actor" {
				sel.ActorID = "99999999-9999-4999-8999-999999999999"
			} else {
				sel.OrgID = "99999999-9999-4999-8999-999999999999"
			}
			id := ua1ControlID(t)
			o.arm(t, UA1ControlArm{ControlID: id, Point: "storage-before-commit", LifetimeMS: 30000, Command: &sel})
			if _, err := o.r.Accounts.CreateInvitation(o.command(t, context.Background(), sel, in), o.session.Token, o.session.CSRFToken, o.org.OrgID, in); err != nil {
				t.Fatal("foreign actor/scope observation controlled the real caller", err)
			}
			if o.read(t, id).Hits != 0 {
				t.Fatal("foreign actor/scope hit")
			}
		})
	}
}
