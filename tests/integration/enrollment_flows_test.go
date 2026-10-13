package integration_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestA4ExistingUserAcceptPreservesVerifierAndScope(t *testing.T) {
	e := enrollmentSetup(t)
	other, err := e.accounts.CreateInvitation(ctx, e.owner.Token, e.owner.CSRFToken, e.otherOrg, application.CreateInvitationInput{CommandID: "existing-invite", Email: "second@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: e.r3, Roles: []string{"Waiter"}}}})
	if err != nil {
		t.Fatal(err)
	}
	actor := application.ChallengeActor{Token: e.second.Token, CSRFToken: e.second.CSRFToken}
	v, err := e.accounts.BeginInvitationChallenge(ctx, actor, application.ChallengeBeginInput{CommandID: "existing-begin", InvitationID: other.InvitationID})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e.accounts.VerifyChallenge(ctx, actor, application.ChallengeVerifyInput{CommandID: "existing-verify", ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)})
	if err != nil {
		t.Fatal(err)
	}
	before := loadEnrollment(t, e)
	in := application.InvitationAcceptInput{CommandID: "existing-accept", ChallengeID: v.ChallengeID, Proof: proof.Proof}
	m, err := e.accounts.AcceptInvitation(ctx, actor, other.InvitationID, in)
	if err != nil {
		t.Fatal(err)
	}
	after := loadEnrollment(t, e)
	if m.UserID != e.second.User.UserID || m.OrgID != e.otherOrg || len(m.Assignments) != 1 || m.Assignments[0].RestaurantID != e.r3 || len(after.Users) != len(before.Users) || after.Users[1].Verifier != before.Users[1].Verifier || after.Users[1].CredentialVersion != before.Users[1].CredentialVersion {
		t.Fatal("existing User credentials or invited scope changed")
	}
	e.reopen(t)
	same, err := e.accounts.AcceptInvitation(ctx, actor, other.InvitationID, in)
	if err != nil || !reflect.DeepEqual(same, m) || !reflect.DeepEqual(after, loadEnrollment(t, e)) {
		t.Fatal("acceptance replay mutated scope")
	}
}
func TestA4EmailLoginResetAndOriginalJobReopen(t *testing.T) {
	e := enrollmentSetup(t)
	v := e.begin(t)
	proof, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "verify-enroll", ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)})
	if err != nil {
		t.Fatal(err)
	}
	created, err := e.accounts.CompleteInvitedUser(ctx, e.actor, application.InvitationCompleteInput{CommandID: "enroll", ChallengeID: v.ChallengeID, Proof: proof.Proof, Password: "invited-password", DisplayName: "Invited User"})
	if err != nil {
		t.Fatal(err)
	}
	actor := application.ChallengeActor{PreauthDigest: application.TokenDigest("synthetic-email-browser")}
	begin := application.EmailChallengeInput{CommandID: "email-login", Email: created.User.Email, Purpose: "login"}
	email, err := e.accounts.BeginEmailChallenge(ctx, actor, begin)
	if err != nil {
		t.Fatal(err)
	}
	before := loadEnrollment(t, e)
	e.reopen(t)
	same, err := e.accounts.BeginEmailChallenge(ctx, actor, begin)
	if err != nil || email != same || !reflect.DeepEqual(before, loadEnrollment(t, e)) {
		t.Fatal("email begin replay lost original edge")
	}
	loginProof, err := e.accounts.VerifyChallenge(ctx, actor, application.ChallengeVerifyInput{CommandID: "email-verify", ChallengeID: email.ChallengeID, Code: e.code(t, email.ChallengeID)})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := e.accounts.CompleteEmailChallenge(ctx, actor, application.EmailCompleteInput{CommandID: "email-complete", ChallengeID: email.ChallengeID, Proof: loginProof.Proof, Purpose: "login", RememberMe: true})
	if err != nil || !issued.Session.RememberMe {
		t.Fatal("email login failed")
	}
	reset, err := e.accounts.BeginEmailChallenge(ctx, actor, application.EmailChallengeInput{CommandID: "reset-begin", Email: created.User.Email, Purpose: "password_reset"})
	if err != nil {
		t.Fatal(err)
	}
	resetProof, err := e.accounts.VerifyChallenge(ctx, actor, application.ChallengeVerifyInput{CommandID: "reset-verify", ChallengeID: reset.ChallengeID, Code: e.code(t, reset.ChallengeID)})
	if err != nil {
		t.Fatal(err)
	}
	in := application.EmailCompleteInput{CommandID: "reset-complete", ChallengeID: reset.ChallengeID, Proof: resetProof.Proof, Purpose: "password_reset", NewPassword: "replacement-password"}
	replacement, err := e.accounts.CompleteEmailChallenge(ctx, actor, in)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.User.CredentialVersion != "2" {
		t.Fatal("reset did not advance credential version")
	}
	if _, err := e.accounts.Peek(ctx, issued.Token); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("reset left old session active")
	}
	e.reopen(t)
	a := loadEnrollment(t, e)
	again, err := e.accounts.CompleteEmailChallenge(ctx, actor, in)
	if err != nil || again.Token != replacement.Token || !reflect.DeepEqual(a, loadEnrollment(t, e)) {
		t.Fatal("reset replay issued or revoked another session")
	}
}
func TestA4AdminResendCancellationAndNamespaceConflict(t *testing.T) {
	e := enrollmentSetup(t)
	v := e.begin(t)
	e.advance(t, time.Minute)
	resent, err := e.accounts.ResendInvitation(ctx, e.owner.Token, e.owner.CSRFToken, e.org, e.invitation.InvitationID, "admin-resend")
	if err != nil || len(resent.MailJobs) != 1 {
		t.Fatal("admin resend did not record a real job")
	}
	if resent.MailJobs[0].State != "pending" {
		t.Fatal("public resend result leaked private queued state")
	}
	same, err := e.accounts.ResendInvitation(ctx, e.owner.Token, e.owner.CSRFToken, e.org, e.invitation.InvitationID, "admin-resend")
	if err != nil || !reflect.DeepEqual(same, resent) {
		t.Fatal("admin resend replay changed job")
	}
	cancel, err := e.accounts.CancelInvitation(ctx, e.owner.Token, e.owner.CSRFToken, e.org, e.invitation.InvitationID, "cancel")
	if err != nil || cancel.ResourceID != e.invitation.InvitationID {
		t.Fatal("cancel failed")
	}
	if _, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "verify-canceled", ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)}); !errors.Is(err, application.ErrInvitationUnavailable) {
		t.Fatal("cancellation allowed acceptance")
	}
	a := loadEnrollment(t, e)
	for _, j := range a.MailJobs {
		if j.State != "suppressed" || j.EncryptedPayload != "" {
			t.Fatal("cancel left a queued invitation")
		}
	}
}
