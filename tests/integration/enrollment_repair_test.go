package integration_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestA4RepairInvitationResendNearExpiry(t *testing.T) {
	for _, remaining := range []time.Duration{90 * time.Second, time.Minute, 30 * time.Second, time.Nanosecond} {
		t.Run(remaining.String(), func(t *testing.T) {
			e := enrollmentSetup(t)
			e.advance(t, 7*24*time.Hour-remaining-90*time.Second)
			challenge := e.begin(t)
			e.advance(t, 90*time.Second)
			admin := login(t, e.accounts, "owner", false)
			before := loadEnrollment(t, e)
			result, err := e.accounts.ResendInvitation(ctx, admin.Token, admin.CSRFToken, e.org, e.invitation.InvitationID, "repair-final-minute")
			if err != nil {
				t.Fatalf("eligible resend before invitation expiry failed: %v", err)
			}
			if len(result.MailJobs) != 1 {
				t.Fatal("resend must accept one actual mail job")
			}
			after := loadEnrollment(t, e)
			if len(after.MailJobs) != len(before.MailJobs)+1 || after.Invitations[0].ExpiresAt != before.Invitations[0].ExpiresAt || after.Challenges[0].ExpiresAt != challenge.ExpiresAt {
				t.Fatal("resend changed a fixed deadline or failed to retain its job")
			}
			e.reopen(t)
			replayed, err := e.accounts.ResendInvitation(ctx, admin.Token, admin.CSRFToken, e.org, e.invitation.InvitationID, "repair-final-minute")
			if err != nil || !reflect.DeepEqual(result, replayed) || !reflect.DeepEqual(after, loadEnrollment(t, e)) {
				t.Fatal("restart replay changed the original resend result or durable edge")
			}
			e.advance(t, remaining)
			if _, err := e.accounts.ResendInvitation(ctx, admin.Token, admin.CSRFToken, e.org, e.invitation.InvitationID, "repair-at-expiry"); !errors.Is(err, application.ErrInvitationUnavailable) {
				t.Fatalf("fresh resend at invitation expiry must be rejected: %v", err)
			}
		})
	}
}

func TestA4RepairAcceptancePreservesQueuedEmailDelivery(t *testing.T) {
	for _, purpose := range []string{"login", "password_reset"} {
		for _, address := range []struct{ name, value string }{{"equivalent-domain", "Invited@umir.invalid"}, {"unchanged", "Invited@UMIR.INVALID"}} {
			t.Run(purpose+"/"+address.name, func(t *testing.T) {
				e := enrollmentSetup(t)
				v := e.begin(t)
				proof, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "repair-enroll-verify", ChallengeID: v.ChallengeID, Code: e.code(t, v.ChallengeID)})
				if err != nil {
					t.Fatal(err)
				}
				created, err := e.accounts.CompleteInvitedUser(ctx, e.actor, application.InvitationCompleteInput{CommandID: "repair-enroll", ChallengeID: v.ChallengeID, Proof: proof.Proof, Password: "invited-password", DisplayName: "Invited User"})
				if err != nil {
					t.Fatal(err)
				}
				queued, err := e.accounts.BeginEmailChallenge(ctx, e.actor, application.EmailChallengeInput{CommandID: "repair-queued-email", Email: created.User.Email, Purpose: purpose})
				if err != nil {
					t.Fatal(err)
				}
				before := loadEnrollment(t, e)
				job := before.MailJobs[len(before.MailJobs)-1]
				invite, err := e.accounts.CreateInvitation(ctx, e.owner.Token, e.owner.CSRFToken, e.otherOrg, application.CreateInvitationInput{CommandID: "repair-second-org", Email: address.value, Assignments: []domain.InviteAssignment{{RestaurantID: e.r3, Roles: []string{"Waiter"}}}})
				if err != nil {
					t.Fatal(err)
				}
				actor := application.ChallengeActor{Token: created.Token, CSRFToken: created.CSRFToken}
				challenge, err := e.accounts.BeginInvitationChallenge(ctx, actor, application.ChallengeBeginInput{CommandID: "repair-accept-begin", InvitationID: invite.InvitationID})
				if err != nil {
					t.Fatal(err)
				}
				verified, err := e.accounts.VerifyChallenge(ctx, actor, application.ChallengeVerifyInput{CommandID: "repair-accept-verify", ChallengeID: challenge.ChallengeID, Code: e.code(t, challenge.ChallengeID)})
				if err != nil {
					t.Fatal(err)
				}
				_, err = e.accounts.AcceptInvitation(ctx, actor, invite.InvitationID, application.InvitationAcceptInput{CommandID: "repair-accept", ChallengeID: challenge.ChallengeID, Proof: verified.Proof})
				if err != nil {
					t.Fatal(err)
				}
				e.reopen(t)
				sender := &mailCapture{result: application.DeliveryResult{Success: true}}
				worked, err := e.accounts.ProcessMail(ctx, sender)
				if err != nil || !worked || len(sender.deliveries) != 1 {
					t.Fatalf("queued email challenge must deliver after equivalent-address acceptance/restart: worked=%v err=%v captures=%d", worked, err, len(sender.deliveries))
				}
				delivered := sender.deliveries[0]
				if delivered.JobID != job.JobID || delivered.Mail.ChallengeID != queued.ChallengeID || delivered.Mail.Email != "Invited@UMIR.INVALID" {
					t.Fatal("delivery changed its original job, challenge or verified recipient")
				}
				after := loadEnrollment(t, e)
				for _, u := range after.Users {
					if u.UserID == created.User.UserID && (u.Email != "Invited@UMIR.INVALID" || u.CredentialVersion != "1") {
						t.Fatal("acceptance changed the established verified email or credential version")
					}
				}
				for _, j := range after.MailJobs {
					if j.JobID == job.JobID && (j.State != "delivered" || j.AcceptedAt != job.AcceptedAt || j.Attempts != 1) {
						t.Fatal("worker failed to retain the original accepted job and real delivered outcome")
					}
				}
			})
		}
	}
}

func TestA4RepairAcceptanceStillBindsFirstVerifiedAddress(t *testing.T) {
	e := enrollmentSetup(t)
	invite, err := e.accounts.CreateInvitation(ctx, e.owner.Token, e.owner.CSRFToken, e.otherOrg, application.CreateInvitationInput{CommandID: "repair-first-address-invite", Email: "Second@UMIR.INVALID", Assignments: []domain.InviteAssignment{{RestaurantID: e.r3, Roles: []string{"Waiter"}}}})
	if err != nil {
		t.Fatal(err)
	}
	actor := application.ChallengeActor{Token: e.second.Token, CSRFToken: e.second.CSRFToken}
	challenge, err := e.accounts.BeginInvitationChallenge(ctx, actor, application.ChallengeBeginInput{CommandID: "repair-first-address-begin", InvitationID: invite.InvitationID})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e.accounts.VerifyChallenge(ctx, actor, application.ChallengeVerifyInput{CommandID: "repair-first-address-verify", ChallengeID: challenge.ChallengeID, Code: e.code(t, challenge.ChallengeID)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.accounts.AcceptInvitation(ctx, actor, invite.InvitationID, application.InvitationAcceptInput{CommandID: "repair-first-address-accept", ChallengeID: challenge.ChallengeID, Proof: proof.Proof})
	if err != nil {
		t.Fatal(err)
	}
	e.reopen(t)
	for _, u := range loadEnrollment(t, e).Users {
		if u.Login == "second" {
			if u.Email != "Second@UMIR.INVALID" || u.CredentialVersion != "1" || u.Verifier != verifier {
				t.Fatal("first verified address must be bound without changing credentials")
			}
			return
		}
	}
	t.Fatal("accepted user is missing after restart")
}
