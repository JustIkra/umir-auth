package integration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
)

func TestUA1AcceptanceSuppressesUnclaimedLink(t *testing.T) {
	for _, existing := range []bool{false, true} {
		f := ua1LinkSetup(t)
		input := ua1Invite(f, "accept-create")
		org := f.org
		actor := application.ChallengeActor{PreauthDigest: application.TokenDigest("accept-invited-browser")}
		if existing {
			org = f.otherOrg
			input.Assignments[0].RestaurantID = f.r3
			input.Email = "second@umir.invalid"
			actor = application.ChallengeActor{Token: f.second.Token, CSRFToken: f.second.CSRFToken}
		}
		v, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, org, input)
		if err != nil {
			t.Fatal(err)
		}
		c, err := f.accounts.BeginInvitationChallenge(ctx, actor, application.ChallengeBeginInput{CommandID: "accept-begin", InvitationID: v.InvitationID})
		if err != nil {
			t.Fatal(err)
		}
		var code string
		for _, stored := range f.snapshot(t).Challenges {
			if stored.ChallengeID == c.ChallengeID {
				code, err = f.opts.Challenges.Open(fmt.Sprintf("code:%s:invitation", c.ChallengeID), stored.EncryptedCode)
			}
		}
		if err != nil || code == "" {
			t.Fatal("missing fixture challenge code")
		}
		proof, err := f.accounts.VerifyChallenge(ctx, actor, application.ChallengeVerifyInput{CommandID: "accept-verify", ChallengeID: c.ChallengeID, Code: code})
		if err != nil {
			t.Fatal(err)
		}
		if existing {
			_, err = f.accounts.AcceptInvitation(ctx, actor, v.InvitationID, application.InvitationAcceptInput{CommandID: "accept-finish", ChallengeID: c.ChallengeID, Proof: proof.Proof})
		} else {
			_, err = f.accounts.CompleteInvitedUser(ctx, actor, application.InvitationCompleteInput{CommandID: "accept-finish", ChallengeID: c.ChallengeID, Proof: proof.Proof, Password: "invited-password", DisplayName: "Invited User"})
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, job := range f.snapshot(t).MailJobs {
			if job.Purpose == "invitation_link" && (job.State != "suppressed" || job.EncryptedPayload != "" || job.NextAttemptAt != "") {
				t.Fatalf("existing=%v acceptance retained unclaimed link", existing)
			}
		}
	}
}

type ua1MailSink struct {
	deliveries []application.MailDelivery
	result     application.DeliveryResult
}

func (s *ua1MailSink) Send(_ context.Context, d application.MailDelivery) application.DeliveryResult {
	s.deliveries = append(s.deliveries, d)
	return s.result
}

func TestUA1LinkDeliveryUnknownRetriesKeepIdentity(t *testing.T) {
	f := ua1LinkSetup(t)
	invitation, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, ua1Invite(f, "delivery-create"))
	if err != nil {
		t.Fatal(err)
	}
	sink := &ua1MailSink{result: application.DeliveryResult{Unknown: true}}
	clock, ok := f.opts.Clock.(*clock)
	if !ok {
		t.Fatal("fixture clock type mismatch")
	}
	for i, delay := range []time.Duration{0, time.Minute, 5 * time.Minute} {
		clock.advance(delay)
		worked, err := f.accounts.ProcessMail(ctx, sink)
		if err != nil || !worked || len(sink.deliveries) != i+1 {
			t.Fatalf("attempt %d did not process: %v", i, err)
		}
		j := f.snapshot(t).MailJobs[0]
		if j.State != "unknown" || j.Attempts != i+1 {
			t.Fatal("ambiguous link delivery became definite failure")
		}
	}
	for _, d := range sink.deliveries {
		if d.Link == nil || d.Link.InvitationID != invitation.InvitationID || d.Link.Email != invitation.Email || d.Link.URL != "https://app.umir.invalid/invite/"+string(invitation.InvitationID) || d.JobID != sink.deliveries[0].JobID || d.Mail.ChallengeID != "" {
			t.Fatal("link payload or retry identity changed")
		}
	}
	if j := f.snapshot(t).MailJobs[0]; j.NextAttemptAt != "" || j.EncryptedPayload == "" {
		t.Fatal("exhausted unknown lost evidence or retained another attempt")
	}
	clock.advance(10 * time.Minute)
	if worked, err := f.accounts.ProcessMail(ctx, sink); err != nil || worked || len(sink.deliveries) != 3 {
		t.Fatalf("unknown job attempted a fourth delivery: %v", err)
	}
	page, err := f.accounts.Invitations(ctx, f.owner.Token, f.org, application.OrganizationListRequest{})
	if err != nil || page.Items[0].LinkDelivery == nil || page.Items[0].LinkDelivery.State != "unknown" || page.Items[0].LinkDelivery.Attempts != 3 {
		t.Fatal("unknown delivery omitted from admin observation")
	}
}

func TestUA1LinkSuppressionBeforeClaim(t *testing.T) {
	f := ua1LinkSetup(t)
	v, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, ua1Invite(f, "cancel-before-send"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.accounts.CancelInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, v.InvitationID, "cancel-before-claim"); err != nil {
		t.Fatal(err)
	}
	sink := &ua1MailSink{result: application.DeliveryResult{Success: true}}
	if _, err := f.accounts.ProcessMail(ctx, sink); err != nil || len(sink.deliveries) != 0 {
		t.Fatal("cancelled invitation sent an unclaimed link")
	}
	if j := f.snapshot(t).MailJobs[0]; j.State != "suppressed" || j.EncryptedPayload != "" || j.NextAttemptAt != "" {
		t.Fatal("cancelled link payload survived suppression")
	}
}
