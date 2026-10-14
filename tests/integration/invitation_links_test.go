package integration_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/challengesecrets"
	"github.com/JustIkra/umir-auth/internal/adapters/invitationurl"
	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func ua1LinkSetup(t *testing.T) *membershipFixture {
	t.Helper()
	f := membershipsSetup(t)
	secrets, err := challengesecrets.New([]byte(strings.Repeat("p", 32)), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	f.opts.Challenges = secrets
	f.opts.InvitationMail = application.InvitationMailOptions{FrontendOrigin: "https://app.umir.invalid"}
	f.opts.LinkURLs = invitationurl.Policy{}
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.accounts.CloseReadPages)
	return f
}

func ua1Invite(f *membershipFixture, command string) application.CreateInvitationInput {
	return application.CreateInvitationInput{CommandID: command, Email: "invitee@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: f.r1, Roles: []string{"Waiter", "Warehouse"}}}}
}

func TestUA1InvitationLinkCreateReplayAndObservation(t *testing.T) {
	f := ua1LinkSetup(t)
	in := ua1Invite(f, "ua1-create")
	invitation, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, in)
	if err != nil {
		t.Fatal(err)
	}
	a := f.snapshot(t)
	if len(a.Invitations) != 1 || len(a.MailJobs) != 1 || len(a.Challenges) != 0 || a.MailJobs[0].Purpose != "invitation_link" || a.MailJobs[0].InvitationID != invitation.InvitationID || a.MailJobs[0].ChallengeID != "" || a.Idempotency[len(a.Idempotency)-1].ContractProfile != "UA1" {
		t.Fatal("create did not atomically accept exactly one typed link job")
	}
	originalJob := a.MailJobs[0].JobID
	if replay, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, in); err != nil || replay.InvitationID != invitation.InvitationID || len(f.snapshot(t).MailJobs) != 1 {
		t.Fatal("exact create replay allocated another job or invitation")
	}
	changed := in
	changed.Email = "other@umir.invalid"
	if _, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, changed); !errors.Is(err, application.ErrCommandConflict) {
		t.Fatalf("changed create input did not conflict: %v", err)
	}
	page, err := f.accounts.Invitations(ctx, f.owner.Token, f.org, application.OrganizationListRequest{})
	if err != nil || len(page.Items) != 1 || page.Items[0].LinkDelivery == nil || page.Items[0].LinkDelivery.JobID != originalJob || page.Items[0].LinkDelivery.State != "pending" {
		t.Fatal("admin observation omitted original accepted link job")
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.store, err = jsonstore.Open(ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.opts.Repository = f.store
	f.opts.InvitationMail.FrontendOrigin = "https://changed.umir.invalid"
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, in); err != nil || f.snapshot(t).MailJobs[0].JobID != originalJob || len(f.snapshot(t).MailJobs) != 1 {
		t.Fatal("reopen/config change changed original acceptance")
	}
}

func TestUA1LinkResendWithoutChallengeAndStateGuards(t *testing.T) {
	f := ua1LinkSetup(t)
	physical, ok := f.opts.Clock.(*clock)
	if !ok {
		t.Fatal("unexpected test clock")
	}
	invitation, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, ua1Invite(f, "ua1-create"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.accounts.ResendInvitationLink(ctx, f.owner.Token, f.owner.CSRFToken, f.org, invitation.InvitationID, "too-early"); !errors.Is(err, application.ErrChallengeRateLimited) {
		t.Fatalf("link cooldown not enforced: %v", err)
	}
	physical.advance(time.Minute)
	receipt, err := f.accounts.ResendInvitationLink(ctx, f.owner.Token, f.owner.CSRFToken, f.org, invitation.InvitationID, "ua1-resend")
	if err != nil || len(receipt.MailJobs) != 1 || receipt.MailJobs[0].State != "pending" || len(f.snapshot(t).Challenges) != 0 || f.snapshot(t).Invitations[0].ExpiresAt != invitation.ExpiresAt {
		t.Fatalf("link resend changed challenge/deadline or omitted job: %v", err)
	}
	if replay, err := f.accounts.ResendInvitationLink(ctx, f.owner.Token, f.owner.CSRFToken, f.org, invitation.InvitationID, "ua1-resend"); err != nil || replay.MailJobs[0].JobID != receipt.MailJobs[0].JobID || len(f.snapshot(t).MailJobs) != 2 {
		t.Fatal("resend replay duplicated job")
	}
	if _, err := f.accounts.CancelInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, invitation.InvitationID, "cancel"); err != nil {
		t.Fatal(err)
	}
	physical.advance(time.Minute)
	if _, err := f.accounts.ResendInvitationLink(ctx, f.owner.Token, f.owner.CSRFToken, f.org, invitation.InvitationID, "after-cancel"); !errors.Is(err, application.ErrInvitationUnavailable) {
		t.Fatalf("cancelled invitation accepted fresh link: %v", err)
	}
}

func TestUA1LinkOriginMissingFailsBeforeMutation(t *testing.T) {
	f := ua1LinkSetup(t)
	f.opts.InvitationMail.FrontendOrigin = ""
	var err error
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t).AggregateRevision
	if _, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, ua1Invite(f, "missing-origin")); !errors.Is(err, application.ErrDeliveryUnavailable) {
		t.Fatalf("missing origin admitted: %v", err)
	}
	if a := f.snapshot(t); a.AggregateRevision != before || len(a.Invitations) != 0 || len(a.MailJobs) != 0 {
		t.Fatal("missing origin partially accepted invitation")
	}
}

func TestUA1ChallengeResendSharesInvitationCooldown(t *testing.T) {
	f := ua1LinkSetup(t)
	physical, ok := f.opts.Clock.(*clock)
	if !ok {
		t.Fatal("unexpected test clock")
	}
	v, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, ua1Invite(f, "shared-create"))
	if err != nil {
		t.Fatal(err)
	}
	physical.advance(10 * time.Minute)
	actor := application.ChallengeActor{PreauthDigest: application.TokenDigest("shared-cooldown-browser")}
	c, err := f.accounts.BeginInvitationChallenge(ctx, actor, application.ChallengeBeginInput{CommandID: "shared-begin", InvitationID: v.InvitationID})
	if err != nil {
		t.Fatal(err)
	}
	physical.advance(time.Minute)
	if _, err := f.accounts.ResendInvitationLink(ctx, f.owner.Token, f.owner.CSRFToken, f.org, v.InvitationID, "shared-link"); err != nil {
		t.Fatal(err)
	}
	physical.advance(time.Second)
	before := f.snapshot(t).AggregateRevision
	if _, err := f.accounts.ResendChallenge(ctx, actor, c.ChallengeID, "shared-otp"); !errors.Is(err, application.ErrChallengeRateLimited) {
		t.Fatalf("OTP ignored invitation link cooldown: %v", err)
	}
	if f.snapshot(t).AggregateRevision != before {
		t.Fatal("refused OTP mutated aggregate")
	}
	physical.advance(59 * time.Second)
	if _, err := f.accounts.ResendChallenge(ctx, actor, c.ChallengeID, "shared-otp"); err != nil {
		t.Fatal(err)
	}
	if invite := f.snapshot(t).Invitations[0]; invite.ResendAvailableAt != domain.Instant(physical.Now().Add(time.Minute).Format(time.RFC3339Nano)) {
		t.Fatal("OTP resend did not update shared invitation cooldown")
	}
}

func TestUA1LinkRateLimitsReportRemainingDelay(t *testing.T) {
	for _, hourly := range []bool{false, true} {
		f := ua1LinkSetup(t)
		physical, ok := f.opts.Clock.(*clock)
		if !ok {
			t.Fatal("unexpected test clock")
		}
		v, err := f.accounts.CreateInvitation(ctx, f.owner.Token, f.owner.CSRFToken, f.org, ua1Invite(f, "rate-create"))
		if err != nil {
			t.Fatal(err)
		}
		count := 2
		if hourly {
			count = 5
		}
		for n := 0; n < count; n++ {
			delay := time.Minute
			if hourly && n > 0 {
				delay = 11 * time.Minute
			}
			physical.advance(delay)
			if hourly {
				f.owner = login(t, f.accounts, "owner", false)
			}
			if _, err := f.accounts.ResendInvitationLink(ctx, f.owner.Token, f.owner.CSRFToken, f.org, v.InvitationID, "rate-"+string(rune('a'+n))); err != nil {
				t.Fatal(err)
			}
		}
		delay, remaining := time.Minute, 7*time.Minute
		if hourly {
			delay, remaining = 11*time.Minute, 5*time.Minute
		}
		physical.advance(delay)
		if hourly {
			f.owner = login(t, f.accounts, "owner", false)
		}
		before := f.snapshot(t).AggregateRevision
		_, err = f.accounts.ResendInvitationLink(ctx, f.owner.Token, f.owner.CSRFToken, f.org, v.InvitationID, "rate-refused")
		var limited *application.InvitationRateLimitError
		if !errors.As(err, &limited) || limited.RetryAfter != remaining {
			t.Fatalf("hourly=%v missing remaining retry delay %s: %v", hourly, remaining, err)
		}
		if f.snapshot(t).AggregateRevision != before {
			t.Fatal("rate refusal mutated aggregate")
		}
	}
}
