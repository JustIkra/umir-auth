package integration_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

// These tests pin the budgets the README's OTP threat model is computed from. They
// describe current behaviour and passed before any change: M1 asks for the model
// to be written down and for the numbers not to drift unnoticed.

func wrongCodes(t *testing.T, e *enrollmentFixture, v application.ChallengeView, prefix string, n int) {
	t.Helper()
	code := "000000"
	if e.code(t, v.ChallengeID) == code {
		code = "999999"
	}
	for j := 0; j < n; j++ {
		_, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: fmt.Sprintf("%s-%d", prefix, j), ChallengeID: v.ChallengeID, Code: code})
		if j < 4 && !errors.Is(err, application.ErrChallengeInvalidCode) || j == 4 && !errors.Is(err, application.ErrChallengeLocked) {
			t.Fatalf("%s attempt %d: %v", prefix, j, err)
		}
	}
}

// The wrong-code budget is ten per address per rolling hour, shared by every
// challenge for that address; each challenge locks itself after five.
func TestWrongCodeBudgetIsTenPerAddressAcrossChallenges(t *testing.T) {
	t.Run("nine failures leave the address usable", func(t *testing.T) {
		e := registrationSetup(t)
		a := registrationBegin(t, e, "pin-nine@umir.invalid", "nine-a")
		b := registrationBegin(t, e, "pin-nine@umir.invalid", "nine-b")
		wrongCodes(t, e, a, "nine-wa", 5)
		code := "000000"
		if e.code(t, b.ChallengeID) == code {
			code = "999999"
		}
		for j := 0; j < 4; j++ {
			if _, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: fmt.Sprintf("nine-wb-%d", j), ChallengeID: b.ChallengeID, Code: code}); !errors.Is(err, application.ErrChallengeInvalidCode) {
				t.Fatal(err)
			}
		}
		if _, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "nine-right", ChallengeID: b.ChallengeID, Code: e.code(t, b.ChallengeID)}); err != nil {
			t.Fatalf("the ninth failure already blocked the address: %v", err)
		}
	})
	t.Run("ten failures block every challenge for the address for an hour", func(t *testing.T) {
		e := registrationSetup(t)
		a := registrationBegin(t, e, "pin-ten@umir.invalid", "ten-a")
		b := registrationBegin(t, e, "pin-ten@umir.invalid", "ten-b")
		c := registrationBegin(t, e, "pin-ten@umir.invalid", "ten-c")
		wrongCodes(t, e, a, "ten-wa", 5)
		wrongCodes(t, e, b, "ten-wb", 5)
		if _, err := e.accounts.VerifyChallenge(ctx, e.actor, application.ChallengeVerifyInput{CommandID: "ten-right", ChallengeID: c.ChallengeID, Code: e.code(t, c.ChallengeID)}); !registrationRateLimit(err) {
			t.Fatalf("a fresh challenge was verifiable after ten failures: %v", err)
		}
	})
}

// Issuing is limited to three codes per address per ten minutes, counting every
// purpose, including the invitation link mail; sixty per ten minutes overall.
func TestIssueBudgetIsThreePerAddressSharedWithInvitations(t *testing.T) {
	e := enrollmentSetup(t)
	invitation, err := e.accounts.CreateInvitation(ctx, e.owner.Token, e.owner.CSRFToken, e.org, application.CreateInvitationInput{CommandID: "pin-invite", Email: "pin-shared@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: e.r1, Roles: []string{"Waiter"}}}})
	if err != nil {
		t.Fatal(err)
	}
	// 1: the link mail of the invitation itself.
	v, err := e.accounts.BeginInvitationChallenge(ctx, e.actor, application.ChallengeBeginInput{CommandID: "pin-begin", InvitationID: invitation.InvitationID}) // 2
	if err != nil {
		t.Fatal(err)
	}
	e.advance(t, time.Minute+time.Second)
	if _, err := e.accounts.ResendChallenge(ctx, e.actor, v.ChallengeID, "pin-resend-1"); err != nil { // 3
		t.Fatal(err)
	}
	e.advance(t, time.Minute+time.Second)
	if _, err := e.accounts.ResendChallenge(ctx, e.actor, v.ChallengeID, "pin-resend-2"); !registrationRateLimit(err) { // 4: refused
		t.Fatalf("a fourth issue for one address inside ten minutes = %v; want a rate limit", err)
	}
	e.advance(t, 10*time.Minute)
	if _, err := e.accounts.BeginInvitationChallenge(ctx, e.actor, application.ChallengeBeginInput{CommandID: "pin-begin-2", InvitationID: invitation.InvitationID}); err != nil {
		t.Fatalf("the budget did not recover after ten minutes: %v", err)
	}
}
