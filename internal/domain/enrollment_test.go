package domain_test

import (
	"testing"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestInvitationComparisonPreservesLocalPart(t *testing.T) {
	a := fixture(t)
	a.Invitations[0].Email = "Invited@UMIR.INVALID"
	a.Invitations[0].ComparisonEmail = "Invited@umir.invalid"
	if _, err := domain.Validate(a); err != nil {
		t.Fatal("case-sensitive local part and lowercase domain must be accepted")
	}
}

func TestRetainedChallengeDeadlineCannotMove(t *testing.T) {
	a := fixture(t)
	before, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	a.Challenges[0].ExpiresAt = "2026-10-13T02:10:00+03:00"
	a.Challenges[0].ResendAvailableAt = "2026-10-13T02:01:00+03:00"
	after, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := domain.ValidateReplacement(before, after); err == nil {
		t.Fatal("replacement moved an authoritative retained OTP deadline")
	}
}
