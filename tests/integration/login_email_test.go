package integration_test

import (
	"errors"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
)

func TestEmailLikeLoginComparisonPreservesStoredIdentity(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "Máx@umir.invalid", "login-canonical"), "login-canonical-proof")
	issued, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "login-canonical-complete"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.accounts.Login(ctx, application.LoginInput{Login: "  Máx@UMIR.INVALID  ", Password: "new-user-password"})
	if err != nil || result.User.Login != issued.User.Login {
		t.Fatalf("email-like canonical comparison failed: %v", err)
	}
}

func TestEmailLoginCaseVariantsSharePasswordFailureBudget(t *testing.T) {
	e := registrationSetup(t)
	p := registrationProof(t, e, registrationBegin(t, e, "Max@umir.invalid", "budget-login"), "budget-login-proof")
	if _, err := e.accounts.CompleteEmailChallenge(ctx, e.actor, registrationComplete(p, "budget-login-complete")); err != nil {
		t.Fatal(err)
	}
	for _, login := range []string{"Max@umir.invalid", "Max@UMIR.INVALID", " Max@umir.invalid ", "Max@Umir.Invalid", "Max@uMIR.invalid"} {
		if _, err := e.accounts.Login(ctx, application.LoginInput{Login: login, Password: "wrong-password"}); !errors.Is(err, application.ErrInvalidCredentials) {
			t.Fatal(err)
		}
	}
	if _, err := e.accounts.Login(ctx, application.LoginInput{Login: "Max@UMIR.invalid", Password: "new-user-password"}); !errors.Is(err, application.ErrLoginRateLimited) {
		t.Fatalf("case variation bypassed failure budget: %v", err)
	}
}
