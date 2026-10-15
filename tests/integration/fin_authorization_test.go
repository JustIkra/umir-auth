package integration_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
	"github.com/JustIkra/umir-auth/internal/application"
)

func TestFINPlanningTokenMinimumAuthority(t *testing.T) {
	f, signer := a5Setup(t)
	keys, err := signer.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		operation              string
		audiences, permissions []string
	}{
		{"supplySuggestions", []string{"umir-warehouse"}, []string{"stock.read"}},
		{"recommendations", []string{"umir-serving", "umir-warehouse"}, []string{"recommendations.read", "consumer.recommendations.read"}},
		{"menu", []string{"umir-serving", "umir-warehouse"}, []string{"menu.read", "consumer.menu.evaluate"}},
		{"history", []string{"umir-warehouse"}, []string{"stock.read"}},
	} {
		result, err := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.worker.Token, RestaurantID: f.r1, Operation: tc.operation, Audiences: tc.audiences, Activity: "background"})
		if err != nil || !slices.Equal(result.Permissions, tc.permissions) {
			t.Fatalf("%s permissions: %+v %v", tc.operation, result.Permissions, err)
		}
		claims, err := jwt.VerifyUser(result.Token, keys, f.opts.Clock.Now(), tc.audiences[0])
		if err != nil || !slices.Equal(claims.Permissions, tc.permissions) || !slices.Equal(claims.Audiences, tc.audiences) {
			t.Fatalf("%s signed authority: %+v %v", tc.operation, claims.Permissions, err)
		}
	}
	if _, err := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.worker.Token, RestaurantID: f.r2, Operation: "supplySuggestions", Audiences: []string{"umir-warehouse"}, Activity: "background"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("Waiter received stock read: %v", err)
	}
	if _, err := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.worker.Token, RestaurantID: f.r2, Operation: "recommendations", Audiences: []string{"umir-serving", "umir-warehouse"}, Activity: "background"}); err != nil {
		t.Fatalf("Waiter lost recommendations: %v", err)
	}
	if _, err := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.worker.Token, RestaurantID: f.r1, Operation: "recommendations", Audiences: []string{"umir-warehouse"}, Activity: "background"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("recommendation audience widened: %v", err)
	}
}
