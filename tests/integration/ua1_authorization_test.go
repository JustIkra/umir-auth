package integration_test

import (
	"slices"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
)

func TestUA1ProductBatchesMinimumAuthority(t *testing.T) {
	f, _ := a5Setup(t)
	result, err := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.worker.Token, RestaurantID: f.r1, Operation: "productBatches", Audiences: []string{"umir-warehouse"}, Activity: "background"})
	if err != nil || !slices.Equal(result.Permissions, []string{"stock.read"}) {
		t.Fatalf("new batch authority missing or wider than stock.read: %v", err)
	}
}
