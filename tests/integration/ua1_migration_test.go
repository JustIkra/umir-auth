package integration_test

import (
	"reflect"
	"testing"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/application"
)

func TestUA1AccountsUpgradeBeforeAdmissionAndReopen(t *testing.T) {
	f := membershipsSetup(t)
	first := f.snapshot(t)
	if first.SchemaVersion != 3 {
		t.Fatalf("legacy store admitted without current schema upgrade: %d", first.SchemaVersion)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := jsonstore.Open(ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.store = reopened
	f.opts.Repository = reopened
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, f.snapshot(t)) {
		t.Fatal("reopen changed an already migrated authority")
	}
	if _, err := f.accounts.Members(ctx, f.owner.Token, f.org, application.OrganizationListRequest{}); err != nil {
		t.Fatal(err)
	}
}
