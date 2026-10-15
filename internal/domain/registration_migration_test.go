package domain_test

import (
	"reflect"
	"testing"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestRegistrationMigrationPreservesV1V2FactsAndRejectsRollback(t *testing.T) {
	for _, version := range []int{1, 2} {
		old := fixture(t)
		var err error
		if version == 2 {
			old, err = domain.UpgradeV1(old)
			if err != nil {
				t.Fatal(err)
			}
		}
		before, err := domain.Validate(old)
		if err != nil {
			t.Fatal(err)
		}
		next, err := domain.UpgradeRegistration(old)
		if err != nil {
			t.Fatal(err)
		}
		if next.SchemaVersion != 3 {
			t.Fatal("current schema missing")
		}
		compatible, err := domain.UpgradeV1(fixture(t))
		if err != nil {
			t.Fatal(err)
		}
		compatible.SchemaVersion = 3
		if !reflect.DeepEqual(next, compatible) {
			t.Fatal("migration rewrote retained facts")
		}
		next.AggregateRevision = "2"
		after, err := domain.Validate(next)
		if err != nil {
			t.Fatal(err)
		}
		if err := domain.ValidateReplacement(before, after); err != nil {
			t.Fatal(err)
		}
		if err := domain.ValidateReplacement(after, before); err == nil {
			t.Fatal("format rollback admitted")
		}
	}
}
