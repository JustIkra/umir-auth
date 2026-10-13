package domain_test

import (
	"testing"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestSettingsReplacementRequiresMonotonicVersion(t *testing.T) {
	before, err := domain.Validate(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*domain.Aggregate){
		"zone without advance": func(a *domain.Aggregate) { a.Organizations[0].Settings.TimeZone = "America/New_York" },
		"version rollback":     func(a *domain.Aggregate) { a.Organizations[0].Settings.SettingsVersion = "1" },
	} {
		t.Run(name, func(t *testing.T) {
			base := before.Snapshot()
			base.Organizations[0].Settings.SettingsVersion = "2"
			previous, err := domain.Validate(base)
			if err != nil {
				t.Fatal(err)
			}
			next := previous.Snapshot()
			change(&next)
			after, err := domain.Validate(next)
			if err != nil {
				t.Fatal(err)
			}
			if domain.ValidateReplacement(previous, after) == nil {
				t.Fatal("settings change/rollback accepted without monotonic version")
			}
		})
	}
}
