package application

import "testing"

func TestLoginMatchesCanonicalizesOnlyEmailLikeIdentities(t *testing.T) {
	for _, tc := range []struct {
		stored, input string
		match         bool
	}{
		{"Ma\u0301x@UMIR.INVALID", "Máx@umir.invalid", true},
		{"Max@UMIR.INVALID", "  Max@umir.invalid  ", true},
		{"Max@umir.invalid", "max@umir.invalid", false},
		{"admin", " admin ", false},
		{"admin", "ADMIN", false},
		{"admin", "admin", true},
		{"foo..bar@EXAMPLE.COM", "foo..bar@example.com", true},
		{"legacy@HOST_WITH_UNDERSCORE.INVALID", "legacy@host_with_underscore.invalid", true},
		{"not@a-domain", "not@a-domain", true},
		{"  not@a-domain  ", "not@a-domain", false},
	} {
		if got := loginMatches(tc.stored, tc.input); got != tc.match {
			t.Fatalf("login match mismatch: got %v", got)
		}
	}
}
