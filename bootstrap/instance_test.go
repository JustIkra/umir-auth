package bootstrap

import "testing"

func TestInstanceIDComesFromTheConfiguredReplicaName(t *testing.T) {
	if got, err := instanceID("auth-b"); err != nil || got != "auth-b" {
		t.Fatalf("configured name = %q, %v", got, err)
	}
	random, err := instanceID("")
	if err != nil || random == "" {
		t.Fatalf("fallback = %q, %v", random, err)
	}
	other, err := instanceID("")
	if err != nil || other == random {
		t.Fatalf("fallback repeated: %q, %v", other, err)
	}
	for _, bad := range []string{"Auth-A", "auth a", "-auth", "auth\n", "a/b"} {
		if _, err := instanceID(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
