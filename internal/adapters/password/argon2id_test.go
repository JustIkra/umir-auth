package password_test

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/internal/adapters/password"
)

func TestArgon2PolicyAndExactPassword(t *testing.T) {
	h, err := password.New(password.Baseline, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := h.Hash(" password ")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Check(encoded); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		password string
		want     bool
	}{{" password ", true}, {"password", false}, {" Password ", false}} {
		got, err := h.Verify(tc.password, encoded)
		if err != nil || got != tc.want {
			t.Fatalf("exact verification=%v error=%v", got, err)
		}
	}
	for _, bad := range []string{strings.Replace(encoded, "m=19456", "m=1024", 1), strings.Replace(encoded, "v=19", "v=16", 1), strings.Replace(encoded, "p=1", "p=01", 1), encoded + "$trailing"} {
		if _, err := h.Verify(" password ", bad); err == nil {
			t.Fatal("malformed policy accepted")
		}
	}
}
func TestSelectedPolicy(t *testing.T) {
	h, err := password.New(password.Selected, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := h.Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(encoded, "m=65536,t=2,p=1") {
		t.Fatal("selected PHC cost changed")
	}
	if _, err := password.New(password.Params{MemoryKiB: 1024, Iterations: 2, Parallelism: 1}, rand.Reader); err == nil {
		t.Fatal("below-baseline cost allowed")
	}
}
