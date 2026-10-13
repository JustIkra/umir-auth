package challengesecrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func secretFixture(t *testing.T) *ChallengeCrypto {
	t.Helper()
	c, err := New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestCodeSamplingAndEntropyFailure(t *testing.T) {
	c := secretFixture(t)
	c.random = bytes.NewReader([]byte{0xff, 0xff, 0xff, 0, 0, 7})
	code, err := c.NewCode()
	if err != nil || code != "000007" {
		t.Fatal("rejection sampling lost leading zeros")
	}
	if _, err := c.NewCode(); err == nil {
		t.Fatal("missing entropy accepted")
	}
}
func TestSecretsBindPurposeAndRejectTampering(t *testing.T) {
	c := secretFixture(t)
	one, err := c.Seal("code:id:invitation", "000007")
	if err != nil {
		t.Fatal(err)
	}
	if value, err := c.Open("code:id:invitation", one); err != nil || value != "000007" {
		t.Fatal("round trip failed")
	}
	if _, err := c.Open("code:id:login", one); err == nil {
		t.Fatal("purpose substitution accepted")
	}
	data, err := base64.RawURLEncoding.DecodeString(one)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if _, err := c.Open("code:id:invitation", base64.RawURLEncoding.EncodeToString(data)); err == nil {
		t.Fatal("tampering accepted")
	}
	if c.Digest("code", "value") == c.Digest("proof", "value") {
		t.Fatal("digest scopes aliased")
	}
	two, err := c.Seal("code:id:invitation", "000007")
	if err != nil || one == two {
		t.Fatal("nonce reused")
	}
	proof, err := c.NewProof()
	if err != nil || len(proof) != 43 {
		t.Fatal("proof entropy/format failed")
	}
}
func TestSeparateKeysAndUnavailableRandomness(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33} {
		if _, err := New(make([]byte, size), bytes.Repeat([]byte{2}, 32)); err == nil {
			t.Fatal("invalid pepper accepted")
		}
		if _, err := New(bytes.Repeat([]byte{1}, 32), make([]byte, size)); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	if _, err := New(make([]byte, 32), make([]byte, 32)); err == nil {
		t.Fatal("aliased keys accepted")
	}
	c := secretFixture(t)
	c.random = failedRandom{}
	if _, err := c.NewProof(); err == nil {
		t.Fatal("proof entropy failure accepted")
	}
	if _, err := c.Seal("scope", "value"); err == nil {
		t.Fatal("nonce entropy failure accepted")
	}
	if _, err := c.NewID(); err == nil {
		t.Fatal("UUID entropy failure accepted")
	}
}

type failedRandom struct{}

func (failedRandom) Read([]byte) (int, error) { return 0, errors.New("synthetic entropy unavailable") }
