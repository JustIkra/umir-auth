package bootstrap_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/adapters/httpapi"
)

func TestAnonymousTokenIsRealEd25519AndCannotBecomeService(t *testing.T) {
	ctx := context.Background()
	o := options(t)
	r, e := bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e = r.Close(); e != nil {
			t.Error(e)
		}
	}()
	h, e := httpapi.New(httpapi.Options{Accounts: r.Accounts, Signer: r.Signer, Clock: o.Clock, Preauth: r.Preauth, ServiceKeys: o.ServiceKeys})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	req, e := http.NewRequestWithContext(ctx, "POST", server.URL+"/internal/auth/v1/anonymous-feedback-token", strings.NewReader(`{"operation":"feedback.anonymous.submit"}`))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("X-Umir-Service-Key", o.ServiceKeys["gateway"])
	req.Header.Set("Content-Type", "application/json")
	res, e := server.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(res.Body)
	ce := res.Body.Close()
	if e != nil || ce != nil {
		t.Fatal(e, ce)
	}
	if res.StatusCode != 200 {
		t.Fatalf("real anonymous signer unavailable: %d", res.StatusCode)
	}
	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expiresAt"`
	}
	if json.Unmarshal(b, &result) != nil {
		t.Fatal("invalid token response")
	}
	parts := strings.Split(result.Token, ".")
	keys, e := r.Signer.JWKS(ctx)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := base64.RawURLEncoding.DecodeString(keys.Keys[0].X)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("fake signature")
	}
	body, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		t.Fatal(e)
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(body, &claims) != nil || string(claims["kind"]) != `"anonymous"` || claims["tenant_id"] != nil {
		t.Fatal("broader anonymous authority")
	}
}
