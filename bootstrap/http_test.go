package bootstrap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/adapters/httpapi"
)

func TestPrivateListenerAuthorizationCSRFAndRealSession(t *testing.T) {
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
	call := func(method, path, key, body string, headers map[string]string) (int, map[string]json.RawMessage) {
		t.Helper()
		req, e := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		if key != "" {
			req.Header.Set("X-Umir-Service-Key", key)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(res.Body)
		ce := res.Body.Close()
		if e != nil || ce != nil {
			t.Fatal(e, ce)
		}
		var out map[string]json.RawMessage
		if len(bytes.TrimSpace(b)) > 0 {
			if e := json.Unmarshal(b, &out); e != nil {
				t.Fatal("non-JSON private response")
			}
		}
		return res.StatusCode, out
	}
	status, _ := call("GET", "/internal/auth/v1/jwks", "", "", nil)
	if status != 401 {
		t.Fatalf("unauthenticated private route: %d", status)
	}
	status, keys := call("GET", "/internal/auth/v1/jwks", o.ServiceKeys["serving"], "", nil)
	if status != 200 || bytes.Contains(keys["keys"], []byte("Private")) {
		t.Fatalf("Serving discovery failed: %d", status)
	}
	status, _ = call("GET", "/internal/auth/v1/public/csrf", o.ServiceKeys["serving"], "", nil)
	if status != 403 {
		t.Fatalf("Serving used Gateway facade: %d", status)
	}
	status, pre := call("GET", "/internal/auth/v1/public/csrf", o.ServiceKeys["gateway"], "", nil)
	if status != 200 {
		t.Fatal(status)
	}
	var token, csrf string
	if json.Unmarshal(pre["preauthToken"], &token) != nil || json.Unmarshal(pre["csrfToken"], &csrf) != nil {
		t.Fatal("missing real preauth")
	}
	body := `{"login":"e2e.initial","password":"0123456789abcdef0123456789abcdef","rememberMe":false,"commandID":"fixture-login-1"}`
	status, _ = call("POST", "/internal/auth/v1/public/session", o.ServiceKeys["gateway"], body, map[string]string{"X-Umir-Preauth": token})
	if status != 403 {
		t.Fatalf("login without CSRF: %d", status)
	}
	headers := map[string]string{"X-Umir-Preauth": token, "X-Umir-CSRF-Token": csrf}
	status, session := call("POST", "/internal/auth/v1/public/session", o.ServiceKeys["gateway"], body, headers)
	if status != 200 || len(session["view"]) == 0 {
		t.Fatalf("real login: %d code=%s", status, session["code"])
	}
	status, replay := call("POST", "/internal/auth/v1/public/session", o.ServiceKeys["gateway"], body, headers)
	if status != 200 || !bytes.Equal(session["sessionToken"], replay["sessionToken"]) {
		t.Fatal("login replay changed token")
	}
	status, _ = call("POST", "/internal/auth/v1/public/session", o.ServiceKeys["gateway"], `{"login":"e2e.initial","login":"other","password":"x","commandID":"x"}`, headers)
	if status != 400 {
		t.Fatalf("duplicate JSON accepted: %d", status)
	}
}
