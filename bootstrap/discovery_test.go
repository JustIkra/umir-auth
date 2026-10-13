package bootstrap_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/bootstrap"
)

func TestFeedbackDiscoveryACL(t *testing.T) {
	o := options(t)
	r, e := bootstrap.Open(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	keys := o.ServiceKeys
	keys["feedback"] = strings.Repeat("d", 64)
	h, e := r.Handler(keys)
	if e != nil {
		t.Fatal(e)
	}
	before, e := r.Store.Load(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/internal/auth/v1/jwks", 200}, {"HEAD", "/internal/auth/v1/jwks", 403},
		{"POST", "/internal/auth/v1/jwks", 403}, {"GET", "/internal/auth/v1/jwks?x=1", 403},
		{"GET", "/internal/auth/v1/jwks?", 403}, {"GET", "/internal/auth/v1/./jwks", 403},
		{"GET", "/internal/auth/v1/jwks/", 403}, {"GET", "/healthz", 403},
		{"GET", "/internal/auth/v1/registry", 403}, {"GET", "/internal/auth/v1/readiness", 403},
		{"POST", "/internal/auth/v1/authorize", 403}, {"POST", "/internal/auth/v1/service-token", 403},
		{"POST", "/internal/auth/v1/anonymous-token", 403}, {"POST", "/internal/auth/v1/public/session", 403},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		req.Header.Set("X-Umir-Service-Key", keys["feedback"])
		req.Header.Set("X-Umir-Caller", "gateway")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != c.status {
			t.Fatalf("%s %s: %d", c.method, c.path, w.Code)
		}
		if c.status == 200 {
			var body struct {
				Keys []map[string]string `json:"keys"`
			}
			if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body.Keys) == 0 {
				t.Fatal("no real JWKS")
			}
			for _, key := range body.Keys {
				if len(key) != 6 || key["d"] != "" {
					t.Fatal("private key material")
				}
			}
		}
	}
	for _, key := range []string{"", strings.Repeat("e", 64)} {
		req := httptest.NewRequest(http.MethodGet, "/internal/auth/v1/jwks", nil)
		if key != "" {
			req.Header.Set("X-Umir-Service-Key", key)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	req := httptest.NewRequest("GET", "/internal/auth/v1/jwks", nil)
	req.Header.Add("X-Umir-Service-Key", keys["feedback"])
	req.Header.Add("X-Umir-Service-Key", keys["gateway"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("duplicate credential admitted")
	}
	after, e := r.Store.Load(context.Background())
	if e != nil || after.Revision() != before.Revision() {
		t.Fatal("denial mutated state", e)
	}
	keys["feedback"] = keys["gateway"]
	if _, e := r.Handler(keys); e == nil {
		t.Fatal("shared credential admitted")
	}
}
