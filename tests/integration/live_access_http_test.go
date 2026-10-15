package integration_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/httpapi"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestFINLiveAccessHTTPIsReadOnlyAndScoped(t *testing.T) {
	f, signer := a5Setup(t)
	preauth, err := httpapi.NewPreauth([]byte(strings.Repeat("k", 32)), f.opts.Clock)
	if err != nil {
		t.Fatal(err)
	}
	gatewayKey, servingKey := strings.Repeat("a", 64), strings.Repeat("b", 64)
	h, err := httpapi.New(httpapi.Options{Accounts: f.accounts, Signer: signer, Clock: f.opts.Clock, Preauth: preauth, ServiceKeys: map[string]string{"gateway": gatewayKey, "serving": servingKey}})
	if err != nil {
		t.Fatal(err)
	}
	call := func(token string, restaurant domain.EntityID, operation, key string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]string{"sessionToken": token, "restaurantID": string(restaurant), "operation": operation})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/internal/auth/v1/access-check", bytes.NewReader(body))
		r.Header.Set("X-Umir-Service-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	physical, ok := f.opts.Clock.(*clock)
	if !ok {
		t.Fatal("unexpected test clock")
	}
	physical.advance(5 * time.Minute)
	before := f.snapshot(t)
	for _, tc := range []struct {
		name, token string
		restaurant  domain.EntityID
	}{
		{"admin", f.owner.Token, f.r1},
		{"warehouse", f.worker.Token, f.r1},
		{"waiter", f.worker.Token, f.r2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := f.accounts.RestaurantAccess(ctx, tc.token, tc.restaurant)
			if err != nil {
				t.Fatal(err)
			}
			w := call(tc.token, tc.restaurant, "live", gatewayKey)
			var got domain.RestaurantAccess
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("live decision = %d %s; want current restaurant permissions", w.Code, w.Body)
			}
			if w.Header().Get("Cache-Control") != "no-store" || bytes.Contains(w.Body.Bytes(), []byte(`"token"`)) || bytes.Contains(w.Body.Bytes(), []byte(`"csrfToken"`)) {
				t.Fatal("live decision exposed authentication material or was cacheable")
			}
		})
	}
	for _, tc := range []struct {
		name, token, operation, key string
		restaurant                  domain.EntityID
	}{
		{"other organization", f.second.Token, "live", gatewayKey, f.r3},
		{"wrong caller", f.worker.Token, "live", servingKey, f.r2},
		{"unknown operation", f.worker.Token, "unknown", gatewayKey, f.r2},
		{"waiter stock", f.worker.Token, "inventory", gatewayKey, f.r2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := call(tc.token, tc.restaurant, tc.operation, tc.key); w.Code != http.StatusForbidden {
				t.Fatalf("denied live scope/action = %d %s", w.Code, w.Body)
			}
		})
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("access checks changed authority or session deadlines")
	}
	if _, ok := application.UserTokenPolicy("live"); ok {
		t.Fatal("live check introduced a bearer-token policy")
	}
	if _, err := f.accounts.AuthorizeToken(ctx, application.AuthorizationInput{SessionToken: f.worker.Token, RestaurantID: f.r2, Operation: "live", Audiences: []string{"umir-warehouse"}, Activity: "background"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("live minted a user token: %v", err)
	}
	if _, err := f.accounts.RevokeAssignment(ctx, f.owner.Token, f.owner.CSRFToken, f.org, f.employee, uid(66), application.RevokeAssignmentInput{CommandID: "fin-live-revoke", ExpectedAssignmentVersion: "1"}); err != nil {
		t.Fatal(err)
	}
	if w := call(f.worker.Token, f.r2, "live", gatewayKey); w.Code != http.StatusForbidden {
		t.Fatalf("revoked restaurant still admitted: %d %s", w.Code, w.Body)
	}
	if w := call(f.worker.Token, f.r1, "live", gatewayKey); w.Code != http.StatusOK {
		t.Fatalf("independent assignment lost live access: %d %s", w.Code, w.Body)
	}
	physical.advance(31 * time.Minute)
	if w := call(f.worker.Token, f.r1, "live", gatewayKey); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired session still admitted: %d %s", w.Code, w.Body)
	}
}
