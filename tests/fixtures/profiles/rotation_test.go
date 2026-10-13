package profiles

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestRealRotationCheckpointAndCounters(t *testing.T) {
	ctx := context.Background()
	o, c := profileOptions(t)
	runtime, e := bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := runtime.Close(); e != nil {
			t.Error(e)
		}
	}()
	path := o.SecretsDir + "/rotation.json"
	rotation, e := openRotation(ctx, runtime, c, path, "project")
	if e != nil {
		t.Fatal(e)
	}
	initial, e := rotation.Facts(ctx)
	if e != nil {
		t.Fatal(e)
	}
	published, e := rotation.PublishNext(ctx)
	if e != nil || published.ActiveKID != initial.ActiveKID || published.NextKID == nil {
		t.Fatal(e)
	}
	state := c.Read()
	if code := c.Set(state.InstanceID, state.Generation, c.Now().Add(59*time.Second).Format(time.RFC3339Nano)); code != "" {
		t.Fatal(code)
	}
	overlap, e := rotation.ActivateNext(ctx)
	if e != nil || overlap.Result != "KeyOverlap" {
		t.Fatal(e)
	}
	issued, e := runtime.Signer.SignAnonymous(ctx, c.Now())
	if e != nil {
		t.Fatal(e)
	}
	state = c.Read()
	if code := c.Set(state.InstanceID, state.Generation, c.Now().Add(time.Second).Format(time.RFC3339Nano)); code != "" {
		t.Fatal(code)
	}
	activated, e := rotation.ActivateNext(ctx)
	if e != nil || activated.PreviousKID == nil || *activated.PreviousKID != initial.ActiveKID {
		t.Fatal(e)
	}
	keys, e := runtime.Signer.JWKS(ctx)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(issued.Token, ".")
	signature, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		t.Fatal(e)
	}
	public, e := base64.RawURLEncoding.DecodeString(keys.Keys[1].X)
	if e != nil || !ed25519.Verify(ed25519.PublicKey(public), []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("real old signature", e)
	}
	keysByCaller := map[string]string{"gateway": strings.Repeat("a", 64), "serving": strings.Repeat("b", 64)}
	handler, e := runtime.Handler(keysByCaller)
	if e != nil {
		t.Fatal(e)
	}
	counted := rotation.CountRequests(handler, keysByCaller)
	req := httptest.NewRequest("GET", "/internal/auth/v1/jwks", nil)
	req.Header.Set("X-Umir-Service-Key", keysByCaller["serving"])
	w := httptest.NewRecorder()
	counted.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	before, e := rotation.Facts(ctx)
	if e != nil || before.JWKSRequests.Serving != 1 {
		t.Fatal("network counter", e)
	}
	restored, e := openRotation(ctx, runtime, c, path, "project")
	if e != nil {
		t.Fatal(e)
	}
	after, e := restored.Facts(ctx)
	if e != nil || after.PreviousKID == nil || *after.PreviousKID != *before.PreviousKID || *after.LastIssuedAt != *before.LastIssuedAt || *after.RetainUntil != *before.RetainUntil {
		t.Fatal("lost retirement checkpoint", e)
	}
	if _, e = restored.PublishNext(ctx); e == nil {
		t.Fatal("second cycle allowed")
	}
	state = c.Read()
	if code := c.Set(state.InstanceID, state.Generation, c.Now().Add(59*time.Second).Format(time.RFC3339Nano)); code != "" {
		t.Fatal(code)
	}
	final, e := restored.Facts(ctx)
	if e != nil || final.PreviousKID != nil {
		t.Fatal("old key retained after expiry", e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if e = restored.Checkpoint(cancelled); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
