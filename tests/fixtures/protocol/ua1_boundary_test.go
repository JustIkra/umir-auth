package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type ua1ReadCounter struct {
	application.AggregateRepository
	reads int
}

func (r *ua1ReadCounter) Load(ctx context.Context) (domain.ValidatedAggregate, error) {
	r.reads++
	return r.AggregateRepository.Load(ctx)
}

func ua1BoundaryRequest(t *testing.T, clock *Clock) UA1Request {
	t.Helper()
	id, err := UUID()
	if err != nil {
		t.Fatal(err)
	}
	state := clock.Read()
	return UA1Request{Version: 1, Supplement: UA1Supplement, BindingSHA256: ua1TestBinding, Project: "umir-backend-000000000000000000000000", RequestID: id, Owner: "auth", Expected: UA1Identity{FixtureID: state.FixtureID, InstanceID: state.InstanceID, ClockGeneration: state.Generation, BinarySHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64)}, Action: "jobs.discover", Selector: UA1Selector{Kind: "invitation_link", OrgID: "11111111-1111-4111-8111-111111111111", InvitationID: "22222222-2222-4222-8222-222222222222"}}
}

func ua1CallBytes(handler http.Handler, method, path string, data []byte, headers http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header = headers
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	return result
}

func TestUA1ClockChangedDuringReadinessRefusesBeforeStoreRead(t *testing.T) {
	r, clock, _ := liveOwner(t)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	store := &ua1ReadCounter{AggregateRepository: r.Store}
	input := ua1BoundaryRequest(t, clock)
	state := clock.Read()
	handler, err := NewUA1Handler(HandlerOptions{Project: input.Project, Credential: strings.Repeat("a", 64), BinarySHA256: input.Expected.BinarySHA256, ConfigSHA256: input.Expected.ConfigSHA256, Clock: clock, Store: store, Ready: func(context.Context) bool { return clock.Set(state.InstanceID, state.Generation, state.Instant) == "" }})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	response := ua1CallBytes(handler, http.MethodPost, UA1Path, data, http.Header{"Authorization": {"Bearer " + strings.Repeat("a", 64)}, "Content-Type": {"application/json"}})
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "ClockConflict") || store.reads != 0 {
		t.Fatalf("stale identity crossed readiness barrier: status=%d reads=%d", response.Code, store.reads)
	}
}

func TestUA1StrictRequestsAndQualifiedIdentityDenyBeforeRead(t *testing.T) {
	r, clock, _ := liveOwner(t)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	store := &ua1ReadCounter{AggregateRepository: r.Store}
	input := ua1BoundaryRequest(t, clock)
	handler, err := NewUA1Handler(HandlerOptions{Project: input.Project, Credential: strings.Repeat("a", 64), BinarySHA256: input.Expected.BinarySHA256, ConfigSHA256: input.Expected.ConfigSHA256, Clock: clock, Store: store, Ready: func(context.Context) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		code   int
		change func(*UA1Request)
		raw    func([]byte) []byte
	}{
		{name: "foreign-project", code: 403, change: func(v *UA1Request) { v.Project = "umir-backend-000000000000000000000001" }},
		{name: "foreign-fixture", code: 409, change: func(v *UA1Request) { v.Expected.FixtureID = "99999999-9999-4999-8999-999999999999" }},
		{name: "stale-instance", code: 409, change: func(v *UA1Request) { v.Expected.InstanceID = "99999999-9999-4999-8999-999999999999" }},
		{name: "stale-generation", code: 409, change: func(v *UA1Request) { v.Expected.ClockGeneration = "2" }},
		{name: "foreign-binary", code: 409, change: func(v *UA1Request) { v.Expected.BinarySHA256 = strings.Repeat("d", 64) }},
		{name: "foreign-config", code: 409, change: func(v *UA1Request) { v.Expected.ConfigSHA256 = strings.Repeat("d", 64) }},
		{name: "unknown-supplement-binding", code: 409, change: func(v *UA1Request) { v.BindingSHA256 = strings.Repeat("d", 64) }},
		{name: "mixed-kind-selector", code: 400, change: func(v *UA1Request) { v.Selector.ChallengeID = "99999999-9999-4999-8999-999999999999" }},
		{name: "unknown-field", code: 400, raw: func(v []byte) []byte {
			return append(append([]byte{}, v[:len(v)-1]...), []byte(`,"privatePath":"/tmp/foreign"}`)...)
		}},
		{name: "duplicate-field", code: 400, raw: func(v []byte) []byte {
			return bytes.Replace(v, []byte(`"kind":"invitation_link"`), []byte(`"kind":"otp","kind":"invitation_link"`), 1)
		}},
		{name: "trailing-json", code: 400, raw: func(v []byte) []byte { return append(v, []byte(` {}`)...) }},
		{name: "request-byte-limit", code: 400, raw: func(v []byte) []byte { return append(v, bytes.Repeat([]byte(" "), MaxRequest)...) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := ua1BoundaryRequest(t, clock)
			if test.change != nil {
				test.change(&input)
			}
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if test.raw != nil {
				data = test.raw(data)
			}
			response := ua1CallBytes(handler, http.MethodPost, UA1Path, data, http.Header{"Authorization": {"Bearer " + strings.Repeat("a", 64)}, "Content-Type": {"application/json"}})
			if response.Code != test.code || store.reads != 0 {
				t.Fatalf("bad request admitted: status=%d reads=%d", response.Code, store.reads)
			}
			if err := validateUA1("Error", response.Body.Bytes()); err != nil {
				t.Fatal("untyped failure", err)
			}
		})
	}
	for _, path := range []string{UA1Path + "?", UA1Path + "?x=1", UA1Path + "/", "/%75a1-fixtures/v1"} {
		data, err := json.Marshal(ua1BoundaryRequest(t, clock))
		if err != nil {
			t.Fatal(err)
		}
		if response := ua1CallBytes(handler, http.MethodPost, path, data, http.Header{"Authorization": {"Bearer " + strings.Repeat("a", 64)}, "Content-Type": {"application/json"}}); response.Code != 400 || store.reads != 0 {
			t.Fatalf("alternate path reached repository: %s", path)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut} {
		data, err := json.Marshal(ua1BoundaryRequest(t, clock))
		if err != nil {
			t.Fatal(err)
		}
		if response := ua1CallBytes(handler, method, UA1Path, data, http.Header{"Authorization": {"Bearer " + strings.Repeat("a", 64)}, "Content-Type": {"application/json"}}); response.Code != 400 || store.reads != 0 {
			t.Fatalf("forbidden method reached repository: %s", method)
		}
	}
	for _, credentials := range [][]string{nil, {"Bearer " + strings.Repeat("d", 64)}, {"Bearer " + strings.Repeat("a", 64), "Bearer " + strings.Repeat("a", 64)}} {
		data, err := json.Marshal(ua1BoundaryRequest(t, clock))
		if err != nil {
			t.Fatal(err)
		}
		if response := ua1CallBytes(handler, http.MethodPost, UA1Path, data, http.Header{"Authorization": credentials, "Content-Type": {"application/json"}}); response.Code != 401 || store.reads != 0 {
			t.Fatal("invalid credential reached repository")
		}
	}
}

func TestUA1ObservationCacheDoesNotEvictOrReadAfterCapacity(t *testing.T) {
	r, clock, _ := liveOwner(t)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	store := &ua1ReadCounter{AggregateRepository: r.Store}
	input := ua1BoundaryRequest(t, clock)
	handler, err := NewUA1Handler(HandlerOptions{Project: input.Project, Credential: strings.Repeat("a", 64), BinarySHA256: input.Expected.BinarySHA256, ConfigSHA256: input.Expected.ConfigSHA256, Clock: clock, Store: store, Ready: func(context.Context) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	var first []byte
	var firstResponse []byte
	headers := http.Header{"Authorization": {"Bearer " + strings.Repeat("a", 64)}, "Content-Type": {"application/json"}}
	for index := range 256 {
		data, err := json.Marshal(ua1BoundaryRequest(t, clock))
		if err != nil {
			t.Fatal(err)
		}
		response := ua1CallBytes(handler, http.MethodPost, UA1Path, data, headers)
		if response.Code != http.StatusNotFound {
			t.Fatalf("allowed observation %d refused: %d", index, response.Code)
		}
		if index == 0 {
			first = bytes.Clone(data)
			firstResponse = bytes.Clone(response.Body.Bytes())
		}
	}
	data, err := json.Marshal(ua1BoundaryRequest(t, clock))
	if err != nil {
		t.Fatal(err)
	}
	if response := ua1CallBytes(handler, http.MethodPost, UA1Path, data, headers); response.Code != http.StatusRequestEntityTooLarge || store.reads != 256 {
		t.Fatal("observation capacity did not fail before read")
	}
	if response := ua1CallBytes(handler, http.MethodPost, UA1Path, first, headers); response.Code != http.StatusNotFound || !bytes.Equal(response.Body.Bytes(), firstResponse) || store.reads != 256 {
		t.Fatal("capacity evicted or recomputed the original observation")
	}
}
