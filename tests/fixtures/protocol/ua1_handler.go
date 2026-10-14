package protocol

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"
)

type UA1Handler struct {
	opts  HandlerOptions
	mu    sync.Mutex
	slots chan struct{}
	cache map[string]*cachedResponse
}

func NewUA1Handler(opts HandlerOptions) (*UA1Handler, error) {
	if !projectPattern.MatchString(opts.Project) || !digestPattern.MatchString(opts.Credential) || !digestPattern.MatchString(opts.BinarySHA256) || !digestPattern.MatchString(opts.ConfigSHA256) || opts.Clock == nil || opts.Store == nil || opts.Ready == nil {
		return nil, errors.New("invalid UA1 control dependencies")
	}
	if _, err := compileUA1Schemas(); err != nil {
		return nil, err
	}
	return &UA1Handler{opts: opts, slots: make(chan struct{}, 8), cache: map[string]*cachedResponse{}}, nil
}

func (h *UA1Handler) identity(clock ClockState) UA1Identity {
	return UA1Identity{FixtureID: clock.FixtureID, InstanceID: clock.InstanceID, ClockGeneration: clock.Generation, BinarySHA256: h.opts.BinarySHA256, ConfigSHA256: h.opts.ConfigSHA256}
}

func (h *UA1Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := UUID()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	input := UA1Request{RequestID: id}
	fail := func(code string) { h.failure(w, input.RequestID, code) }
	if r.Method != http.MethodPost || r.URL.Path != UA1Path || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail("InvalidRequest")
		return
	}
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 || subtle.ConstantTimeCompare([]byte(auth[0]), []byte("Bearer "+h.opts.Credential)) != 1 {
		fail("Unauthenticated")
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		fail("CapacityExceeded")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	contentType := r.Header.Values("Content-Type")
	if len(contentType) != 1 {
		fail("InvalidRequest")
		return
	}
	content, _, err := mime.ParseMediaType(contentType[0])
	if err != nil || content != "application/json" {
		fail("InvalidRequest")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequest))
	if err != nil || validateUA1("Request", data) != nil || json.Unmarshal(data, &input) != nil {
		fail("InvalidRequest")
		return
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		fail("InvalidRequest")
		return
	}
	h.mu.Lock()
	if prior := h.cache[input.RequestID]; prior != nil {
		h.mu.Unlock()
		if !bytes.Equal(prior.canonical, canonical) {
			fail("CorrelationConflict")
			return
		}
		select {
		case <-prior.done:
			h.write(w, prior.body, prior.status)
		case <-ctx.Done():
			fail("WaitExpired")
		}
		return
	}
	if len(h.cache) == 256 {
		h.mu.Unlock()
		fail("CapacityExceeded")
		return
	}
	entry := &cachedResponse{canonical: canonical, done: make(chan struct{})}
	h.cache[input.RequestID] = entry
	h.mu.Unlock()
	defer close(entry.done)
	code := ""
	var response UA1Response
	clock := h.opts.Clock.Read()
	actual := h.identity(clock)
	if input.Project != h.opts.Project {
		code = "WrongProject"
	} else if input.BindingSHA256 != UA1BindingSHA256 || input.Expected.FixtureID != actual.FixtureID || input.Expected.BinarySHA256 != actual.BinarySHA256 || input.Expected.ConfigSHA256 != actual.ConfigSHA256 {
		code = "IdentityConflict"
	} else if input.Expected.InstanceID != actual.InstanceID || input.Expected.ClockGeneration != actual.ClockGeneration {
		code = "ClockConflict"
	} else if !clock.Healthy || !h.opts.Ready(ctx) {
		code = "NotReady"
	} else {
		response, code = h.discover(ctx, input)
	}
	if ctx.Err() != nil {
		code = "WaitExpired"
	}
	entry.status = http.StatusOK
	if code == "" {
		entry.body, err = json.Marshal(response)
		if err != nil || len(entry.body) > MaxResponse || validateUA1("Response", entry.body) != nil {
			code = "CapacityExceeded"
		}
	}
	if code != "" {
		entry.body, entry.status = h.errorBytes(input.RequestID, code)
	}
	h.write(w, entry.body, entry.status)
}

func (h *UA1Handler) errorBytes(id, code string) ([]byte, int) {
	status := statusFor(code)
	if code == "IdentityConflict" {
		status = http.StatusConflict
	}
	value := ua1Error{Version: 1, Supplement: UA1Supplement, BindingSHA256: UA1BindingSHA256, Project: h.opts.Project, RequestID: id, Owner: "auth", Error: Fault{Code: code, Effect: "none", Retryable: code == "NotReady" || code == "WaitExpired"}}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, http.StatusServiceUnavailable
	}
	return data, status
}

func (h *UA1Handler) failure(w http.ResponseWriter, id, code string) {
	data, status := h.errorBytes(id, code)
	h.write(w, data, status)
}

func (h *UA1Handler) write(w http.ResponseWriter, data []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		return
	}
}
