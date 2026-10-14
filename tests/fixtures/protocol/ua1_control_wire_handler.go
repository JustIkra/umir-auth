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

type UA1ControlWireHandler struct {
	opts     HandlerOptions
	controls *UA1MailControls
	mu       sync.Mutex
	slots    chan struct{}
	cache    map[string]*cachedResponse
}

func NewUA1ControlWireHandler(opts HandlerOptions, controls *UA1MailControls) (*UA1ControlWireHandler, error) {
	if controls == nil || opts.Clock == nil || opts.Ready == nil || opts.Project != controls.opts.Project || opts.Clock != controls.opts.Clock || opts.BinarySHA256 != controls.opts.BinarySHA256 || opts.ConfigSHA256 != controls.opts.ConfigSHA256 || !digestPattern.MatchString(opts.Credential) {
		return nil, errors.New("invalid UA1 wire dependencies")
	}
	if _, err := compileUA1ControlWire(); err != nil {
		return nil, err
	}
	return &UA1ControlWireHandler{opts: opts, controls: controls, slots: make(chan struct{}, 8), cache: map[string]*cachedResponse{}}, nil
}

func (h *UA1ControlWireHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := UUID()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	input := UA1ControlWireRequest{RequestID: id, Action: "control.read"}
	fail := func(code string) { body, status := h.failure(input, code, "none"); h.write(w, body, status) }
	if r.Method != http.MethodPost || r.URL.Path != UA1ControlWirePath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
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
	types := r.Header.Values("Content-Type")
	if len(types) != 1 {
		fail("InvalidRequest")
		return
	}
	media, _, err := mime.ParseMediaType(types[0])
	if err != nil || media != "application/json" {
		fail("InvalidRequest")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequest))
	if err != nil || validateUA1ControlWire("Request", data) != nil || json.Unmarshal(data, &input) != nil {
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
	if len(h.cache) >= 256 {
		h.mu.Unlock()
		fail("CapacityExceeded")
		return
	}
	entry := &cachedResponse{canonical: canonical, done: make(chan struct{})}
	h.cache[input.RequestID] = entry
	h.mu.Unlock()
	defer close(entry.done)
	var record UA1ControlRecord
	code := ""
	if input.Project != h.opts.Project {
		code = "WrongProject"
	} else if input.BindingSHA256 != UA1ControlWireBindingSHA256 {
		code = "IdentityConflict"
	} else if input.Action == "control.arm" && !h.opts.Ready(ctx) {
		code = "NotReady"
	} else {
		switch input.Action {
		case "control.arm":
			record, code = h.controls.Arm(ctx, UA1ControlBindingSHA256, input.Expected, *input.Arm)
		case "control.read":
			record, code = h.controls.Read(ctx, UA1ControlBindingSHA256, input.Expected, input.ControlID)
		case "control.release":
			record, code = h.controls.Release(ctx, UA1ControlBindingSHA256, input.Expected, input.ControlID)
		case "control.cancel":
			record, code = h.controls.Cancel(ctx, UA1ControlBindingSHA256, input.Expected, input.ControlID)
		default:
			code = "InvalidRequest"
		}
	}
	if code != "" {
		effect := "none"
		if code == "ControlConflict" {
			effect = "unknown"
		}
		entry.body, entry.status = h.failure(input, code, effect)
	} else {
		response := h.envelope(input)
		response.Identity = &input.Expected
		response.Record = &record
		entry.body, err = json.Marshal(response)
		entry.status = http.StatusOK
		if err != nil || len(entry.body) > MaxResponse || validateUA1ControlWire("Response", entry.body) != nil {
			entry.body, entry.status = h.failure(input, "ObservationUnavailable", "unknown")
		}
	}
	h.write(w, entry.body, entry.status)
}

func (h *UA1ControlWireHandler) envelope(r UA1ControlWireRequest) UA1ControlWireResponse {
	return UA1ControlWireResponse{Version: 1, Supplement: UA1ControlWireSupplement, BindingSHA256: UA1ControlWireBindingSHA256, Project: h.opts.Project, RequestID: r.RequestID, Owner: "auth", Action: r.Action}
}

func ua1ControlWireStatus(code string) int {
	if code == "IdentityConflict" || code == "ControlConflict" {
		return http.StatusConflict
	}
	if code == "ObservationUnavailable" {
		return http.StatusServiceUnavailable
	}
	return statusFor(code)
}

func (h *UA1ControlWireHandler) failure(r UA1ControlWireRequest, code, effect string) ([]byte, int) {
	response := h.envelope(r)
	response.Error = &Fault{Code: code, Effect: effect, Retryable: code == "WaitExpired" || code == "NotReady"}
	body, err := json.Marshal(response)
	if err != nil {
		return nil, http.StatusServiceUnavailable
	}
	return body, ua1ControlWireStatus(code)
}

func (h *UA1ControlWireHandler) write(w http.ResponseWriter, body []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		return
	}
}
