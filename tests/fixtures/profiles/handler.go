package profiles

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

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/tests/fixtures/protocol"
)

type cached struct {
	input  []byte
	body   []byte
	status int
}
type Owner struct {
	mu         sync.Mutex
	binding    protocol.ProfileBinding
	clock      *protocol.Clock
	credential string
	runtime    *bootstrap.Runtime
	catalog    application.TimeZoneCatalog
	rotation   *Rotation
	legacy     *protocol.ProfileAuthLegacy
	writer     *protocol.ProfileWriter
	refused    bool
	phase      Phase
	opened     time.Time
	cache      map[string]cached
}

func NewOwner(cfg protocol.Config, digest, profileDigest, credential string, c *protocol.Clock, catalog application.TimeZoneCatalog) (*Owner, error) {
	binary, e := protocol.BinarySHA()
	if e != nil {
		return nil, e
	}
	return &Owner{binding: protocol.ProfileBinding{Project: cfg.Project, Owner: "auth", InstanceID: c.Read().InstanceID, BinarySHA256: binary, ConfigSHA256: digest, ProfileConfigSHA256: profileDigest, FixtureSHA256: protocol.FixtureSHA256, ProfileContractIdentity: protocol.ProfileIdentity}, clock: c, credential: credential, catalog: catalog, cache: map[string]cached{}, opened: time.Now(), phase: "admitted"}, nil
}
func (o *Owner) Admit(ctx context.Context, selector string, options bootstrap.Options) (*bootstrap.Runtime, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.binding.Profile = selector
	if !protocol.AuthProfile(selector) || len(protocol.FixtureSHA256) != 64 {
		return nil, errors.New("unsupported profile binary")
	}
	var prepared PreparedFacts
	var e error
	if selector != "auth-rotation" {
		prepared, e = prepareStorage(ctx, Profile(selector), o.clock, ownerDir, o.binding.Project, options.Password)
		if e != nil {
			return nil, e
		}
		o.legacy = prepared.Legacy
		if prepared.Reopened {
			o.phase = "reopened"
		}
	}
	var r *bootstrap.Runtime
	if prepared.Imported != nil {
		r, e = bootstrap.OpenImported(ctx, options, *prepared.Imported)
	} else {
		r, e = bootstrap.Open(ctx, options)
	}
	if e != nil {
		if (selector == "auth-corrupt-json" || selector == "auth-unknown-schema" || selector == "auth-invalid-aggregate") && errors.Is(e, application.ErrStorageUnavailable) {
			o.refused = true
			return nil, nil
		}
		return nil, e
	}
	if selector == "auth-corrupt-json" || selector == "auth-unknown-schema" || selector == "auth-invalid-aggregate" {
		return nil, errors.Join(errors.New("refusal admitted"), r.Close())
	}
	o.runtime = r
	return r, nil
}
func (o *Owner) Bind(ctx context.Context, r *bootstrap.Runtime) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.runtime = r
	if o.binding.Profile == "auth-rotation" {
		rotation, e := openRotation(ctx, r, o.clock, ownerDir+"/secrets/rotation.json", o.binding.Project)
		if e != nil {
			return e
		}
		o.rotation = rotation
		return nil
	}
	if o.binding.Profile == "auth-second-writer" {
		writer, e := secondWriter(ctx)
		if e != nil {
			return e
		}
		o.writer = &writer
	}
	return CheckpointStorage(o.clock)
}
func (o *Owner) BindOrdinary(r *bootstrap.Runtime) { o.mu.Lock(); defer o.mu.Unlock(); o.runtime = r }
func (o *Owner) WrapBusiness(h http.Handler, keys map[string]string) http.Handler {
	if o.rotation != nil {
		return o.rotation.CountRequests(h, keys)
	}
	return h
}
func (o *Owner) Checkpoint(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.refused {
		return nil
	}
	if o.rotation != nil {
		return o.rotation.Checkpoint(ctx)
	}
	if o.binding.Profile != "" {
		return CheckpointStorage(o.clock)
	}
	return nil
}
func (o *Owner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, e := protocol.UUID()
	if e != nil {
		w.WriteHeader(503)
		return
	}
	fail := func(code string, status int) {
		o.write(w, protocol.ProfileProfileError{Amendment: protocol.ProfileAmendment, RequestID: id, Error: code}, status)
	}
	if r.Method != "POST" || r.URL.Path != protocol.ProfilePath || r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail("InvalidRequest", 400)
		return
	}
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 || subtle.ConstantTimeCompare([]byte(auth[0]), []byte("Bearer "+o.credential)) != 1 {
		fail("Unauthorized", 401)
		return
	}
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		fail("InvalidRequest", 400)
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if e != nil {
		fail("InvalidRequest", 400)
		return
	}
	catalog := protocol.ValidateProfile("CatalogRequest", body) == nil
	var req protocol.ProfileRequest
	if catalog {
		var c protocol.ProfileCatalogRequest
		if json.Unmarshal(body, &c) != nil {
			fail("InvalidRequest", 400)
			return
		}
		req = protocol.ProfileRequest{Amendment: c.Amendment, Project: c.Project, RequestID: c.RequestID, ExpectedInstanceID: c.ExpectedInstanceID, ExpectedGeneration: c.ExpectedGeneration, Action: c.Action}
	} else if protocol.ValidateProfile("Request", body) != nil || json.Unmarshal(body, &req) != nil {
		fail("InvalidRequest", 400)
		return
	}
	id = req.RequestID
	canonical, e := json.Marshal(req)
	if e != nil {
		fail("InvalidRequest", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	o.mu.Lock()
	defer o.mu.Unlock()
	if req.Project != o.binding.Project || !catalog && req.Profile != o.binding.Profile {
		fail("OwnershipMismatch", 403)
		return
	}
	if prior, ok := o.cache[id]; ok {
		if !bytes.Equal(prior.input, canonical) {
			fail("RequestConflict", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(prior.status)
		if _, e = w.Write(prior.body); e != nil {
			return
		}
		return
	}
	if time.Since(o.opened) > 300*time.Second {
		fail("ProfileExpired", 503)
		return
	}
	if len(o.cache) >= 64 {
		fail("ProfileCapacityExceeded", 413)
		return
	}
	if _, ok := o.clock.ReadExpected(req.ExpectedInstanceID, req.ExpectedGeneration); !ok {
		fail("ClockConflict", 409)
		return
	}
	var result any
	if catalog {
		if o.runtime == nil || o.refused {
			fail("UnsupportedAction", 400)
			return
		}
		report, e := ObserveCatalog(ctx, o.catalog, o.clock)
		if e != nil {
			fail("ProfileAdmissionFailed", 503)
			return
		}
		report.RequestID = id
		report.Project = o.binding.Project
		report.ConfigSHA256 = o.binding.ConfigSHA256
		result = report
	} else {
		if o.refused && req.Action != "report" {
			fail("UnsupportedAction", 400)
			return
		}
		facts := protocol.ProfileFacts{Legacy: o.legacy, Writer: o.writer}
		if o.rotation != nil {
			var rotation RotationFacts
			switch req.Action {
			case "publish-next":
				rotation, e = o.rotation.PublishNext(ctx)
			case "activate-next":
				rotation, e = o.rotation.ActivateNext(ctx)
			case "checkpoint":
				e = o.rotation.Checkpoint(ctx)
				if e == nil {
					rotation, e = o.rotation.Facts(ctx)
				}
			default:
				rotation, e = o.rotation.Facts(ctx)
			}
			if e != nil {
				fail("CheckpointFailed", 503)
				return
			}
			facts.Rotation = &rotation
		} else if o.runtime != nil {
			if req.Action == "checkpoint" {
				e = CheckpointStorage(o.clock)
				if e != nil {
					fail("CheckpointFailed", 503)
					return
				}
			}
			if o.legacy != nil {
				auth, e := ObserveAuth(ctx, o.runtime, o.phase)
				if e != nil {
					fail("ProfileAdmissionFailed", 503)
					return
				}
				facts.Auth = &auth
			}
		}
		report := protocol.ProfileReport{Amendment: protocol.ProfileAmendment, RequestID: id, Binding: o.binding, Clock: protocol.ProfileClockRead(o.clock), Admission: "ready", NormalReady: o.runtime != nil && o.runtime.Ready(ctx) == nil, BusinessHandlerCreated: o.runtime != nil, Facts: facts}
		if o.refused {
			code := "StorageUnavailable"
			report.Admission = "refused"
			report.Error = &code
		}
		if o.writer != nil {
			code := "WriterLocked"
			report.Admission = "contended"
			report.NormalReady = false
			report.Error = &code
		}
		result = report
	}
	b, e := json.Marshal(result)
	schema := "Report"
	if catalog {
		schema = "CatalogReport"
	}
	if e != nil || protocol.ValidateProfile(schema, b) != nil {
		fail("ProfileAdmissionFailed", 503)
		return
	}
	if _, ok := o.clock.ReadExpected(req.ExpectedInstanceID, req.ExpectedGeneration); !ok {
		fail("ClockConflict", 409)
		return
	}
	o.cache[id] = cached{input: canonical, body: b, status: 200}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	if _, e = w.Write(b); e != nil {
		return
	}
}
func (o *Owner) write(w http.ResponseWriter, value any, status int) {
	b, e := json.Marshal(value)
	if e != nil {
		w.WriteHeader(503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, e = w.Write(b); e != nil {
		return
	}
}
