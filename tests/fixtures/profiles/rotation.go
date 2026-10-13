package profiles

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/tests/fixtures/protocol"
)

type RotationFacts = protocol.ProfileRotation
type rotationCheckpoint struct {
	State          jwt.KeyState
	Clock          protocol.ProfileClock
	Project        string
	Contract       string
	Published      bool
	Activated      bool
	PublishedAt    *string
	RetiringIssued time.Time
}
type Rotation struct {
	mu         sync.Mutex
	signer     *jwt.Signer
	clock      *protocol.Clock
	path       string
	project    string
	checkpoint rotationCheckpoint
	counts     struct {
		Gateway   int `json:"gateway"`
		Warehouse int `json:"warehouse"`
		Serving   int `json:"serving"`
	}
}

func OpenRotation(ctx context.Context, runtime *bootstrap.Runtime, clock *protocol.Clock) (*Rotation, error) {
	return openRotation(ctx, runtime, clock, ownerDir+"/secrets/rotation.json", "")
}
func openRotation(ctx context.Context, r *bootstrap.Runtime, c *protocol.Clock, path, project string) (*Rotation, error) {
	checkpoint := rotationCheckpoint{Contract: protocol.ProfileIdentity, Project: project}
	if _, e := os.Lstat(path); e == nil {
		if e = readPrivate(path, &checkpoint); e != nil {
			return nil, e
		}
		if checkpoint.Contract != protocol.ProfileIdentity || checkpoint.Project != project || checkpoint.Clock.Instant != c.Read().Instant || checkpoint.Clock.Generation != c.Read().Generation {
			return nil, errors.New("rotation binding mismatch")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	} else {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		kid, e := protocol.UUID()
		if e != nil {
			return nil, e
		}
		checkpoint.State.Active = jwt.SigningKey{KID: kid, PrivateKey: key}
	}
	state := checkpoint.State
	s, e := jwt.New(jwt.Options{Clock: c, IDs: r.AccountOptions.IDs, Active: state.Active, ActiveLastIssued: state.ActiveLastIssued, Next: state.Next, Previous: state.Previous})
	if e != nil {
		return nil, e
	}
	if checkpoint.Activated && state.Previous != nil && !checkpoint.RetiringIssued.IsZero() && !state.Previous.RetainUntil.Equal(checkpoint.RetiringIssued.Add(time.Minute)) {
		return nil, errors.New("retention mismatch")
	}
	r.Signer = s
	r.AccountOptions.Issuer = s
	r.Accounts, e = application.NewAccounts(ctx, r.AccountOptions)
	if e != nil {
		return nil, e
	}
	out := &Rotation{signer: s, clock: c, path: path, project: project, checkpoint: checkpoint}
	if e = out.Checkpoint(ctx); e != nil {
		return nil, e
	}
	return out, nil
}
func (r *Rotation) PublishNext(ctx context.Context) (RotationFacts, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.checkpoint.Published || r.checkpoint.Activated {
		return RotationFacts{}, errors.New("rotation already published")
	}
	if e := ctx.Err(); e != nil {
		return RotationFacts{}, e
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return RotationFacts{}, e
	}
	id, e := protocol.UUID()
	if e != nil {
		return RotationFacts{}, e
	}
	if e = r.signer.PublishNext(jwt.SigningKey{KID: id, PrivateKey: key}); e != nil {
		return RotationFacts{}, e
	}
	r.checkpoint.Published = true
	at := r.clock.Now().Format(time.RFC3339Nano)
	r.checkpoint.PublishedAt = &at
	if e = r.checkpointLocked(ctx); e != nil {
		return RotationFacts{}, e
	}
	return r.factsLocked(ctx, "published")
}
func (r *Rotation) ActivateNext(ctx context.Context) (RotationFacts, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.checkpoint.Activated || !r.checkpoint.Published {
		return RotationFacts{}, errors.New("unsupported activation")
	}
	if e := ctx.Err(); e != nil {
		return RotationFacts{}, e
	}
	state, e := r.signer.Snapshot(ctx)
	if e != nil {
		return RotationFacts{}, e
	}
	if e = r.signer.ActivateNext(); errors.Is(e, jwt.ErrKeyOverlap) {
		return r.factsLocked(ctx, "KeyOverlap")
	} else if e != nil {
		return RotationFacts{}, e
	}
	r.checkpoint.Activated = true
	r.checkpoint.RetiringIssued = state.ActiveLastIssued
	if e = r.checkpointLocked(ctx); e != nil {
		return RotationFacts{}, e
	}
	return r.factsLocked(ctx, "activated")
}
func (r *Rotation) Checkpoint(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkpointLocked(ctx)
}
func (r *Rotation) checkpointLocked(ctx context.Context) error {
	s, e := r.signer.Snapshot(ctx)
	if e != nil {
		return e
	}
	r.checkpoint.State = s
	r.checkpoint.Clock = protocol.ProfileClockRead(r.clock)
	if !s.PreviousLastIssued.IsZero() {
		r.checkpoint.RetiringIssued = s.PreviousLastIssued
	}
	return writePrivate(r.path, r.checkpoint, false)
}
func (r *Rotation) Facts(ctx context.Context) (RotationFacts, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.factsLocked(ctx, "observed")
}
func timePointer(at time.Time) *string {
	if at.IsZero() {
		return nil
	}
	s := at.Format(time.RFC3339Nano)
	return &s
}
func (r *Rotation) factsLocked(ctx context.Context, result string) (RotationFacts, error) {
	s, e := r.signer.Snapshot(ctx)
	if e != nil {
		return RotationFacts{}, e
	}
	keys, e := r.signer.JWKS(ctx)
	if e != nil {
		return RotationFacts{}, e
	}
	out := RotationFacts{ActiveKID: s.Active.KID, PublishedAt: r.checkpoint.PublishedAt, LastIssuedAt: timePointer(s.ActiveLastIssued), JWKSRequests: r.counts, Result: result, JWKSKIDs: nil}
	if s.Next != nil {
		out.NextKID = &s.Next.Key.KID
	}
	if s.Previous != nil {
		out.PreviousKID = &s.Previous.Key.KID
		out.RetainUntil = timePointer(s.Previous.RetainUntil)
		at := s.PreviousLastIssued
		if at.IsZero() {
			at = r.checkpoint.RetiringIssued
		}
		out.LastIssuedAt = timePointer(at)
	}
	for _, k := range keys.Keys {
		out.JWKSKIDs = append(out.JWKSKIDs, k.KID)
	}
	return out, nil
}
func (r *Rotation) CountRequests(next http.Handler, keys map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" && req.URL.Path == "/internal/auth/v1/jwks" && req.URL.RawQuery == "" && !req.URL.ForceQuery && len(req.Header.Values("X-Umir-Service-Key")) == 1 {
			r.mu.Lock()
			for name, key := range keys {
				if subtle.ConstantTimeCompare([]byte(key), []byte(req.Header.Get("X-Umir-Service-Key"))) == 1 {
					switch name {
					case "gateway":
						r.counts.Gateway++
					case "warehouse":
						r.counts.Warehouse++
					case "serving":
						r.counts.Serving++
					}
				}
			}
			r.mu.Unlock()
		}
		next.ServeHTTP(w, req)
	})
}
func RestoreClock(selector, project string, c *protocol.Clock) (*protocol.Clock, error) {
	path := filepath.Join(ownerDir, "profile-state.json")
	if selector == "auth-rotation" {
		path = ownerDir + "/secrets/rotation.json"
		if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
			return c, nil
		} else if e != nil {
			return nil, e
		}
		var cp rotationCheckpoint
		if e := readPrivate(path, &cp); errors.Is(e, os.ErrNotExist) {
			return c, nil
		} else if e != nil {
			return nil, e
		}
		if cp.Project != project || cp.Contract != protocol.ProfileIdentity {
			return nil, errors.New("clock binding")
		}
		s := c.Read()
		return protocol.NewClock(s.FixtureID, s.InstanceID, cp.Clock.Instant, cp.Clock.Generation)
	}
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return c, nil
	} else if e != nil {
		return nil, e
	}
	var m storageMetadata
	if e := readPrivate(path, &m); errors.Is(e, os.ErrNotExist) {
		return c, nil
	} else if e != nil {
		return nil, e
	}
	if m.Profile != selector || m.Project != project || m.Contract != protocol.ProfileIdentity {
		return nil, errors.New("clock binding")
	}
	s := c.Read()
	return protocol.NewClock(s.FixtureID, s.InstanceID, m.Clock.Instant, m.Clock.Generation)
}
