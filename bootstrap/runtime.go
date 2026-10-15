package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/challengesecrets"
	"github.com/JustIkra/umir-auth/internal/adapters/httpapi"
	"github.com/JustIkra/umir-auth/internal/adapters/invitationurl"
	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
	"github.com/JustIkra/umir-auth/internal/adapters/password"
	"github.com/JustIkra/umir-auth/internal/adapters/sessionsecrets"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

var ErrNotReady = errors.New("auth runtime not ready")
var ErrBootstrapConflict = errors.New("bootstrap conflict")

type InitialUser struct {
	UserID            domain.EntityID `json:"userID"`
	Login             string          `json:"login"`
	DisplayName       string          `json:"displayName"`
	CredentialVersion domain.Version  `json:"credentialVersion"`
	Email             string          `json:"email,omitempty"`
}
type Options struct {
	Registration                    application.RegistrationOptions
	InvitationMail                  application.InvitationMailOptions
	StateFile, SecretsDir, Password string
	Initial                         *InitialUser
	Clock                           application.Clock
	TimeZones                       application.TimeZoneCatalog
	Runtimes                        application.RuntimePeers
	ServiceKeys                     map[string]string
}
type Runtime struct {
	Store          *jsonstore.Store
	Accounts       *application.Accounts
	Signer         *jwt.Signer
	Preauth        *httpapi.Preauth
	Initialized    bool
	BindingSHA256  string
	AccountOptions application.AccountOptions
	once           sync.Once
	closeErr       error
	healthMu       sync.Mutex
	workerErr      error
}
type ownerSecrets struct {
	Version                                             int          `json:"version"`
	Initial                                             *InitialUser `json:"initial"`
	Binding                                             string       `json:"binding"`
	SigningSeed, Results, ChallengeKey, ChallengePepper []byte
	SigningKID                                          string
}
type entropy struct{}

func (entropy) NewID() (domain.EntityID, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return domain.EntityID(fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])), nil
}
func (entropy) NewToken() (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
func NewID() (string, error)                                { id, e := (entropy{}).NewID(); return string(id), e }
func Open(ctx context.Context, o Options) (*Runtime, error) { return open(ctx, o, nil) }
func open(ctx context.Context, o Options, imported *domain.ValidatedAggregate) (r *Runtime, err error) {
	if o.Clock == nil || o.TimeZones == nil || o.StateFile == "" || o.SecretsDir == "" {
		return nil, ErrNotReady
	}
	if _, err = o.TimeZones.Ready(); err != nil {
		return nil, ErrNotReady
	}
	hasher, err := password.New(password.Selected, rand.Reader)
	if err != nil {
		return nil, ErrNotReady
	}
	_, statErr := os.Lstat(o.StateFile)
	initialize := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !initialize {
		return nil, ErrNotReady
	}
	if err = admitPrivateDirectory(o.SecretsDir, initialize); err != nil {
		return nil, err
	}
	var store *jsonstore.Store
	if imported != nil && !initialize {
		return nil, ErrBootstrapConflict
	}
	if initialize {
		if _, e := os.Lstat(filepath.Join(o.SecretsDir, "owner.json")); !errors.Is(e, os.ErrNotExist) {
			return nil, ErrNotReady
		}
		if o.Initial == nil || o.Initial.Email != "" || o.Initial.CredentialVersion != "1" {
			return nil, ErrBootstrapConflict
		}
		name, e := application.CanonicalDisplayName(o.Initial.DisplayName)
		if e != nil || name != o.Initial.DisplayName {
			return nil, ErrBootstrapConflict
		}
		var v domain.ValidatedAggregate
		if imported != nil {
			v, err = validateImported(o, *imported, hasher)
			if err != nil {
				return nil, err
			}
		} else {
			if application.CheckPassword(o.Password) != nil {
				return nil, ErrBootstrapConflict
			}
			verifier, e := hasher.Hash(o.Password)
			if e != nil {
				return nil, ErrNotReady
			}
			a := domain.Empty()
			a.Users = append(a.Users, domain.User{UserID: o.Initial.UserID, Login: o.Initial.Login, DisplayName: name, CredentialVersion: o.Initial.CredentialVersion, Verifier: verifier})
			v, e = domain.Validate(a)
			if e != nil {
				return nil, ErrBootstrapConflict
			}
		}
		store, err = jsonstore.Initialize(ctx, o.StateFile, v)
	} else {
		store, err = jsonstore.Open(ctx, o.StateFile)
	}
	if err != nil {
		return nil, errors.Join(ErrNotReady, err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, store.Close())
		}
	}()
	secrets, err := loadSecrets(o, initialize)
	if err != nil {
		return nil, err
	}
	v, err := store.Load(ctx)
	if err != nil {
		return nil, ErrNotReady
	}
	found := false
	for _, u := range v.Snapshot().Users {
		if u.UserID == secrets.Initial.UserID && u.Login == secrets.Initial.Login {
			found = true
		}
	}
	if !found {
		return nil, ErrBootstrapConflict
	}
	results, err := sessionsecrets.New(secrets.Results, rand.Reader)
	if err != nil {
		return nil, ErrNotReady
	}
	challenges, err := challengesecrets.New(secrets.ChallengePepper, secrets.ChallengeKey)
	if err != nil {
		return nil, ErrNotReady
	}
	signer, err := jwt.New(jwt.Options{Clock: o.Clock, IDs: entropy{}, Active: jwt.SigningKey{KID: secrets.SigningKID, PrivateKey: ed25519.NewKeyFromSeed(secrets.SigningSeed)}})
	if err != nil {
		return nil, ErrNotReady
	}
	accountOptions := application.AccountOptions{Repository: store, Passwords: hasher, Clock: o.Clock, IDs: entropy{}, Tokens: entropy{}, Results: results, Challenges: challenges, Issuer: signer, TimeZones: o.TimeZones, Runtimes: o.Runtimes}
	accountOptions.Registration = o.Registration
	accountOptions.InvitationMail = o.InvitationMail
	accountOptions.LinkURLs = invitationurl.Policy{}
	accountOptions.PageClock = physicalPageClock{}
	accountOptions.PageAfter = func(d time.Duration, f func()) application.PageExpiryTimer { return time.AfterFunc(d, f) }
	accounts, err := application.NewAccounts(ctx, accountOptions)
	if err != nil {
		return nil, errors.Join(ErrNotReady, err)
	}
	preauth, err := httpapi.NewPreauth(secrets.Results, o.Clock)
	if err != nil {
		return nil, ErrNotReady
	}
	return &Runtime{AccountOptions: accountOptions, Preauth: preauth, Store: store, Accounts: accounts, Signer: signer, Initialized: initialize, BindingSHA256: secrets.Binding}, nil
}
func loadSecrets(o Options, initialize bool) (ownerSecrets, error) {
	p := filepath.Join(o.SecretsDir, "owner.json")
	var s ownerSecrets
	if initialize {
		if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			return s, ErrNotReady
		}
		kid, e := NewID()
		s.SigningKID = kid
		if e != nil {
			return s, ErrNotReady
		}
		s.Version = 1
		s.Initial = o.Initial
		b, e := json.Marshal(o.Initial)
		if e != nil {
			return s, ErrNotReady
		}
		sum := sha256.Sum256(b)
		s.Binding = hex.EncodeToString(sum[:])
		for _, target := range []*[]byte{&s.SigningSeed, &s.Results, &s.ChallengeKey, &s.ChallengePepper} {
			*target = make([]byte, 32)
			if _, e = rand.Read(*target); e != nil {
				return ownerSecrets{}, ErrNotReady
			}
		}
		b, e = json.Marshal(s)
		if e != nil {
			return s, ErrNotReady
		}
		defer clear(b)
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return s, ErrNotReady
		}
		_, w := f.Write(b)
		e = errors.Join(w, f.Sync(), f.Close())
		if e == nil {
			d, de := os.Open(o.SecretsDir)
			if de != nil {
				return s, ErrNotReady
			}
			e = errors.Join(d.Sync(), d.Close())
		}
		if e != nil {
			return s, ErrNotReady
		}
	} else {
		b, e := ReadPrivateFile(p, 16384)
		if e != nil {
			return s, ErrNotReady
		}
		defer clear(b)
		if e = DecodeStrict(b, &s); e != nil {
			return s, ErrNotReady
		}
	}
	if s.Version != 1 || len(s.SigningSeed) != 32 || len(s.Results) != 32 || len(s.ChallengeKey) != 32 || len(s.ChallengePepper) != 32 {
		return s, ErrNotReady
	}
	if s.Initial == nil || o.Initial == nil || *s.Initial != *o.Initial {
		return s, ErrBootstrapConflict
	}
	b, e := json.Marshal(o.Initial)
	if e != nil {
		return s, ErrNotReady
	}
	sum := sha256.Sum256(b)
	if s.Binding != hex.EncodeToString(sum[:]) {
		return s, ErrBootstrapConflict
	}
	return s, nil
}
func (r *Runtime) Close() error {
	r.once.Do(func() {
		r.Accounts.CloseReadPages()
		r.closeErr = r.Store.Close()
	})
	return r.closeErr
}

type physicalPageClock struct{}

func (physicalPageClock) Now() time.Time { return time.Now() }

func (r *Runtime) failWorker(err error) {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	r.workerErr = err
}
func (r *Runtime) Ready(ctx context.Context) error {
	r.healthMu.Lock()
	err := r.workerErr
	r.healthMu.Unlock()
	if err != nil {
		return application.ErrAuthUnavailable
	}
	return r.Accounts.Ready(ctx)
}
