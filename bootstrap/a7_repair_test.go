package bootstrap_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/application"
)

func TestA7RepairMissingStateWithRetainedSecretsNeverReseeds(t *testing.T) {
	ctx := context.Background()
	o := options(t)
	r, e := bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	s, e := r.Accounts.Login(ctx, application.LoginInput{Login: o.Initial.Login, Password: o.Password})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Accounts.UpdateDisplayName(ctx, s.Token, "Retained Changed Profile"); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(o.StateFile); e != nil {
		t.Fatal(e)
	}
	first, e := bootstrap.Open(ctx, o)
	if e == nil {
		if closeErr := first.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("first restart admitted missing authority")
	}
	second, e := bootstrap.Open(ctx, o)
	if e == nil {
		defer func() {
			if closeErr := second.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}()
		v, loadErr := second.Store.Load(ctx)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		t.Fatalf("second restart admitted silently reseeded authority: initialized=%v users=%d sessions=%d profileReset=%v", second.Initialized, len(v.Snapshot().Users), len(v.Snapshot().Sessions), v.Snapshot().Users[0].DisplayName == o.Initial.DisplayName)
	}
}

func TestA7RepairPartialOriginalBindingMetadataFailsClosed(t *testing.T) {
	ctx := context.Background()
	o := options(t)
	r, e := bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	secretPath := filepath.Join(o.SecretsDir, "owner.json")
	b, e := os.ReadFile(secretPath)
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(b, &fields); e != nil {
		t.Fatal(e)
	}
	delete(fields, "initial")
	b, e = json.Marshal(fields)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(secretPath, b, 0600); e != nil {
		t.Fatal(e)
	}
	clear(b)
	r, e = bootstrap.Open(ctx, o)
	if e == nil {
		defer func() {
			if closeErr := r.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}()
		t.Fatalf("partial owner secrets admitted: ready=%v bindingPresent=%v", r.Ready(ctx) == nil, r.BindingSHA256 != "")
	}
}

func TestA7RepairInitialSecretDirectorySymlinkFailsClosed(t *testing.T) {
	ctx := context.Background()
	o := options(t)
	destination := filepath.Join(filepath.Dir(o.StateFile), "destination")
	if e := os.Mkdir(destination, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(destination, o.SecretsDir); e != nil {
		t.Fatal(e)
	}
	r, e := bootstrap.Open(ctx, o)
	if e == nil {
		defer func() {
			if closeErr := r.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}()
		_, written := os.Stat(filepath.Join(destination, "owner.json"))
		t.Fatalf("bootstrap admitted secret directory symlink and wrote owner secrets: written=%v", written == nil)
	}
}

func TestA7RepairUnsafeInitialSecretPathsNeverWriteAuthority(t *testing.T) {
	for _, kind := range []string{"directory-symlink", "parent-symlink", "public-directory"} {
		t.Run(kind, func(t *testing.T) {
			o := options(t)
			target := filepath.Join(filepath.Dir(o.StateFile), "target")
			if e := os.Mkdir(target, 0700); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "directory-symlink":
				if e := os.Symlink(target, o.SecretsDir); e != nil {
					t.Fatal(e)
				}
			case "parent-symlink":
				link := filepath.Join(filepath.Dir(o.StateFile), "linked")
				if e := os.Symlink(target, link); e != nil {
					t.Fatal(e)
				}
				o.SecretsDir = filepath.Join(link, "nested")
			case "public-directory":
				if e := os.Mkdir(o.SecretsDir, 0755); e != nil {
					t.Fatal(e)
				}
			}
			r, e := bootstrap.Open(context.Background(), o)
			if e == nil {
				if closeErr := r.Close(); closeErr != nil {
					t.Error(closeErr)
				}
				t.Fatal("unsafe secret creation path admitted")
			}
			if _, e = os.Lstat(o.StateFile); !os.IsNotExist(e) {
				t.Fatal("unsafe secret path modified authority before admission")
			}
			if _, e = os.Lstat(filepath.Join(target, "owner.json")); !os.IsNotExist(e) {
				t.Fatal("owner secrets written through unsafe path")
			}
		})
	}
}

func TestA7RepairOriginalProfileMustMatchRetainedBinding(t *testing.T) {
	o := options(t)
	ctx := context.Background()
	r, e := bootstrap.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(o.SecretsDir, "owner.json")
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(b)
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(b, &fields); e != nil {
		t.Fatal(e)
	}
	initial := *o.Initial
	initial.DisplayName = "Changed Original Metadata"
	fields["initial"], e = json.Marshal(initial)
	if e != nil {
		t.Fatal(e)
	}
	changed, e := json.Marshal(fields)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(changed)
	if e = os.WriteFile(p, changed, 0600); e != nil {
		t.Fatal(e)
	}
	r, e = bootstrap.Open(ctx, o)
	if e == nil {
		if closeErr := r.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("modified original metadata admitted under unchanged binding")
	}
}
