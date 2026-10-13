package bootstrap_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JustIkra/umir-auth/bootstrap"
)

func TestSecretParentSymlinkFailsClosed(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	secret := filepath.Join(dir, "secret")
	if e = os.WriteFile(secret, []byte("synthetic-private-content"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "linked")
	if e = os.Symlink(dir, link); e != nil {
		t.Fatal(e)
	}
	if _, e = bootstrap.ReadPrivateFile(filepath.Join(link, "secret"), 128); e == nil {
		t.Fatal("secret followed a symlinked parent")
	}
}
