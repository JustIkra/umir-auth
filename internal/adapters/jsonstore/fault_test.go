package jsonstore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

var errFault = errors.New("private secret-sentinel failure")

type faultyFile struct {
	file
	stage string
}

func (f faultyFile) Write(p []byte) (int, error) {
	switch f.stage {
	case "write":
		return 0, errFault
	case "partial":
		n, err := f.file.Write(p[:len(p)/2])
		if err != nil {
			return n, err
		}
		return n, nil
	}
	return f.file.Write(p)
}
func (f faultyFile) Sync() error {
	if f.stage == "sync" {
		return errFault
	}
	return f.file.Sync()
}
func (f faultyFile) Close() error {
	err := f.file.Close()
	if f.stage == "close" {
		return errors.Join(err, errFault)
	}
	return err
}
func inject(s *Store, stage string) {
	real := s.files
	switch stage {
	case "create":
		s.files.createTemp = func(string, string) (file, error) { return nil, errFault }
	case "rename-before":
		s.files.rename = func(string, string) error { return errFault }
	case "rename-after":
		s.files.rename = func(a, b string) error {
			if err := real.rename(a, b); err != nil {
				return err
			}
			return errFault
		}
	case "dir-open":
		s.files.openDir = func(string) (file, error) { return nil, errFault }
	case "dir-sync", "dir-close":
		s.files.openDir = func(p string) (file, error) {
			f, err := real.openDir(p)
			if err != nil {
				return nil, err
			}
			kind := "sync"
			if stage == "dir-close" {
				kind = "close"
			}
			return faultyFile{f, kind}, nil
		}
	default:
		s.files.createTemp = func(a, b string) (file, error) {
			f, err := real.createTemp(a, b)
			if err != nil {
				return nil, err
			}
			return faultyFile{f, stage}, nil
		}
	}
}
func TestPreReplacementFailuresPreservePreviousAuthority(t *testing.T) {
	for _, stage := range []string{"create", "write", "partial", "sync", "close"} {
		t.Run(stage, func(t *testing.T) {
			s, p := seeded(t)
			n := next(t, s)
			inject(s, stage)
			r, err := s.Commit(context.Background(), "1", n)
			if err == nil || r.Outcome != application.NotCommitted || r.AggregateRevision != "1" {
				t.Fatalf("failure %+v %v", r, err)
			}
			if strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("error leaks secret")
			}
			if stage == "partial" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("short write not preserved")
			}
			if load(t, s).Revision() != "1" || s.current.Snapshot().Users[0].DisplayName != "Owner" {
				t.Fatal("partial authority published")
			}
			entries, err := os.ReadDir(filepath.Dir(p))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if strings.Contains(e.Name(), ".tmp-") {
					t.Fatal("temporary file leaked")
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer closeStore(t, s)
			if load(t, s).Revision() != "1" {
				t.Fatal("previous revision lost")
			}
		})
	}
}
func TestReplacementAmbiguityBlocksUntilRestart(t *testing.T) {
	for _, stage := range []string{"rename-before", "rename-after", "dir-open", "dir-sync", "dir-close"} {
		t.Run(stage, func(t *testing.T) {
			s, p := seeded(t)
			n := next(t, s)
			inject(s, stage)
			r, err := s.Commit(context.Background(), "1", n)
			if err == nil || r.Outcome != application.Unknown || r.AggregateRevision != "" {
				t.Fatalf("ambiguity reported certain: %+v %v", r, err)
			}
			if !errors.Is(err, application.ErrRecoveryRequired) || !errors.Is(err, errFault) {
				t.Fatalf("classification/cause lost: %v", err)
			}
			if strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("error leaks secret")
			}
			if s.current.Revision() != "1" || s.current.Snapshot().Users[0].DisplayName != "Owner" {
				t.Fatal("unknown authority published")
			}
			if _, err := s.Load(context.Background()); !errors.Is(err, application.ErrRecoveryRequired) {
				t.Fatal("unknown authority used")
			}
			if r, err := s.Commit(context.Background(), "1", n); !errors.Is(err, application.ErrRecoveryRequired) || r.Outcome != application.Unknown {
				t.Fatalf("unknown retried %+v %v", r, err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer closeStore(t, s)
			want := domain.Version("2")
			if stage == "rename-before" {
				want = "1"
			}
			if load(t, s).Revision() != want {
				t.Fatal("restart did not resolve disk authority")
			}
		})
	}
}
func TestCommitIOOrderAndCancellationAfterReplacement(t *testing.T) {
	s, _ := seeded(t)
	n := next(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	real := s.files
	var order []string
	s.files.createTemp = func(a, b string) (file, error) {
		order = append(order, "create")
		f, err := real.createTemp(a, b)
		return orderedFile{file: f, order: &order}, err
	}
	s.files.rename = func(a, b string) error {
		order = append(order, "rename")
		err := real.rename(a, b)
		cancel()
		return err
	}
	s.files.openDir = func(p string) (file, error) {
		order = append(order, "open-dir")
		f, err := real.openDir(p)
		return orderedFile{file: f, order: &order, dir: true}, err
	}
	r, err := s.Commit(ctx, "1", n)
	if err != nil || r.Outcome != application.Committed {
		t.Fatalf("cancel after replacement: %+v %v", r, err)
	}
	if strings.Join(order, ",") != "create,write,sync,close,rename,open-dir,dir-sync,dir-close" {
		t.Fatalf("durability order %v", order)
	}
}

type orderedFile struct {
	file
	order *[]string
	dir   bool
}

func (f orderedFile) Write(p []byte) (int, error) {
	*f.order = append(*f.order, "write")
	return f.file.Write(p)
}
func (f orderedFile) Sync() error {
	stage := "sync"
	if f.dir {
		stage = "dir-sync"
	}
	*f.order = append(*f.order, stage)
	return f.file.Sync()
}
func (f orderedFile) Close() error {
	stage := "close"
	if f.dir {
		stage = "dir-close"
	}
	*f.order = append(*f.order, stage)
	return f.file.Close()
}
func TestUnsafeModesAndLockSymlinkFailClosed(t *testing.T) {
	for _, kind := range []string{"data-mode", "lock-mode", "lock-link"} {
		t.Run(kind, func(t *testing.T) {
			s, p := seeded(t)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "data-mode":
				if err := os.Chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
			case "lock-mode":
				if err := os.Chmod(p+".lock", 0644); err != nil {
					t.Fatal(err)
				}
			case "lock-link":
				if err := os.Remove(p + ".lock"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p, p+".lock"); err != nil {
					t.Fatal(err)
				}
			}
			if s, err := Open(context.Background(), p); err == nil {
				closeStore(t, s)
				t.Fatal("unsafe storage opened")
			}
		})
	}
}
func TestInitializationAmbiguityDoesNotGrantAuthority(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.json")
	files := systemDisk()
	real := files.rename
	files.rename = func(a, b string) error {
		if err := real(a, b); err != nil {
			return err
		}
		return errFault
	}
	s, err := open(context.Background(), p, &initialization{aggregate: validated(t, fixture(t))}, files)
	if err == nil || s != nil || !errors.Is(err, application.ErrRecoveryRequired) {
		t.Fatalf("unknown initialized as ready: %v", err)
	}
	s, err = Open(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore(t, s)
	if load(t, s).Revision() != "1" {
		t.Fatal("recovered initialization lost")
	}
}
