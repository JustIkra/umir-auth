package jsonstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func validated(t *testing.T, a domain.Aggregate) domain.ValidatedAggregate {
	t.Helper()
	v, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func seeded(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "auth.json")
	s, err := Initialize(context.Background(), p, validated(t, fixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, p
}
func load(t *testing.T, s *Store) domain.ValidatedAggregate {
	t.Helper()
	v, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func next(t *testing.T, s *Store) domain.ValidatedAggregate {
	t.Helper()
	a := load(t, s).Snapshot()
	a.AggregateRevision = "2"
	a.Users[0].DisplayName = "Updated"
	return validated(t, a)
}

func TestCommitPersistsAcrossRestartAndCopies(t *testing.T) {
	s, p := seeded(t)
	n := next(t, s)
	result, err := s.Commit(context.Background(), "1", n)
	if err != nil || result.Outcome != application.Committed || result.AggregateRevision != "2" {
		t.Fatalf("commit: %+v %v", result, err)
	}
	snapshot := load(t, s).Snapshot()
	snapshot.Users[0].DisplayName = "Alias"
	if load(t, s).Snapshot().Users[0].DisplayName != "Updated" {
		t.Fatal("published alias")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore(t, reopened)
	if load(t, reopened).Revision() != "2" || load(t, reopened).Snapshot().Sessions[0].AbsoluteExpiresAt != fixtureDeadline {
		t.Fatal("revision or immutable instant lost")
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", info.Mode())
	}
}
func closeStore(t *testing.T, s *Store) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Error(err)
	}
}

func TestConcurrentCommitsHaveOneWinner(t *testing.T) {
	s, _ := seeded(t)
	n := next(t, s)
	var wg sync.WaitGroup
	results := make(chan application.CommitResult, 16)
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() { r, err := s.Commit(context.Background(), "1", n); results <- r; errs <- err })
	}
	wg.Wait()
	close(results)
	close(errs)
	winners := 0
	for r := range results {
		if r.Outcome == application.Committed {
			winners++
		} else if r.Outcome != application.NotCommitted {
			t.Fatalf("unexpected outcome %+v", r)
		}
	}
	for err := range errs {
		if err != nil && !errors.Is(err, application.ErrRevisionConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 || load(t, s).Revision() != "2" {
		t.Fatalf("winners %d", winners)
	}
}

func TestInvalidCommitAndCancellationDoNotWrite(t *testing.T) {
	s, p := seeded(t)
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []domain.ValidatedAggregate{{}, validated(t, fixture(t))} {
		r, err := s.Commit(context.Background(), "1", n)
		if err == nil || r.Outcome != application.NotCommitted {
			t.Fatalf("invalid commit %+v %v", r, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := s.Commit(ctx, "1", next(t, s))
	if !errors.Is(err, context.Canceled) || r.Outcome != application.NotCommitted {
		t.Fatalf("canceled commit %+v %v", r, err)
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed mutation changed file")
	}
}

func TestStartupRejectsCorruptionAndUnknownJSON(t *testing.T) {
	a := fixture(t)
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(b)
	cases := map[string]string{
		"unknown timezone": strings.Replace(valid, "Europe/Moscow", "not/a/zone", 1), "corrupt": "{", "unknown schema": strings.Replace(valid, `"schemaVersion":1`, `"schemaVersion":2`, 1),
		"unknown field":      strings.Replace(valid, `"schemaVersion":1`, `"schemaVersion":1,"password":"secret-sentinel"`, 1),
		"duplicate key":      strings.Replace(valid, `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1),
		"missing collection": strings.Replace(valid, `,"tombstones":[]`, "", 1),
		"null collection":    strings.Replace(valid, `"tombstones":[]`, `"tombstones":null`, 1),
		"nested unknown":     strings.Replace(valid, `"displayName":"Owner"`, `"displayName":"Owner","rawPassword":"secret-sentinel"`, 1),
		"second value":       valid + " {}", "invalid utf8": strings.Replace(valid, "Owner", string([]byte{0xff}), 1),
		"bad reference": strings.Replace(valid, `"userID":"`+string(id(1))+`","sessionVersion"`, `"userID":"`+string(id(99))+`","sessionVersion"`, 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "auth.json")
			if err := os.WriteFile(p, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := Open(context.Background(), p)
			if err == nil {
				closeStore(t, s)
				t.Fatal("corrupt store opened")
			}
			if strings.Contains(err.Error(), "secret-sentinel") || strings.Contains(err.Error(), body) {
				t.Fatal("storage error exposes content")
			}
			if err := os.WriteFile(p, b, 0600); err != nil {
				t.Fatal(err)
			}
			s, err = Open(context.Background(), p)
			if err != nil {
				t.Fatalf("startup failure leaked lock: %v", err)
			}
			closeStore(t, s)
		})
	}
}

func TestInitializeNeverOverwritesAndMissingStartupFails(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.json")
	if s, err := Open(context.Background(), p); err == nil {
		closeStore(t, s)
		t.Fatal("missing file opened")
	}
	s, err := Initialize(context.Background(), p, validated(t, fixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	closeStore(t, s)
	if s, err := Initialize(context.Background(), p, validated(t, domain.Empty())); err == nil {
		closeStore(t, s)
		t.Fatal("existing authority overwritten")
	}
	s, err = Open(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore(t, s)
	if len(load(t, s).Snapshot().Users) != 1 {
		t.Fatal("authority erased")
	}
}

func TestLifetimeWriterLockAndClosedStore(t *testing.T) {
	s, p := seeded(t)
	if other, err := Open(context.Background(), p); !errors.Is(err, application.ErrWriterLocked) {
		if other != nil {
			closeStore(t, other)
		}
		t.Fatalf("second writer: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(context.Background()); !errors.Is(err, application.ErrClosed) {
		t.Fatal(err)
	}
	if r, err := s.Commit(context.Background(), "1", validated(t, domain.Empty())); !errors.Is(err, application.ErrClosed) || r.Outcome != application.NotCommitted {
		t.Fatalf("closed commit %+v %v", r, err)
	}
	other, err := Open(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	closeStore(t, other)
	if _, err := os.Stat(p + ".lock"); err != nil {
		t.Fatal("lock inode must be retained")
	}
}

func TestProcessWriterExclusion(t *testing.T) {
	if p := os.Getenv("AUTH_LOCK_TEST_PATH"); p != "" {
		s, err := Open(context.Background(), p)
		if !errors.Is(err, application.ErrWriterLocked) {
			if s != nil {
				closeStore(t, s)
			}
			t.Fatalf("process lock bypassed: %v", err)
		}
		return
	}
	_, p := seeded(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessWriterExclusion$")
	cmd.Env = append(os.Environ(), "AUTH_LOCK_TEST_PATH="+p)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
}

func TestPathAliasesCannotBypassWriterLock(t *testing.T) {
	s, p := seeded(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(p), alias); err != nil {
		t.Fatal(err)
	}
	other, err := Open(context.Background(), filepath.Join(alias, "auth.json"))
	if err == nil {
		closeStore(t, other)
		t.Fatal("directory alias bypassed lock")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "auth.json")
	if err := os.Symlink(p, symlink); err != nil {
		t.Fatal(err)
	}
	other, err = Open(context.Background(), symlink)
	if err == nil {
		closeStore(t, other)
		t.Fatal("data symlink accepted")
	}
}

func TestStrictStorageRejectsMalformedUnicodeAndMissingFalseFields(t *testing.T) {
	a := fixture(t)
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"lone high surrogate":   strings.Replace(string(data), "Owner", `Owner \ud800`, 1),
		"lone low surrogate":    strings.Replace(string(data), "Owner", `Owner \udc00`, 1),
		"missing false boolean": strings.Replace(string(data), `,"rememberMe":false`, "", 1),
		"case alias":            strings.Replace(string(data), `"schemaVersion"`, `"SchemaVersion"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "auth.json")
			if err := os.WriteFile(p, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := Open(context.Background(), p)
			if err == nil {
				closeStore(t, s)
				t.Fatal("malformed document accepted")
			}
		})
	}
	a.Users[0].DisplayName = "Owner � 🧑"
	data, err = json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), p)
	if err != nil {
		t.Fatal("literal valid Unicode rejected", err)
	}
	closeStore(t, s)
}

func TestCommitCannotEraseScopeOrReplayEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*domain.Aggregate){
		"remove idempotency":        func(a *domain.Aggregate) { a.Idempotency = []domain.IdempotencyRecord{} },
		"change committed response": func(a *domain.Aggregate) { a.Idempotency[0].EncryptedResponse = "changed" },
		"change immutable instant": func(a *domain.Aggregate) {
			a.Sessions[0].CreatedAt = "2026-10-13T00:00:00+03:00"
			a.Sessions[0].AbsoluteExpiresAt = "2026-10-13T08:00:00+03:00"
		},
		"erase authority": func(a *domain.Aggregate) { empty := domain.Empty(); empty.AggregateRevision = "2"; *a = empty },
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := seeded(t)
			a := load(t, s).Snapshot()
			a.AggregateRevision = "2"
			mutate(&a)
			r, err := s.Commit(context.Background(), "1", validated(t, a))
			if err == nil || r.Outcome != application.NotCommitted || load(t, s).Revision() != "1" {
				t.Fatalf("history rewritten: %+v %v", r, err)
			}
		})
	}
}
