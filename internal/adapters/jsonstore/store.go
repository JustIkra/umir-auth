package jsonstore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type file interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
	Name() string
}
type disk struct {
	createTemp func(string, string) (file, error)
	rename     func(string, string) error
	openDir    func(string) (file, error)
	remove     func(string) error
}

func systemDisk() disk {
	return disk{createTemp: func(a, b string) (file, error) { return os.CreateTemp(a, b) }, rename: os.Rename, openDir: func(p string) (file, error) { return os.Open(p) }, remove: os.Remove}
}

type initialization struct{ aggregate domain.ValidatedAggregate }
type Store struct {
	mu               sync.Mutex
	current          domain.ValidatedAggregate
	files            disk
	path             string
	lock             *writerLock
	closed, recovery bool
}

var _ application.AggregateRepository = (*Store)(nil)

func Open(ctx context.Context, p string) (*Store, error) { return open(ctx, p, nil, systemDisk()) }
func Initialize(ctx context.Context, p string, a domain.ValidatedAggregate) (*Store, error) {
	return open(ctx, p, &initialization{a}, systemDisk())
}
func open(ctx context.Context, p string, initial *initialization, files disk) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, safe(application.ErrStorageUnavailable, err)
	}
	if p == "" {
		return nil, application.ErrStorageUnavailable
	}
	absolute, err := filepath.Abs(p)
	if err != nil {
		return nil, safe(application.ErrStorageUnavailable, err)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, safe(application.ErrStorageUnavailable, err)
	}
	p = filepath.Join(dir, filepath.Base(absolute))
	lock, err := acquire(p + ".lock")
	if err != nil {
		return nil, err
	}
	s := &Store{path: p, files: files, lock: lock}
	if initial != nil {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			return nil, safe(application.ErrStorageUnavailable, errors.Join(err, lock.close()))
		}
		v, err := domain.Validate(initial.aggregate.Snapshot())
		if err == nil {
			err = zones(v)
		}
		if err != nil {
			return nil, safe(application.ErrStorageUnavailable, errors.Join(err, lock.close()))
		}
		outcome, err := s.replace(ctx, v)
		if err != nil {
			kind := application.ErrStorageUnavailable
			if outcome == application.Unknown {
				kind = application.ErrRecoveryRequired
			}
			return nil, safe(kind, errors.Join(err, lock.close()))
		}
		s.current = v
		return s, nil
	} else {
		f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, safe(application.ErrStorageUnavailable, errors.Join(err, lock.close()))
		}
		if err := privateRegular(f); err != nil {
			return nil, safe(application.ErrStorageUnavailable, errors.Join(err, f.Close(), lock.close()))
		}
		data, readErr := io.ReadAll(f)
		closeErr := f.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, safe(application.ErrStorageUnavailable, errors.Join(err, lock.close()))
		}
		v, err := decode(data)
		if err != nil {
			return nil, safe(application.ErrStorageUnavailable, errors.Join(err, lock.close()))
		}
		s.current = v
	}
	if err := ctx.Err(); err != nil {
		return nil, safe(application.ErrStorageUnavailable, errors.Join(err, lock.close()))
	}
	return s, nil
}
func (s *Store) Load(ctx context.Context) (domain.ValidatedAggregate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return domain.ValidatedAggregate{}, application.ErrClosed
	}
	if s.recovery {
		return domain.ValidatedAggregate{}, application.ErrRecoveryRequired
	}
	if err := ctx.Err(); err != nil {
		return domain.ValidatedAggregate{}, safe(application.ErrStorageUnavailable, err)
	}
	return s.current, nil
}
func (s *Store) Commit(ctx context.Context, expected domain.Version, next domain.ValidatedAggregate) (application.CommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recovery && !s.closed {
		return application.CommitResult{Outcome: application.Unknown}, application.ErrRecoveryRequired
	}
	result := application.CommitResult{Outcome: application.NotCommitted, AggregateRevision: s.current.Revision()}
	if s.closed {
		return result, application.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return result, safe(application.ErrStorageUnavailable, err)
	}
	if expected != s.current.Revision() {
		return result, application.ErrRevisionConflict
	}
	v, err := domain.Validate(next.Snapshot())
	if err != nil {
		return result, err
	}
	n, ok := domain.VersionNumber(expected)
	if !ok || n == 9223372036854775807 || v.Revision() != domain.Version(strconv.FormatInt(n+1, 10)) {
		return result, application.ErrRevisionConflict
	}
	if err := zones(v); err != nil {
		return result, err
	}
	if err := domain.ValidateReplacement(s.current, v); err != nil {
		return result, err
	}
	outcome, err := s.replace(ctx, v)
	if err != nil {
		if outcome == application.Unknown {
			s.recovery = true
			return application.CommitResult{Outcome: application.Unknown}, safe(application.ErrRecoveryRequired, err)
		}
		return result, safe(application.ErrStorageUnavailable, err)
	}
	s.current = v
	return application.CommitResult{Outcome: application.Committed, AggregateRevision: v.Revision()}, nil
}
func (s *Store) replace(ctx context.Context, v domain.ValidatedAggregate) (application.CommitOutcome, error) {
	data, err := json.Marshal(v.Snapshot())
	if err != nil {
		return application.NotCommitted, err
	}
	f, err := s.files.createTemp(filepath.Dir(s.path), ".auth.tmp-")
	if err != nil {
		return application.NotCommitted, err
	}
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	writeErr = errors.Join(writeErr, f.Close())
	if writeErr == nil {
		writeErr = ctx.Err()
	}
	if writeErr != nil {
		return application.NotCommitted, errors.Join(writeErr, s.files.remove(f.Name()))
	}
	if err := s.files.rename(f.Name(), s.path); err != nil {
		cleanup := s.files.remove(f.Name())
		if errors.Is(cleanup, os.ErrNotExist) {
			cleanup = nil
		}
		return application.Unknown, errors.Join(err, cleanup)
	}
	dir, err := s.files.openDir(filepath.Dir(s.path))
	if err != nil {
		return application.Unknown, err
	}
	if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
		return application.Unknown, err
	}
	return application.Committed, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if err := s.lock.close(); err != nil {
		return safe(application.ErrStorageUnavailable, err)
	}
	return nil
}
