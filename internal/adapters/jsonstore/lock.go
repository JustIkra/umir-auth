package jsonstore

import (
	"errors"
	"os"
	"syscall"

	"github.com/JustIkra/umir-auth/internal/application"
)

type writerLock struct{ file *os.File }

func acquire(path string) (*writerLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, safe(application.ErrStorageUnavailable, err)
	}
	if err := privateRegular(f); err != nil {
		return nil, safe(application.ErrStorageUnavailable, errors.Join(err, f.Close()))
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		kind := application.ErrStorageUnavailable
		if errors.Is(err, syscall.EWOULDBLOCK) {
			kind = application.ErrWriterLocked
		}
		return nil, safe(kind, errors.Join(err, f.Close()))
	}
	return &writerLock{f}, nil
}
func (l *writerLock) close() error {
	return errors.Join(syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN), l.file.Close())
}
func privateRegular(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return application.ErrStorageUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return application.ErrStorageUnavailable
	}
	return nil
}

type storageError struct{ kind, cause error }

func (e *storageError) Error() string   { return e.kind.Error() }
func (e *storageError) Unwrap() []error { return []error{e.kind, e.cause} }
func safe(kind, cause error) error      { return &storageError{kind, cause} }
