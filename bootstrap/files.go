package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/adapters/strictjson"
)

func admitPrivateDirectory(p string, create bool) error {
	if filepath.Clean(p) != p {
		return ErrNotReady
	}
	absolute, e := filepath.Abs(p)
	if e != nil {
		return ErrNotReady
	}
	for dir := absolute; dir != "/"; dir = filepath.Dir(dir) {
		info, statErr := os.Lstat(dir)
		if create && errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrNotReady
		}
	}
	if create {
		if e = os.MkdirAll(absolute, 0700); e != nil {
			return ErrNotReady
		}
	}
	info, e := os.Lstat(absolute)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return ErrNotReady
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) {
		return ErrNotReady
	}
	return nil
}

func ReadPrivateFile(p string, limit int64) ([]byte, error) {
	for dir := filepath.Dir(p); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		info, e := os.Lstat(dir)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrNotReady
		}
	}
	f, e := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrNotReady
	}
	s, e := f.Stat()
	if e != nil {
		return nil, errors.Join(ErrNotReady, f.Close())
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) || s.Size() > limit {
		return nil, errors.Join(ErrNotReady, f.Close())
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	e = errors.Join(e, f.Close())
	if e != nil || int64(len(b)) > limit {
		return nil, ErrNotReady
	}
	return b, nil
}

func readTextCredential(p string, limit int64) ([]byte, error) {
	b, err := ReadPrivateFile(p, limit+2)
	if err != nil {
		return nil, err
	}
	end := len(b)
	if end > 0 && b[end-1] == '\n' {
		end--
		if end > 0 && b[end-1] == '\r' {
			end--
		}
	}
	if end == 0 || int64(end) > limit {
		clear(b)
		return nil, ErrNotReady
	}
	return b[:end], nil
}

func DecodeStrict(b []byte, v any) error {
	if !utf8.Valid(b) || strictjson.CheckText(b) != nil {
		return ErrNotReady
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if e := walk(d, 0); e != nil {
		return ErrNotReady
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrNotReady
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func walk(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrNotReady
	}
	t, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return ErrNotReady
			}
			seen[s] = true
			if e = walk(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e := walk(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return ErrNotReady
	}
	_, e = d.Token()
	return e
}
