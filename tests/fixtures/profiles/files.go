package profiles

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/JustIkra/umir-auth/bootstrap"
)

const ownerDir = "/var/lib/umir-auth"
const statePath = ownerDir + "/auth.json"

func writePrivate(path string, v any, exclusive bool) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	defer clear(b)
	return writeBytes(path, b, exclusive)
}
func writeBytes(path string, b []byte, exclusive bool) error {
	flags := os.O_WRONLY | os.O_CREATE | syscall.O_NOFOLLOW
	target := path
	if exclusive {
		flags |= os.O_EXCL
	} else {
		target = path + ".new"
		flags |= os.O_EXCL
	}
	f, e := os.OpenFile(target, flags, 0600)
	if e != nil {
		return e
	}
	n, w := f.Write(b)
	if w == nil && n != len(b) {
		w = errors.New("short profile write")
	}
	e = errors.Join(w, f.Sync(), f.Close())
	if e != nil {
		return e
	}
	if !exclusive {
		if e = os.Rename(target, path); e != nil {
			return e
		}
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	return errors.Join(d.Sync(), d.Close())
}
func readPrivate(path string, v any) error {
	b, e := bootstrap.ReadPrivateFile(path, 1<<20)
	if e != nil {
		return e
	}
	defer clear(b)
	return bootstrap.DecodeStrict(b, v)
}
