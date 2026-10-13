package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

type fileFact struct {
	Path   string `json:"path"`
	Mode   int    `json:"mode"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

func main() {
	if e := run(); e != nil {
		os.Exit(1)
	}
}
func run() error {
	facts := []fileFact{}
	e := filepath.WalkDir("tests/fixtures", func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("nonregular fixture source")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		h := sha256.Sum256(b)
		facts = append(facts, fileFact{filepath.ToSlash(path), int(info.Mode().Perm()), len(b), hex.EncodeToString(h[:])})
		return nil
	})
	if e != nil {
		return e
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].Path < facts[j].Path })
	b, e := json.Marshal(facts)
	if e != nil {
		return e
	}
	h := sha256.Sum256(b)
	_, e = fmt.Println(hex.EncodeToString(h[:]))
	return e
}
