package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func privateCredential(t *testing.T, value string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTextCredentialRemovesExactlyOneLineEnding(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"unchanged", "password", "password"},
		{"LF", "password\n", "password"},
		{"CRLF", "password\r\n", "password"},
		{"spaces", " password \r\n", " password "},
		{"one-ending", "password\n\n", "password\n"},
		{"lone-CR", "password\r", "password\r"},
		{"unicode", "пароль🔑\n", "пароль🔑"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readTextCredential(privateCredential(t, tc.input), 128)
			if err != nil || string(got) != tc.want {
				t.Fatal("text credential was changed beyond its final line ending")
			}
			clear(got)
		})
	}
}

func TestTextCredentialBoundsAndEmptyInput(t *testing.T) {
	for _, input := range []string{"", "\n", "\r\n", "123456789", "12345678\n\n"} {
		if _, err := readTextCredential(privateCredential(t, input), 8); !errors.Is(err, ErrNotReady) {
			t.Fatal("empty or oversized text credential was admitted")
		}
	}
	for _, input := range []string{"12345678", "12345678\n", "12345678\r\n"} {
		got, err := readTextCredential(privateCredential(t, input), 8)
		if err != nil || string(got) != "12345678" {
			t.Fatal("line ending consumed the credential's byte allowance")
		}
		clear(got)
	}
}

func TestRawPrivateFileRetainsAllBytes(t *testing.T) {
	value := []byte{0, 255, 1, '\r', '\n'}
	got, err := ReadPrivateFile(privateCredential(t, string(value)), 8)
	if err != nil || !bytes.Equal(got, value) {
		t.Fatal("raw key bytes were normalized")
	}
	clear(got)
}

func TestProcessFailureReportsStageWithoutPrivateContent(t *testing.T) {
	const marker = "synthetic-private-value"
	path := privateCredential(t, `{"`+marker+`":true}`)
	err := Run(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "private configuration") || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), path) {
		t.Fatal("process failure did not return a safe stage summary")
	}
	if cause := errors.Unwrap(err); cause == nil || !strings.Contains(cause.Error(), marker) {
		t.Fatal("process failure discarded its original diagnostic cause")
	}
}
