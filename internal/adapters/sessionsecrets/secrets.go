package sessionsecrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"sync"
)

var ErrSecrets = errors.New("auth result secrets unavailable")

type Secrets struct {
	mu     sync.Mutex
	key    []byte
	gcm    cipher.AEAD
	random io.Reader
}

func New(key []byte, random io.Reader) (*Secrets, error) {
	if len(key) != 32 || random == nil {
		return nil, ErrSecrets
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrSecrets
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrSecrets
	}
	return &Secrets{key: append([]byte(nil), key...), gcm: gcm, random: random}, nil
}
func (s *Secrets) Digest(data []byte) (string, error) {
	h := hmac.New(sha256.New, s.key)
	if _, err := h.Write([]byte("umir-auth-fingerprint-v1\x00")); err != nil {
		return "", ErrSecrets
	}
	if _, err := h.Write(data); err != nil {
		return "", ErrSecrets
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (s *Secrets) Seal(data []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return "", ErrSecrets
	}
	sealed := s.gcm.Seal(nonce, nonce, data, []byte("umir-auth-result-v1"))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}
func (s *Secrets) Open(encoded string) ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) < s.gcm.NonceSize()+s.gcm.Overhead() {
		return nil, ErrSecrets
	}
	plain, err := s.gcm.Open(nil, data[:s.gcm.NonceSize()], data[s.gcm.NonceSize():], []byte("umir-auth-result-v1"))
	if err != nil {
		return nil, ErrSecrets
	}
	return plain, nil
}
