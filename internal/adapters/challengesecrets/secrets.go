package challengesecrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"unicode"
	"unicode/utf8"

	"encoding/base64"
	"encoding/hex"
)

type ChallengeCrypto struct {
	mu     sync.Mutex
	pepper [32]byte
	aead   cipher.AEAD
	random io.Reader
}

func New(pepper, key []byte) (*ChallengeCrypto, error) {
	if len(pepper) != 32 || len(key) != 32 {
		return nil, errors.New("OTP keys must each contain 32 bytes")
	}
	if subtle.ConstantTimeCompare(pepper, key) == 1 {
		return nil, errors.New("OTP keys must be separate")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize OTP cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize OTP encryption: %w", err)
	}
	c := &ChallengeCrypto{aead: aead, random: rand.Reader}
	copy(c.pepper[:], pepper)
	return c, nil
}

func (c *ChallengeCrypto) NewID() (string, error) {
	var id [16]byte
	c.mu.Lock()
	_, err := io.ReadFull(c.random, id[:])
	c.mu.Unlock()
	if err != nil {
		return "", fmt.Errorf("OTP identity entropy unavailable: %w", err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]), nil
}

func (c *ChallengeCrypto) NewCode() (string, error) {
	c.mu.Lock()
	n, err := rand.Int(c.random, big.NewInt(1_000_000))
	c.mu.Unlock()
	if err != nil {
		return "", fmt.Errorf("OTP entropy unavailable: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func (c *ChallengeCrypto) Digest(scope, value string) string {
	if !validSecretScope(scope) || len(value) > 65536 {
		return ""
	}
	mac := hmac.New(sha256.New, c.pepper[:])
	if _, err := mac.Write([]byte(scope)); err != nil {
		return ""
	}
	if _, err := mac.Write([]byte{0}); err != nil {
		return ""
	}
	data := []byte(value)
	defer clear(data)
	if _, err := mac.Write(data); err != nil {
		return ""
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *ChallengeCrypto) Seal(scope, value string) (string, error) {
	if !validSecretScope(scope) || value == "" || len(value) > 65536 {
		return "", errors.New("invalid OTP secret payload")
	}
	nonce := make([]byte, c.aead.NonceSize())
	c.mu.Lock()
	_, err := io.ReadFull(c.random, nonce)
	c.mu.Unlock()
	if err != nil {
		return "", fmt.Errorf("OTP nonce entropy unavailable: %w", err)
	}
	data := []byte(value)
	defer clear(data)
	return base64.RawURLEncoding.EncodeToString(c.aead.Seal(nonce, nonce, data, []byte(scope))), nil
}

func (c *ChallengeCrypto) Open(scope, encoded string) (string, error) {
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || !validSecretScope(scope) || len(sealed) < c.aead.NonceSize()+c.aead.Overhead()+1 || len(sealed) > 65536+c.aead.NonceSize()+c.aead.Overhead() {
		return "", errors.New("invalid OTP encrypted payload")
	}
	data, err := c.aead.Open(nil, sealed[:c.aead.NonceSize()], sealed[c.aead.NonceSize():], []byte(scope))
	if err != nil {
		return "", errors.New("OTP encrypted payload authentication failed")
	}
	defer clear(data)
	return string(data), nil
}

func validSecretScope(scope string) bool {
	if scope == "" || len(scope) > 256 || !utf8.ValidString(scope) {
		return false
	}
	for _, r := range scope {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (c *ChallengeCrypto) NewProof() (string, error) {
	var b [32]byte
	c.mu.Lock()
	_, err := io.ReadFull(c.random, b[:])
	c.mu.Unlock()
	if err != nil {
		return "", errors.New("OTP proof entropy unavailable")
	}
	defer clear(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
