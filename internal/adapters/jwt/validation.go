package jwt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

var encodedPart = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var headerFields = []string{"alg", "typ", "kid"}
var userFields = []string{"iss", "aud", "iat", "nbf", "exp", "jti", "operation", "permissions", "kind", "sub", "sid", "session_version", "credential_version", "access_version", "org_id", "tenant_id", "time_zone", "settings_version", "lifecycle_version", "azp"}

func VerifyUser(token string, keys JWKS, at time.Time, audience string) (UserClaims, error) {
	var zero UserClaims
	if len(token) > 16384 || !validClock(at) || len(keys.Keys) < 1 || len(keys.Keys) > 3 {
		return zero, ErrInvalidToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return zero, ErrInvalidToken
	}
	for _, part := range parts {
		if !encodedPart.MatchString(part) {
			return zero, ErrInvalidToken
		}
	}
	header, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return zero, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return zero, ErrInvalidToken
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return zero, ErrInvalidToken
	}
	var h Header
	if err := strict(header, headerFields, &h); err != nil || h.Algorithm != "EdDSA" || h.Type != "JWT" || !keyID.MatchString(h.KID) {
		return zero, ErrInvalidToken
	}
	seen := map[string]bool{}
	var pub ed25519.PublicKey
	for _, k := range keys.Keys {
		if seen[k.KID] || !keyID.MatchString(k.KID) || k.KTY != "OKP" || k.Curve != "Ed25519" || k.Algorithm != "EdDSA" || k.Use != "sig" {
			return zero, ErrInvalidToken
		}
		seen[k.KID] = true
		data, err := base64.RawURLEncoding.Strict().DecodeString(k.X)
		if err != nil || len(data) != ed25519.PublicKeySize {
			return zero, ErrInvalidToken
		}
		if k.KID == h.KID {
			pub = ed25519.PublicKey(data)
		}
	}
	if pub == nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), signature) {
		return zero, ErrInvalidToken
	}
	var c UserClaims
	if err := strict(payload, userFields, &c); err != nil {
		return zero, ErrInvalidToken
	}
	if c.Issuer != "urn:umir:auth" || c.Kind != "user" || c.AuthorizedParty != "umir-gateway" || !entityID.MatchString(string(c.TokenID)) || c.IssuedAt < 0 || c.IssuedAt > 253402300739 || c.NotBefore != c.IssuedAt || c.ExpiresAt != c.IssuedAt+60 || !validDecision(c.UserToken) || !slices.Contains(c.Audiences, audience) || at.Before(time.Unix(c.IssuedAt, 0)) || !at.Before(time.Unix(c.ExpiresAt, 0)) {
		return zero, ErrInvalidToken
	}
	return c, nil
}
func strict(data []byte, fields []string, target any) error {
	if len(data) == 0 || !utf8.Valid(data) {
		return ErrInvalidToken
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := walk(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalidToken
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || len(object) != len(fields) {
		return ErrInvalidToken
	}
	for k, v := range object {
		if !slices.Contains(fields, k) || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return ErrInvalidToken
		}
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return ErrInvalidToken
	}
	return nil
}
func walk(d *json.Decoder, depth int) error {
	if depth > 3 {
		return ErrInvalidToken
	}
	token, err := d.Token()
	if err != nil {
		return ErrInvalidToken
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return ErrInvalidToken
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return ErrInvalidToken
			}
			seen[key] = true
			if err := walk(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := walk(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidToken
	}
	if _, err := d.Token(); err != nil {
		return ErrInvalidToken
	}
	return nil
}
