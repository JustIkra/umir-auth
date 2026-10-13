package legacy

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type document struct {
	SchemaVersion     int       `json:"schemaVersion"`
	ProfileID         string    `json:"profileID"`
	Login             string    `json:"login"`
	DisplayName       string    `json:"displayName"`
	PasswordHash      string    `json:"passwordHash"`
	CredentialVersion int64     `json:"credentialVersion"`
	Sessions          []session `json:"sessions,omitempty"`
}
type session struct {
	Digest            string         `json:"digest"`
	RememberMe        bool           `json:"rememberMe"`
	CredentialVersion int64          `json:"credentialVersion"`
	CreatedAt         domain.Instant `json:"createdAt"`
	LastSeenAt        domain.Instant `json:"lastSeenAt"`
	ExpiresAt         domain.Instant `json:"expiresAt"`
}

func Decode(data []byte) (application.LegacyAccount, error) {
	fail := func() (application.LegacyAccount, error) {
		return application.LegacyAccount{}, application.ErrInvalidLegacy
	}
	if len(data) > 1<<20 || !utf8.Valid(data) || !unicodeEscapes(data) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := shape(d, reflect.TypeFor[document]()); err != nil {
		return fail()
	}
	if _, err := d.Token(); err != io.EOF {
		return fail()
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return fail()
	}
	if doc.SchemaVersion != 1 && doc.SchemaVersion != 2 || doc.SchemaVersion == 1 && doc.Sessions != nil || doc.SchemaVersion == 2 && doc.Sessions == nil {
		return fail()
	}
	if doc.ProfileID == "" || len(doc.ProfileID) > 128 || strings.ContainsFunc(doc.ProfileID, func(r rune) bool { return r > unicode.MaxASCII || !unicode.IsGraphic(r) || unicode.IsSpace(r) }) {
		return fail()
	}
	out := application.LegacyAccount{SchemaVersion: doc.SchemaVersion, ProfileID: doc.ProfileID, Login: doc.Login, DisplayName: doc.DisplayName, PasswordHash: doc.PasswordHash, CredentialVersion: doc.CredentialVersion, Sessions: []application.LegacySession{}}
	for _, s := range doc.Sessions {
		out.Sessions = append(out.Sessions, application.LegacySession{Digest: s.Digest, RememberMe: s.RememberMe, CredentialVersion: s.CredentialVersion, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt})
	}
	return out, nil
}
