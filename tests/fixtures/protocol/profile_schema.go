package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const ProfileAmendment = "umir-owner-profiles/0.1.0-unpublished"
const ProfileIdentity = "sha256:ee5ea052cf8239a40fdc3aba7c97c0a143260be284c390168a75c8afb7770460"
const ProfilePath = "/owner-profile/v1"
const ProfileConfigPath = "/run/umir-fixtures/profile.json"
const ProfileRequestPath = "/run/umir-fixtures/profile-request.json"

var FixtureSHA256 string
var profileValidators sync.Pool

func ValidateProfile(name string, body []byte) error {
	if len(body) > MaxResponse || checkDocument(body) != nil {
		return errors.New("invalid profile document")
	}
	var v *schemaValidator
	if pooled := profileValidators.Get(); pooled != nil {
		var ok bool
		v, ok = pooled.(*schemaValidator)
		if !ok {
			return errors.New("invalid validator")
		}
	} else {
		var e error
		v, e = compileProfileSchemas()
		if e != nil {
			return e
		}
	}
	defer profileValidators.Put(v)
	value, e := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if e != nil {
		return e
	}
	return v.validate(name, value)
}
func LoadProfile(cfg Config, selector string) (ProfileProfileConfig, string, error) {
	var p ProfileProfileConfig
	b, e := readFile(ProfileConfigPath, 4096, 0600)
	if e != nil {
		return p, "", e
	}
	if e = ValidateProfile("ProfileConfig", b); e != nil {
		return p, "", e
	}
	if e = json.Unmarshal(b, &p); e != nil {
		return p, "", e
	}
	if p.Project != cfg.Project || p.Profile != selector || p.ProfileContractIdentity != ProfileIdentity || !AuthProfile(selector) {
		return p, "", errors.New("unsupported profile binding")
	}
	return p, SHA(b), nil
}
func AuthProfile(p string) bool {
	switch p {
	case "auth-rotation", "auth-corrupt-json", "auth-unknown-schema", "auth-invalid-aggregate", "auth-legacy-v1", "auth-legacy-v2", "auth-second-writer":
		return true
	}
	return false
}
func ProfileClockRead(clock *Clock) ProfileClock {
	s := clock.Read()
	return ProfileClock{Instant: s.Instant, Generation: s.Generation, InstanceID: s.InstanceID, Source: "owner", Healthy: s.Healthy}
}

func compileProfileSchemas() (v *schemaValidator, err error) {
	defer recoverSchemaMatch(&err)
	v = &schemaValidator{schemas: map[string]*jsonschema.Schema{}}
	v.budget.reset(2 * time.Second)
	resource, e := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(profileSchemaJSON)))
	if e != nil {
		return nil, e
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseRegexpEngine(v.budget.compile)
	compiler.AssertFormat()
	if e = compiler.AddResource("profile.json", resource); e != nil {
		return nil, e
	}
	for _, name := range []string{"Report", "Binding", "Clock", "Session", "AuthFacts", "Rotation", "Writer", "AuthLegacy", "Request", "ProfileConfig", "ProfileError", "AuthPreparedSession", "AuthIdentityMap", "AuthSessionMap", "CatalogRequest", "CatalogFact", "CatalogReport"} {
		schema, e := compiler.Compile("profile.json#/$defs/" + name)
		if e != nil {
			return nil, e
		}
		v.schemas[name] = schema
	}
	v.budget.check()
	return v, nil
}
