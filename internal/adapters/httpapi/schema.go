package httpapi

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed contract.json
var contractJSON []byte
var contractOnce sync.Once
var contractSchemas map[string]*jsonschema.Schema
var contractError error

func schemaCheck(r *http.Request, body []byte) (err error) {
	defer func() {
		if v := recover(); v != nil {
			if e, ok := v.(matchError); ok {
				err = e.err
			} else {
				panic(v)
			}
		}
	}()
	contractOnce.Do(func() {
		var document struct {
			Paths map[string]map[string]struct {
				RequestBody *struct {
					Content map[string]struct {
						Schema json.RawMessage `json:"schema"`
					} `json:"content"`
				} `json:"requestBody"`
			} `json:"paths"`
		}
		if e := json.Unmarshal(contractJSON, &document); e != nil {
			contractError = e
			return
		}
		value, e := jsonschema.UnmarshalJSON(bytes.NewReader(contractJSON))
		if e != nil {
			contractError = e
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.AssertFormat()
		compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
			re, e := regexp2.Compile(pattern, regexp2.ECMAScript)
			if e != nil {
				return nil, e
			}
			re.MatchTimeout = 100 * time.Millisecond
			return &contractRegexp{re}, nil
		})
		if e = compiler.AddResource("contract.json", value); e != nil {
			contractError = e
			return
		}
		contractSchemas = map[string]*jsonschema.Schema{}
		for path, ops := range document.Paths {
			if !strings.HasPrefix(path, "/internal/auth/") {
				continue
			}
			for method, op := range ops {
				if op.RequestBody == nil {
					continue
				}
				pointer := strings.ReplaceAll(strings.ReplaceAll(path, "~", "~0"), "/", "~1")
				schema, e := compiler.Compile("contract.json#/paths/" + pointer + "/" + method + "/requestBody/content/application~1json/schema")
				if e != nil {
					contractError = e
					return
				}
				contractSchemas[strings.ToUpper(method)+" "+path] = schema
			}
		}
	})
	if contractError != nil {
		return contractError
	}
	schema, ok := contractSchemas[r.Pattern]
	if !ok {
		return errors.New("missing frozen request schema")
	}
	v, e := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if e != nil {
		return e
	}
	return schema.Validate(v)
}

type contractRegexp struct{ re *regexp2.Regexp }

func (r *contractRegexp) String() string { return r.re.String() }
func (r *contractRegexp) MatchString(s string) bool {
	ok, e := r.re.MatchString(s)
	if e != nil {
		panic(matchError{e})
	}
	return ok
}

type matchError struct{ err error }
