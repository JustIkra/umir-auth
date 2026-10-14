package protocol

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed ua1-control-wire.schema.json
var ua1ControlWireSchema []byte

//go:embed ua1-control-wire.binding.json
var ua1ControlWireBinding []byte

var ua1ControlWirePool sync.Pool
var ua1ControlWireOnce sync.Once
var ua1ControlWireCompileError error

type ua1WireRegexp struct {
	pattern *regexp.Regexp
	budget  *matchBudget
}

func (r *ua1WireRegexp) String() string { return r.pattern.String() }
func (r *ua1WireRegexp) MatchString(input string) bool {
	r.budget.check()
	r.budget.remaining--
	if r.budget.remaining < 0 || len(input) > schemaInputLimit {
		panic(schemaMatchFailure{errors.New("fixture schema matching work bound")})
	}
	matched := r.pattern.MatchString(input)
	r.budget.check()
	return matched
}

func compileUA1WirePattern(budget *matchBudget, pattern string) (jsonschema.Regexp, error) {
	switch pattern {
	case `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, `^[0-9a-f]{64}$`, `^[1-9][0-9]{0,18}$`, `^umir-backend-[0-9a-f]{24}$`:
	default:
		return nil, errors.New("unqualified control wire pattern")
	}
	r, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &ua1WireRegexp{pattern: r, budget: budget}, nil
}

func compileUA1ControlWire() (v *schemaValidator, err error) {
	defer recoverSchemaMatch(&err)
	var binding struct{ Supplement, SchemaSHA256, ControlLibraryBindingSHA256, DiscoveryBindingSHA256 string }
	if SHA(ua1ControlWireBinding) != UA1ControlWireBindingSHA256 || json.Unmarshal(ua1ControlWireBinding, &binding) != nil || binding.Supplement != UA1ControlWireSupplement || binding.SchemaSHA256 != SHA(ua1ControlWireSchema) || binding.ControlLibraryBindingSHA256 != UA1ControlBindingSHA256 || binding.DiscoveryBindingSHA256 != UA1BindingSHA256 {
		return nil, errors.New("UA1 control wire binding mismatch")
	}
	v = &schemaValidator{schemas: map[string]*jsonschema.Schema{}}
	v.budget.reset(2 * time.Second)
	resource, err := jsonschema.UnmarshalJSON(bytes.NewReader(ua1ControlWireSchema))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) { return compileUA1WirePattern(&v.budget, pattern) })
	if err = compiler.AddResource("ua1-control-wire.json", resource); err != nil {
		return nil, err
	}
	var definitions struct {
		Definitions map[string]json.RawMessage `json:"$defs"`
	}
	if err = json.Unmarshal(ua1ControlWireSchema, &definitions); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(definitions.Definitions))
	for name := range definitions.Definitions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		schema, err := compiler.Compile("ua1-control-wire.json#/$defs/" + name)
		if err != nil {
			return nil, err
		}
		v.schemas[name] = schema
	}
	return v, nil
}

func validateUA1ControlWire(name string, body []byte) error {
	if len(body) > MaxResponse || checkDocument(body) != nil {
		return errors.New("invalid UA1 control wire JSON")
	}
	ua1ControlWireOnce.Do(func() {
		v, err := compileUA1ControlWire()
		ua1ControlWireCompileError = err
		if err == nil {
			ua1ControlWirePool.Put(v)
		}
	})
	if ua1ControlWireCompileError != nil {
		return ua1ControlWireCompileError
	}
	var v *schemaValidator
	if pooled := ua1ControlWirePool.Get(); pooled != nil {
		var ok bool
		v, ok = pooled.(*schemaValidator)
		if !ok {
			return errors.New("invalid control wire validator")
		}
	} else {
		var err error
		v, err = compileUA1ControlWire()
		if err != nil {
			return err
		}
	}
	defer ua1ControlWirePool.Put(v)
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		return err
	}
	return v.validate(name, value)
}
