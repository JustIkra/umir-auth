package protocol

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed ua1.schema.json
var ua1SchemaJSON []byte

//go:embed ua1.binding.json
var ua1BindingJSON []byte

var ua1SchemaPool sync.Pool
var ua1SchemaOnce sync.Once
var ua1SchemaError error

func compileUA1Schemas() (validator *schemaValidator, err error) {
	defer recoverSchemaMatch(&err)
	var binding struct {
		Supplement   string `json:"supplement"`
		SchemaSHA256 string `json:"schemaSHA256"`
	}
	if SHA(ua1BindingJSON) != UA1BindingSHA256 || json.Unmarshal(ua1BindingJSON, &binding) != nil || binding.Supplement != UA1Supplement || binding.SchemaSHA256 != SHA(ua1SchemaJSON) {
		return nil, errors.New("UA1 supplement bytes do not match binding")
	}
	resource, err := jsonschema.UnmarshalJSON(bytes.NewReader(ua1SchemaJSON))
	if err != nil {
		return nil, err
	}
	validator = &schemaValidator{schemas: map[string]*jsonschema.Schema{}}
	validator.budget.reset(2 * time.Second)
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	compiler.UseRegexpEngine(validator.budget.compile)
	if err := compiler.AddResource("ua1.json", resource); err != nil {
		return nil, err
	}
	var definitions struct {
		Definitions map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(ua1SchemaJSON, &definitions); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(definitions.Definitions))
	for name := range definitions.Definitions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		schema, err := compiler.Compile("ua1.json#/$defs/" + name)
		if err != nil {
			return nil, err
		}
		validator.schemas[name] = schema
	}
	return validator, nil
}

func validateUA1(name string, data []byte) error {
	if len(data) > MaxResponse {
		return errors.New("UA1 schema input bound")
	}
	if err := checkDocument(data); err != nil {
		return err
	}
	ua1SchemaOnce.Do(func() {
		var validator *schemaValidator
		validator, ua1SchemaError = compileUA1Schemas()
		if ua1SchemaError == nil {
			ua1SchemaPool.Put(validator)
		}
	})
	if ua1SchemaError != nil {
		return ua1SchemaError
	}
	var validator *schemaValidator
	if pooled := ua1SchemaPool.Get(); pooled != nil {
		var ok bool
		validator, ok = pooled.(*schemaValidator)
		if !ok {
			return errors.New("invalid UA1 validator")
		}
	} else {
		var err error
		validator, err = compileUA1Schemas()
		if err != nil {
			return err
		}
	}
	defer ua1SchemaPool.Put(validator)
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return validator.validate(name, value)
}
