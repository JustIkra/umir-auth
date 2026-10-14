package jsonstore

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func decode(data []byte) (domain.ValidatedAggregate, error) {
	if !utf8.Valid(data) || !unicodeEscapes(data) {
		return domain.ValidatedAggregate{}, domain.ErrInvalidAggregate
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := shape(d, reflect.TypeFor[domain.Aggregate]()); err != nil {
		return domain.ValidatedAggregate{}, err
	}
	if _, err := d.Token(); err != io.EOF {
		return domain.ValidatedAggregate{}, domain.ErrInvalidAggregate
	}
	var a domain.Aggregate
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&a); err != nil {
		return domain.ValidatedAggregate{}, err
	}
	if a.SchemaVersion == 1 {
		var legacy struct {
			MailJobs    []map[string]json.RawMessage `json:"mailJobs"`
			Idempotency []map[string]json.RawMessage `json:"idempotency"`
		}
		if err := json.Unmarshal(data, &legacy); err != nil {
			return domain.ValidatedAggregate{}, err
		}
		for _, j := range legacy.MailJobs {
			if _, exists := j["purpose"]; exists {
				return domain.ValidatedAggregate{}, domain.ErrInvalidAggregate
			}
			if _, exists := j["enqueueOrder"]; exists {
				return domain.ValidatedAggregate{}, domain.ErrInvalidAggregate
			}
		}
		for _, r := range legacy.Idempotency {
			if _, exists := r["contractProfile"]; exists {
				return domain.ValidatedAggregate{}, domain.ErrInvalidAggregate
			}
		}
	}
	v, err := domain.Validate(a)
	if err != nil {
		return domain.ValidatedAggregate{}, err
	}
	if err := zones(v); err != nil {
		return domain.ValidatedAggregate{}, err
	}
	return v, nil
}
func shape(d *json.Decoder, t reflect.Type) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return domain.ErrInvalidAggregate
	}
	switch t.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return domain.ErrInvalidAggregate
		}
		fields := map[string]reflect.StructField{}
		required := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			fields[tag[0]] = f
			if len(tag) == 1 {
				required[tag[0]] = true
			}
		}
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return domain.ErrInvalidAggregate
			}
			f, ok := fields[key]
			if !ok {
				return domain.ErrInvalidAggregate
			}
			seen[key] = true
			if err := shape(d, f.Type); err != nil {
				return err
			}
		}
		for k := range required {
			if !seen[k] {
				return domain.ErrInvalidAggregate
			}
		}
		end, err := d.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return domain.ErrInvalidAggregate
		}
	case reflect.Slice:
		if token != json.Delim('[') {
			return domain.ErrInvalidAggregate
		}
		for d.More() {
			if err := shape(d, t.Elem()); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return domain.ErrInvalidAggregate
		}
	case reflect.String:
		if _, ok := token.(string); !ok {
			return domain.ErrInvalidAggregate
		}
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return domain.ErrInvalidAggregate
		}
	case reflect.Int:
		if _, ok := token.(json.Number); !ok {
			return domain.ErrInvalidAggregate
		}
	default:
		return domain.ErrInvalidAggregate
	}
	return nil
}
func zones(v domain.ValidatedAggregate) error {
	for _, o := range v.Snapshot().Organizations {
		if o.Settings.TimeZone == "Local" {
			return domain.ErrInvalidAggregate
		}
		if _, err := time.LoadLocation(o.Settings.TimeZone); err != nil {
			return domain.ErrInvalidAggregate
		}
	}
	return nil
}

func unicodeEscapes(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		code, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !inString
}
