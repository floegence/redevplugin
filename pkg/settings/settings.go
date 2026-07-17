package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/floegence/redevplugin/pkg/manifest"
)

const (
	FieldString  = "string"
	FieldBoolean = "boolean"
	FieldNumber  = "number"
	FieldInteger = "integer"
	FieldEnum    = "enum"
	FieldSelect  = "select"
	FieldSecret  = "secret"

	maxJSONSafeInteger = int64(1<<53 - 1)
)

var ErrInvalidSetting = errors.New("plugin setting is invalid")

type Schema struct {
	SchemaVersion int     `json:"schema_version"`
	Fields        []Field `json:"fields,omitempty"`
}

type Field struct {
	Key        string          `json:"key"`
	Type       string          `json:"type"`
	Scope      string          `json:"scope"`
	Options    []string        `json:"options,omitempty"`
	Default    json.RawMessage `json:"default,omitempty"`
	Validation *Validation     `json:"validation,omitempty"`
}

type Validation struct {
	Minimum   *float64 `json:"minimum,omitempty"`
	Maximum   *float64 `json:"maximum,omitempty"`
	MinLength *uint64  `json:"min_length,omitempty"`
	MaxLength *uint64  `json:"max_length,omitempty"`
}

func CanonicalSchema(spec *manifest.SettingsSpec) (Schema, error) {
	if spec == nil {
		return Schema{}, nil
	}
	fields, err := NonSecretFields(spec)
	if err != nil {
		return Schema{}, err
	}
	return Schema{SchemaVersion: spec.SchemaVersion, Fields: fields}, nil
}

func CanonicalizeSchema(schema Schema) (Schema, error) {
	if schema.SchemaVersion < 0 || schema.SchemaVersion == 0 && len(schema.Fields) != 0 {
		return Schema{}, fmt.Errorf("%w: schema_version must be positive when fields are declared", ErrInvalidSetting)
	}
	fields, err := normalizeFields(schema.Fields)
	if err != nil {
		return Schema{}, err
	}
	return Schema{SchemaVersion: schema.SchemaVersion, Fields: fields}, nil
}

func CanonicalSchemaJSON(spec *manifest.SettingsSpec) ([]byte, error) {
	schema, err := CanonicalSchema(spec)
	if err != nil {
		return nil, err
	}
	return json.Marshal(schema)
}

func NonSecretFields(spec *manifest.SettingsSpec) ([]Field, error) {
	if spec == nil {
		return nil, nil
	}
	if spec.SchemaVersion <= 0 {
		return nil, fmt.Errorf("%w: schema_version must be positive", ErrInvalidSetting)
	}
	fields := make([]Field, 0, len(spec.Fields))
	seen := make(map[string]struct{}, len(spec.Fields))
	for i, source := range spec.Fields {
		key := strings.TrimSpace(source.Key)
		fieldType := strings.TrimSpace(source.Type)
		scope := strings.TrimSpace(source.Scope)
		if key == "" {
			return nil, fmt.Errorf("%w: fields[%d].key is required", ErrInvalidSetting, i)
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("%w: fields[%d].key must be unique", ErrInvalidSetting, i)
		}
		seen[key] = struct{}{}
		if scope != "user" && scope != "environment" {
			return nil, fmt.Errorf("%w: fields[%d].scope must be user or environment", ErrInvalidSetting, i)
		}
		if !supportedType(fieldType) {
			return nil, fmt.Errorf("%w: fields[%d].type is unsupported", ErrInvalidSetting, i)
		}
		if fieldType == FieldSecret {
			if strings.TrimSpace(source.SecretRef) == "" {
				return nil, fmt.Errorf("%w: fields[%d].secret_ref is required", ErrInvalidSetting, i)
			}
			if source.Default != nil || len(source.Options) != 0 || len(source.Validation) != 0 {
				return nil, fmt.Errorf("%w: fields[%d] secret settings cannot declare data defaults, options, or validation", ErrInvalidSetting, i)
			}
			continue
		}
		if strings.TrimSpace(source.SecretRef) != "" {
			return nil, fmt.Errorf("%w: fields[%d].secret_ref is only allowed for secrets", ErrInvalidSetting, i)
		}

		field := Field{Key: key, Type: fieldType, Scope: scope}
		options, err := normalizeOptions(source, i)
		if err != nil {
			return nil, err
		}
		field.Options = options
		validation, err := normalizeValidation(source, i)
		if err != nil {
			return nil, err
		}
		field.Validation = validation
		if source.Default != nil {
			normalized, err := normalizeValue(field, source.Default)
			if err != nil {
				return nil, fmt.Errorf("fields[%d].default: %w", i, err)
			}
			field.Default, err = json.Marshal(normalized)
			if err != nil {
				return nil, fmt.Errorf("fields[%d].default: %w", i, err)
			}
		}
		fields = append(fields, field)
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Key < fields[j].Key })
	return fields, nil
}

func DefaultValues(fields []Field) (map[string]json.RawMessage, error) {
	fields, err := normalizeFields(fields)
	if err != nil {
		return nil, err
	}
	values := make(map[string]json.RawMessage)
	for _, field := range fields {
		if field.Default != nil {
			values[field.Key] = cloneRaw(field.Default)
		}
	}
	return values, nil
}

func NormalizeRawValues(fields []Field, values map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	fields, err := normalizeFields(fields)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]Field, len(fields))
	for _, field := range fields {
		byKey[field.Key] = field
	}
	normalized := make(map[string]json.RawMessage, len(values))
	for key, raw := range values {
		field, ok := byKey[key]
		if !ok {
			return nil, fmt.Errorf("%w: setting %q is not declared", ErrInvalidSetting, key)
		}
		value, err := decodeJSONValue(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: setting %q: %v", ErrInvalidSetting, key, err)
		}
		value, err = normalizeValue(field, value)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("%w: setting %q: %v", ErrInvalidSetting, key, err)
		}
		normalized[key] = encoded
	}
	return normalized, nil
}

func DecodeValues(values map[string]json.RawMessage) (map[string]any, error) {
	decoded := make(map[string]any, len(values))
	for key, raw := range values {
		value, err := decodeJSONValue(raw)
		if err != nil {
			return nil, fmt.Errorf("decode setting %q: %w", key, err)
		}
		decoded[key] = value
	}
	return decoded, nil
}

func normalizeFields(fields []Field) ([]Field, error) {
	normalized := make([]Field, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for i, field := range fields {
		field.Key = strings.TrimSpace(field.Key)
		field.Type = strings.TrimSpace(field.Type)
		field.Scope = strings.TrimSpace(field.Scope)
		if field.Key == "" {
			return nil, fmt.Errorf("%w: fields[%d].key is required", ErrInvalidSetting, i)
		}
		if _, exists := seen[field.Key]; exists {
			return nil, fmt.Errorf("%w: fields[%d].key must be unique", ErrInvalidSetting, i)
		}
		seen[field.Key] = struct{}{}
		if field.Scope != "user" && field.Scope != "environment" {
			return nil, fmt.Errorf("%w: fields[%d].scope must be user or environment", ErrInvalidSetting, i)
		}
		if field.Type == FieldSecret || !supportedType(field.Type) {
			return nil, fmt.Errorf("%w: fields[%d].type is not a non-secret settings type", ErrInvalidSetting, i)
		}
		options, err := normalizeFieldOptions(field, i)
		if err != nil {
			return nil, err
		}
		field.Options = options
		field.Validation = cloneValidation(field.Validation)
		if validationEmpty(field.Validation) {
			field.Validation = nil
		}
		if err := validateCanonicalValidation(field, i); err != nil {
			return nil, err
		}
		if field.Default != nil {
			value, err := decodeJSONValue(field.Default)
			if err != nil {
				return nil, fmt.Errorf("fields[%d].default: %w", i, err)
			}
			normalizedValue, err := normalizeValue(field, value)
			if err != nil {
				return nil, fmt.Errorf("fields[%d].default: %w", i, err)
			}
			field.Default, err = json.Marshal(normalizedValue)
			if err != nil {
				return nil, fmt.Errorf("fields[%d].default: %w", i, err)
			}
		}
		normalized[i] = field
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Key < normalized[j].Key })
	return normalized, nil
}

func normalizeOptions(source manifest.SettingFieldSpec, fieldIndex int) ([]string, error) {
	field := Field{Type: strings.TrimSpace(source.Type), Options: source.Options}
	return normalizeFieldOptions(field, fieldIndex)
}

func normalizeFieldOptions(field Field, fieldIndex int) ([]string, error) {
	if field.Type != FieldEnum && field.Type != FieldSelect {
		if len(field.Options) != 0 {
			return nil, fmt.Errorf("%w: fields[%d].options is only allowed for enum or select settings", ErrInvalidSetting, fieldIndex)
		}
		return nil, nil
	}
	if len(field.Options) == 0 {
		return nil, fmt.Errorf("%w: fields[%d].options is required", ErrInvalidSetting, fieldIndex)
	}
	options := make([]string, len(field.Options))
	seen := make(map[string]struct{}, len(field.Options))
	for i, option := range field.Options {
		option = strings.TrimSpace(option)
		if option == "" {
			return nil, fmt.Errorf("%w: fields[%d].options[%d] must not be empty", ErrInvalidSetting, fieldIndex, i)
		}
		if _, exists := seen[option]; exists {
			return nil, fmt.Errorf("%w: fields[%d].options must be unique", ErrInvalidSetting, fieldIndex)
		}
		seen[option] = struct{}{}
		options[i] = option
	}
	sort.Strings(options)
	return options, nil
}

func normalizeValidation(source manifest.SettingFieldSpec, fieldIndex int) (*Validation, error) {
	if len(source.Validation) == 0 {
		return nil, nil
	}
	allowed := map[string]bool{}
	switch strings.TrimSpace(source.Type) {
	case FieldString:
		allowed["min_length"] = true
		allowed["max_length"] = true
	case FieldNumber, FieldInteger:
		allowed["minimum"] = true
		allowed["maximum"] = true
	}
	for key := range source.Validation {
		if !allowed[key] {
			return nil, fmt.Errorf("%w: fields[%d].validation.%s is unsupported for type %s", ErrInvalidSetting, fieldIndex, key, source.Type)
		}
	}
	validation := &Validation{}
	var err error
	if raw, ok := source.Validation["minimum"]; ok {
		validation.Minimum, err = finiteFloatPointer(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: fields[%d].validation.minimum %v", ErrInvalidSetting, fieldIndex, err)
		}
	}
	if raw, ok := source.Validation["maximum"]; ok {
		validation.Maximum, err = finiteFloatPointer(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: fields[%d].validation.maximum %v", ErrInvalidSetting, fieldIndex, err)
		}
	}
	if raw, ok := source.Validation["min_length"]; ok {
		validation.MinLength, err = nonNegativeIntegerPointer(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: fields[%d].validation.min_length %v", ErrInvalidSetting, fieldIndex, err)
		}
	}
	if raw, ok := source.Validation["max_length"]; ok {
		validation.MaxLength, err = nonNegativeIntegerPointer(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: fields[%d].validation.max_length %v", ErrInvalidSetting, fieldIndex, err)
		}
	}
	field := Field{Type: strings.TrimSpace(source.Type), Validation: validation}
	if err := validateCanonicalValidation(field, fieldIndex); err != nil {
		return nil, err
	}
	return validation, nil
}

func validateCanonicalValidation(field Field, fieldIndex int) error {
	validation := field.Validation
	if validation == nil {
		return nil
	}
	switch field.Type {
	case FieldString:
		if validation.Minimum != nil || validation.Maximum != nil {
			return fmt.Errorf("%w: fields[%d].validation has numeric constraints for a string", ErrInvalidSetting, fieldIndex)
		}
		if validation.MinLength != nil && validation.MaxLength != nil && *validation.MinLength > *validation.MaxLength {
			return fmt.Errorf("%w: fields[%d].validation.min_length exceeds max_length", ErrInvalidSetting, fieldIndex)
		}
	case FieldNumber, FieldInteger:
		if validation.MinLength != nil || validation.MaxLength != nil {
			return fmt.Errorf("%w: fields[%d].validation has length constraints for a number", ErrInvalidSetting, fieldIndex)
		}
		for name, value := range map[string]*float64{"minimum": validation.Minimum, "maximum": validation.Maximum} {
			if value != nil && (math.IsNaN(*value) || math.IsInf(*value, 0)) {
				return fmt.Errorf("%w: fields[%d].validation.%s must be finite", ErrInvalidSetting, fieldIndex, name)
			}
		}
		if validation.Minimum != nil && validation.Maximum != nil && *validation.Minimum > *validation.Maximum {
			return fmt.Errorf("%w: fields[%d].validation.minimum exceeds maximum", ErrInvalidSetting, fieldIndex)
		}
	default:
		return fmt.Errorf("%w: fields[%d].validation is unsupported for type %s", ErrInvalidSetting, fieldIndex, field.Type)
	}
	return nil
}

func decodeJSONValue(raw json.RawMessage) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

func normalizeValue(field Field, value any) (any, error) {
	switch field.Type {
	case FieldString:
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: setting %q must be a string", ErrInvalidSetting, field.Key)
		}
		length := uint64(utf8.RuneCountInString(text))
		if field.Validation != nil && field.Validation.MinLength != nil && length < *field.Validation.MinLength {
			return nil, fmt.Errorf("%w: setting %q is shorter than min_length", ErrInvalidSetting, field.Key)
		}
		if field.Validation != nil && field.Validation.MaxLength != nil && length > *field.Validation.MaxLength {
			return nil, fmt.Errorf("%w: setting %q exceeds max_length", ErrInvalidSetting, field.Key)
		}
		return text, nil
	case FieldBoolean:
		boolean, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("%w: setting %q must be a boolean", ErrInvalidSetting, field.Key)
		}
		return boolean, nil
	case FieldNumber, FieldInteger:
		number, ok := numberValue(value)
		if !ok {
			return nil, fmt.Errorf("%w: setting %q must be a finite %s", ErrInvalidSetting, field.Key, field.Type)
		}
		if field.Type == FieldInteger {
			if math.Trunc(number) != number || number < -float64(maxJSONSafeInteger) || number > float64(maxJSONSafeInteger) {
				return nil, fmt.Errorf("%w: setting %q must be a JSON-safe integer", ErrInvalidSetting, field.Key)
			}
		}
		if field.Validation != nil && field.Validation.Minimum != nil && number < *field.Validation.Minimum {
			return nil, fmt.Errorf("%w: setting %q is below minimum", ErrInvalidSetting, field.Key)
		}
		if field.Validation != nil && field.Validation.Maximum != nil && number > *field.Validation.Maximum {
			return nil, fmt.Errorf("%w: setting %q exceeds maximum", ErrInvalidSetting, field.Key)
		}
		if field.Type == FieldInteger {
			return int64(number), nil
		}
		if number == 0 {
			return float64(0), nil
		}
		return number, nil
	case FieldEnum, FieldSelect:
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: setting %q must be an option string", ErrInvalidSetting, field.Key)
		}
		index := sort.SearchStrings(field.Options, text)
		if index >= len(field.Options) || field.Options[index] != text {
			return nil, fmt.Errorf("%w: setting %q must match a declared option", ErrInvalidSetting, field.Key)
		}
		return text, nil
	default:
		return nil, fmt.Errorf("%w: setting %q has unsupported type %q", ErrInvalidSetting, field.Key, field.Type)
	}
}

func finiteFloatPointer(value any) (*float64, error) {
	number, ok := numberValue(value)
	if !ok {
		return nil, errors.New("must be a finite number")
	}
	return &number, nil
}

func nonNegativeIntegerPointer(value any) (*uint64, error) {
	number, ok := numberValue(value)
	if !ok || math.Trunc(number) != number || number < 0 || number > float64(maxJSONSafeInteger) {
		return nil, errors.New("must be a non-negative JSON-safe integer")
	}
	integer := uint64(number)
	return &integer, nil
}

func numberValue(value any) (float64, bool) {
	var number float64
	switch value := value.(type) {
	case json.Number:
		var err error
		number, err = value.Float64()
		if err != nil {
			return 0, false
		}
	case float64:
		number = value
	case float32:
		number = float64(value)
	case int:
		number = float64(value)
	case int8:
		number = float64(value)
	case int16:
		number = float64(value)
	case int32:
		number = float64(value)
	case int64:
		number = float64(value)
	case uint:
		number = float64(value)
	case uint8:
		number = float64(value)
	case uint16:
		number = float64(value)
	case uint32:
		number = float64(value)
	case uint64:
		number = float64(value)
	default:
		return 0, false
	}
	return number, !math.IsNaN(number) && !math.IsInf(number, 0)
}

func supportedType(fieldType string) bool {
	switch fieldType {
	case FieldString, FieldBoolean, FieldNumber, FieldInteger, FieldEnum, FieldSelect, FieldSecret:
		return true
	default:
		return false
	}
}

func cloneRaw(value json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), value...)
}

func cloneValidation(value *Validation) *Validation {
	if value == nil {
		return nil
	}
	cloned := *value
	if value.Minimum != nil {
		item := *value.Minimum
		cloned.Minimum = &item
	}
	if value.Maximum != nil {
		item := *value.Maximum
		cloned.Maximum = &item
	}
	if value.MinLength != nil {
		item := *value.MinLength
		cloned.MinLength = &item
	}
	if value.MaxLength != nil {
		item := *value.MaxLength
		cloned.MaxLength = &item
	}
	return &cloned
}

func validationEmpty(value *Validation) bool {
	return value != nil && value.Minimum == nil && value.Maximum == nil && value.MinLength == nil && value.MaxLength == nil
}
