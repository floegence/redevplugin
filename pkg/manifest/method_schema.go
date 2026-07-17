package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

const (
	maxMethodSchemaBytes = 256 << 10
	maxMethodSchemaDepth = 64
	maxMethodSchemaNodes = 4096
)

var allowedMethodSchemaKeywords = map[string]struct{}{
	"$comment": {}, "title": {}, "description": {}, "readOnly": {}, "writeOnly": {},
	"$ref": {}, "$defs": {}, "type": {}, "properties": {}, "patternProperties": {}, "required": {}, "additionalProperties": {},
	"items": {}, "allOf": {}, "anyOf": {}, "oneOf": {}, "enum": {}, "const": {},
	"default": {}, "examples": {}, "minimum": {}, "maximum": {}, "exclusiveMinimum": {},
	"exclusiveMaximum": {}, "multipleOf": {}, "minLength": {}, "maxLength": {}, "pattern": {},
	"format": {}, "minItems": {}, "maxItems": {}, "uniqueItems": {}, "minProperties": {}, "maxProperties": {},
}

// CompiledMethodSchemas holds the closed request and response contracts for one
// manifest method. The compiled validators are safe for concurrent validation.
type CompiledMethodSchemas struct {
	request  *jsonschema.Schema
	response *jsonschema.Schema
}

type methodSchemaError struct {
	path    string
	message string
}

func (e methodSchemaError) Error() string {
	if e.path == "" {
		return e.message
	}
	return e.path + ": " + e.message
}

// CompileMethodSchemas validates and compiles a method's JSON Schema contracts.
// Remote schema loading is disabled so package validation remains deterministic
// and cannot perform network I/O.
func CompileMethodSchemas(method MethodSpec) (*CompiledMethodSchemas, error) {
	request, err := compileClosedObjectSchema("request_schema", method.RequestSchema)
	if err != nil {
		return nil, err
	}
	response, err := compileClosedObjectSchema("response_schema", method.ResponseSchema)
	if err != nil {
		return nil, err
	}
	return &CompiledMethodSchemas{request: request, response: response}, nil
}

func (s *CompiledMethodSchemas) ValidateRequest(value map[string]any) error {
	if value == nil {
		value = map[string]any{}
	}
	return s.request.Validate(value)
}

func (s *CompiledMethodSchemas) ValidateResponse(value any) error {
	return s.response.Validate(value)
}

func compileClosedObjectSchema(name string, schema map[string]any) (*jsonschema.Schema, error) {
	if schema == nil {
		return nil, methodSchemaError{path: name, message: "is required"}
	}
	if schemaType, ok := schema["type"].(string); !ok || schemaType != "object" {
		return nil, methodSchemaError{path: name + ".type", message: "must be object"}
	}

	nodes := 0
	if err := validateClosedSchemaNode(schema, name, 0, &nodes); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		return nil, methodSchemaError{path: name, message: "must be valid JSON: " + err.Error()}
	}
	if len(raw) > maxMethodSchemaBytes {
		return nil, methodSchemaError{path: name, message: fmt.Sprintf("exceeds %d bytes", maxMethodSchemaBytes)}
	}

	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.LoadURL = func(string) (io.ReadCloser, error) {
		return nil, errors.New("external schema resources are forbidden")
	}
	resource := "urn:redevplugin:manifest:" + name
	if err := compiler.AddResource(resource, bytes.NewReader(raw)); err != nil {
		return nil, methodSchemaError{path: name, message: "is invalid: " + err.Error()}
	}
	compiled, err := compiler.Compile(resource)
	if err != nil {
		return nil, methodSchemaError{path: name, message: "is invalid: " + err.Error()}
	}
	return compiled, nil
}

func validateClosedSchemaNode(value any, path string, depth int, nodes *int) error {
	if depth > maxMethodSchemaDepth {
		return methodSchemaError{path: path, message: fmt.Sprintf("exceeds maximum depth %d", maxMethodSchemaDepth)}
	}
	*nodes++
	if *nodes > maxMethodSchemaNodes {
		return methodSchemaError{path: path, message: fmt.Sprintf("exceeds maximum node count %d", maxMethodSchemaNodes)}
	}

	switch node := value.(type) {
	case bool:
		if node {
			return methodSchemaError{path: path, message: "unconstrained true schemas are forbidden"}
		}
	case map[string]any:
		for keyword := range node {
			if _, ok := allowedMethodSchemaKeywords[keyword]; !ok {
				return methodSchemaError{path: path, message: fmt.Sprintf("keyword %q is not supported by the closed method-schema subset", keyword)}
			}
		}
		if !schemaDeclaresValueDomain(node) {
			return methodSchemaError{path: path, message: "must declare an explicit type, object contract, finite value, or composition"}
		}
		if ref, ok := node["$ref"].(string); ok && !strings.HasPrefix(ref, "#/$defs/") {
			return methodSchemaError{path: path + ".$ref", message: "must reference a local $defs schema"}
		}
		if schemaCanMatchObject(node) {
			additional, ok := node["additionalProperties"].(bool)
			if !ok || additional {
				return methodSchemaError{path: path + ".additionalProperties", message: "must be false for object schemas"}
			}
		}
		if err := validateSchemaMapKeywords(node, path, depth, nodes); err != nil {
			return err
		}
		if err := validateSchemaArrayKeywords(node, path, depth, nodes); err != nil {
			return err
		}
		if err := validateSchemaSingleKeywords(node, path, depth, nodes); err != nil {
			return err
		}
	}
	return nil
}

func schemaDeclaresValueDomain(node map[string]any) bool {
	if _, ok := node["type"]; ok {
		return true
	}
	if _, ok := node["$ref"]; ok {
		return true
	}
	for _, keyword := range []string{
		"properties",
		"patternProperties",
		"additionalProperties",
		"required",
		"minProperties",
		"maxProperties",
		"allOf",
		"anyOf",
		"oneOf",
		"const",
		"enum",
	} {
		if _, ok := node[keyword]; ok {
			return true
		}
	}
	return false
}

func validateSchemaMapKeywords(node map[string]any, path string, depth int, nodes *int) error {
	for _, keyword := range []string{"$defs", "properties", "patternProperties"} {
		children, ok := node[keyword].(map[string]any)
		if !ok {
			continue
		}
		for name, child := range children {
			if err := validateClosedSchemaNode(child, path+"."+keyword+"."+name, depth+1, nodes); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSchemaArrayKeywords(node map[string]any, path string, depth int, nodes *int) error {
	for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
		children, ok := node[keyword].([]any)
		if !ok {
			continue
		}
		for i, child := range children {
			if err := validateClosedSchemaNode(child, fmt.Sprintf("%s.%s[%d]", path, keyword, i), depth+1, nodes); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSchemaSingleKeywords(node map[string]any, path string, depth int, nodes *int) error {
	for _, keyword := range []string{"items"} {
		child, ok := node[keyword]
		if !ok {
			continue
		}
		switch child.(type) {
		case map[string]any, bool:
			if err := validateClosedSchemaNode(child, path+"."+keyword, depth+1, nodes); err != nil {
				return err
			}
		}
	}
	return nil
}

func schemaCanMatchObject(node map[string]any) bool {
	switch schemaType := node["type"].(type) {
	case string:
		if schemaType == "object" {
			return true
		}
	case []any:
		for _, candidate := range schemaType {
			if candidate == "object" {
				return true
			}
		}
	}
	for _, keyword := range []string{
		"properties",
		"patternProperties",
		"additionalProperties",
		"required",
		"minProperties",
		"maxProperties",
	} {
		if _, ok := node[keyword]; ok {
			return true
		}
	}
	return false
}
