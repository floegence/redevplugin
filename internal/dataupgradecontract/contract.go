// Package dataupgradecontract validates the canonical isolated conversion wire.
package dataupgradecontract

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schema.gen.json
var schemaBytes []byte
var compiled = sync.OnceValues(func() (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft2020
	const id = "urn:redevplugin:data-upgrade"
	if err := c.AddResource(id, bytes.NewReader(schemaBytes)); err != nil {
		return nil, err
	}
	return c.Compile(id)
})

// Validate checks only the closed wire. Dataset authority, paths, store quotas
// and lifecycle state remain enforced by the Host and plugin-data broker.
func Validate(raw []byte) error {
	schema, err := compiled()
	if err != nil {
		return err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	return schema.Validate(value)
}
