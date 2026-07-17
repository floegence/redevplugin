package manifest

import (
	"bytes"
	"testing"
)

// FuzzDecode keeps strict manifest decoding total for arbitrary JSON and
// arbitrary bytes. Validation errors are expected; panics are not.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"schema_version":"redevplugin.manifest.v5"}`))
	f.Add([]byte(`{"schema_version":"redevplugin.manifest.v4"}`))
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Decode(bytes.NewReader(input))
	})
}
