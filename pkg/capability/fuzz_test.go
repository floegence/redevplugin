package capability

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzPrepareResponseData exercises the adapter response boundary with JSON
// values of arbitrary shape. Normalization and redaction must remain
// deterministic and panic-free for both accepted and rejected values.
func FuzzPrepareResponseData(f *testing.F) {
	f.Add([]byte(`{"password":"secret","nested":[1,true,null]}`))
	f.Add([]byte(`{"mounts":[{"source":"/home/user/.ssh/id_rsa"}]}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, input []byte) {
		decoder := json.NewDecoder(bytes.NewReader(input))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return
		}
		_, _ = PrepareResponseData(value)
	})
}
