package canonicaljson

import (
	"bytes"
	"testing"
)

func FuzzCanonicalJSON(f *testing.F) {
	for _, raw := range []string{`{}`, `{"z":1,"a":[true,null,"text"]}`, `{"a":1,"a":2}`, `1e9`, `"中文"`, `{"invalid":NaN}`, `[] true`} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		first, err := CanonicalJSON(raw)
		if err != nil {
			return
		}
		second, err := CanonicalJSON(first)
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("canonical output is not idempotent: %v", err)
		}
	})
}
