package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSurfaceWebWireRequiresExplicitClosedPolicy(t *testing.T) {
	for _, raw := range []string{`{"root":"ui"}`, `{"root":"ui","spa":null}`, `{"root":"ui","spa":false,"future":true}`, `null`} {
		var web SurfaceWebSpec
		if err := json.Unmarshal([]byte(raw), &web); err == nil {
			t.Errorf("accepted ambiguous Web policy: %s", raw)
		}
	}
	for _, raw := range []string{`{"root":"ui","spa":false}`, `{"root":"ui","spa":true}`} {
		var web SurfaceWebSpec
		if err := json.Unmarshal([]byte(raw), &web); err != nil {
			t.Errorf("rejected explicit Web policy: %v", err)
		}
	}
}

func TestSurfaceWebRootMatchesSchemaLengthBoundary(t *testing.T) {
	for _, size := range []int{512, 513} {
		root := strings.Repeat("a", size)
		err := validateSurfaceWeb(SurfaceSpec{Entry: root + "/index.html", Web: SurfaceWebSpec{Root: root}})
		if (err == nil) != (size == 512) {
			t.Errorf("root length %d: %v", size, err)
		}
	}
}
