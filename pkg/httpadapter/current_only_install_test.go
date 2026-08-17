package httpadapter

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/host"
)

func TestCurrentInstallRequestsRejectRetiredActivationFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		dst  any
	}{
		{
			name: "release install activation",
			body: `{"request_id":"request_1","plugin_instance_id":"plugini_1","release_ref":{},"activate_after_install":false}`,
			dst:  &startReleaseInstallExecutionRequest{},
		},
		{
			name: "release install approved permissions",
			body: `{"request_id":"request_1","plugin_instance_id":"plugini_1","release_ref":{},"approved_permission_ids":["read"]}`,
			dst:  &startReleaseInstallExecutionRequest{},
		},
		{
			name: "inspected package activation",
			body: `{"inspection_id":"inspect_1","expected_package_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","activate_after_install":true}`,
			dst:  &installInspectedPackageRequest{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := newJSONHTTPRequest(http.MethodPost, "/", strings.NewReader(test.body))
			if err := decodeJSON(req, test.dst); err == nil {
				t.Fatal("decodeJSON() accepted a retired install activation field")
			}
		})
	}
}

func TestCurrentInstalledPackageProjectionHasNoActivationLifecycle(t *testing.T) {
	projected, err := publicInstalledExternalPackage(host.InstalledExternalPackage{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"activation"`) {
		t.Fatalf("installed package projection retained activation lifecycle: %s", raw)
	}
}
