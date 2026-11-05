package httpadapter

import (
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
			dst:  &host.StartInspectedInstallRequest{},
		},
		{
			name: "release install approved permissions",
			body: `{"request_id":"request_1","plugin_instance_id":"plugini_1","release_ref":{},"approved_permission_ids":["read"]}`,
			dst:  &host.StartInspectedInstallRequest{},
		},
		{
			name: "inspected package activation",
			body: `{"inspection_id":"inspect_1","expected_package_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","activate_after_install":true}`,
			dst:  &host.StartInspectedInstallRequest{},
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
