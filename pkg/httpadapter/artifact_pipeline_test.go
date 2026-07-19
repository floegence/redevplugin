package httpadapter

import "testing"

func TestLocalImportRoutesUseBoundedBinaryEndpoints(t *testing.T) {
	routes := map[string]bool{}
	for _, route := range RouteSet() {
		routes[route.Method+" "+route.Path] = true
	}
	for _, route := range []string{
		"POST /_redevplugin/api/plugins/{plugin_instance_id}/local-import",
		"PUT /_redevplugin/api/plugins/{plugin_instance_id}/local-import",
	} {
		if !routes[route] {
			t.Fatalf("missing local import route %q", route)
		}
	}
}
