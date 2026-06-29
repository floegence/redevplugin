package httpadapter

import "testing"

func TestRouteSetHasManagementAndSandboxRoutes(t *testing.T) {
	routes := RouteSet()
	want := map[string]bool{
		"POST /_redeven_proxy/api/plugins/install":     false,
		"POST /_redeven_proxy/api/plugins/enable":      false,
		"POST /_redeven_proxy/api/plugins/rpc":         false,
		"POST /_redeven_proxy/api/plugins/data/export": false,
		"POST /_redeven_plugin/bootstrap":              false,
		"GET /_redeven_plugin/assets/{asset_path...}":  false,
		"POST /_redeven_plugin/csp-report":             false,
	}
	for _, route := range routes {
		key := route.Method + " " + route.Path
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Fatalf("RouteSet() missing %s", key)
		}
	}
}
