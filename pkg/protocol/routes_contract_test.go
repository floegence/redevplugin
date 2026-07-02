package protocol

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/httpadapter"
)

type routeFixture struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type openAPIRequestBodyFixture struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func TestHTTPRouteSetMatchesFixture(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []routeFixture
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}

	got := make([]routeFixture, 0, len(httpadapter.RouteSet()))
	for _, route := range httpadapter.RouteSet() {
		got = append(got, routeFixture{Method: route.Method, Path: route.Path})
	}
	sortRoutes(fixtures)
	sortRoutes(got)
	if !reflect.DeepEqual(got, fixtures) {
		t.Fatalf("route set mismatch\n got: %#v\nwant: %#v", got, fixtures)
	}
}

func TestHTTPRouteSetMatchesOpenAPI(t *testing.T) {
	root := repoRoot(t)
	openAPIRoutes, err := readOpenAPIRoutes(filepath.Join(root, "spec", "openapi", "plugin-platform-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	got := make([]routeFixture, 0, len(httpadapter.RouteSet()))
	for _, route := range httpadapter.RouteSet() {
		got = append(got, routeFixture{Method: route.Method, Path: route.Path})
	}
	sortRoutes(openAPIRoutes)
	sortRoutes(got)
	if !reflect.DeepEqual(got, openAPIRoutes) {
		t.Fatalf("OpenAPI route set mismatch\n got: %#v\nwant: %#v", got, openAPIRoutes)
	}
}

func TestOpenAPIDefinesJSONRequestBodies(t *testing.T) {
	root := repoRoot(t)
	requestBodies, err := readOpenAPIRequestBodyRoutes(filepath.Join(root, "spec", "openapi", "plugin-platform-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[routeFixture]bool{}
	for _, route := range requestBodies {
		got[routeFixture(route)] = true
	}
	for _, route := range requiredJSONRequestBodyRoutes() {
		if !got[route] {
			t.Fatalf("OpenAPI route %s %s missing requestBody", route.Method, route.Path)
		}
	}
}

func TestOpenAPIRequestSchemasDefineCriticalFields(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, snippet := range []string{
		"BridgeTokenRequest:",
		"plugin_gateway_token: { type: string, minLength: 1 }",
		"delete_data: { type: boolean }",
		"asset_ticket: { type: string, minLength: 1 }",
		"ui_protocol_version: { const: plugin-ui-v1 }",
		"scope: { type: string, enum: [user, environment] }",
		"RetainedDataRecord:",
		"RetainedDataCleanupResult:",
		"PLUGIN_RETAINED_DATA_CLEANUP_FAILED",
		"PLUGIN_RETAINED_DATA_BIND_FAILED",
	} {
		if !strings.Contains(text, snippet) {
			t.Fatalf("OpenAPI schema missing snippet %q", snippet)
		}
	}
}

func readOpenAPIRoutes(path string) ([]routeFixture, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var routes []routeFixture
	var currentPath string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "components:") {
			currentPath = ""
			continue
		}
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":") {
			currentPath = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		if currentPath == "" {
			continue
		}
		switch line {
		case "    get:":
			routes = append(routes, routeFixture{Method: "GET", Path: currentPath})
		case "    patch:":
			routes = append(routes, routeFixture{Method: "PATCH", Path: currentPath})
		case "    post:":
			routes = append(routes, routeFixture{Method: "POST", Path: currentPath})
		}
	}
	return routes, scanner.Err()
}

func readOpenAPIRequestBodyRoutes(path string) ([]openAPIRequestBodyFixture, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var routes []openAPIRequestBodyFixture
	var currentPath string
	var currentMethod string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "components:") {
			break
		}
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":") {
			currentPath = strings.TrimSuffix(strings.TrimSpace(line), ":")
			currentMethod = ""
			continue
		}
		if currentPath == "" {
			continue
		}
		switch line {
		case "    get:":
			currentMethod = "GET"
		case "    patch:":
			currentMethod = "PATCH"
		case "    post:":
			currentMethod = "POST"
		case "      requestBody:":
			if currentMethod != "" {
				routes = append(routes, openAPIRequestBodyFixture{Method: currentMethod, Path: currentPath})
			}
		}
	}
	return routes, scanner.Err()
}

func requiredJSONRequestBodyRoutes() []routeFixture {
	return []routeFixture{
		{Method: "POST", Path: "/_redevplugin/api/plugins/install"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/enable"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/disable"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/uninstall"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/update"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/downgrade"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/open"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bootstrap"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/rpc"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/confirm"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/intents/invoke"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/operations/{operation_id}/cancel"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/start"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/data/export"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/data/import"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/delete"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/cleanup-expired"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/permissions/grant"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/permissions/revoke"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/bind"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/test"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/delete"},
		{Method: "PATCH", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings"},
		{Method: "POST", Path: "/_redevplugin/bootstrap"},
		{Method: "POST", Path: "/_redevplugin/csp-report"},
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	var _, file, _, _ = runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func sortRoutes(routes []routeFixture) {
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
}
