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

type typeScriptSDKRouteBinding struct {
	routeFixture
	Owner    string
	Snippets []string
}

type routeWithoutTypeScriptSDKBinding struct {
	routeFixture
	Reason string
}

type openAPIRequestBodyFixture struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func TestHTTPRouteSetMatchesFixture(t *testing.T) {
	root := repoRoot(t)
	fixtures, err := readRouteFixtures(filepath.Join(root, "testdata", "contracts", "routes.json"))
	if err != nil {
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

func TestHTTPRoutesClassifyTypeScriptSDKCoverage(t *testing.T) {
	root := repoRoot(t)
	fixtures, err := readRouteFixtures(filepath.Join(root, "testdata", "contracts", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	sdkRaw, err := os.ReadFile(filepath.Join(root, "packages", "redevplugin-ui", "src", "index.ts"))
	if err != nil {
		t.Fatal(err)
	}
	sdkSource := string(sdkRaw)

	fixtureRoutes := map[string]routeFixture{}
	for _, route := range fixtures {
		key := routeKey(route)
		if _, ok := fixtureRoutes[key]; ok {
			t.Fatalf("route fixture has duplicate route %s", key)
		}
		fixtureRoutes[key] = route
	}

	classifiedRoutes := map[string]string{}
	for _, binding := range typeScriptSDKRouteBindings() {
		key := routeKey(binding.routeFixture)
		if _, ok := fixtureRoutes[key]; !ok {
			t.Fatalf("TypeScript SDK binding %s references unknown HTTP route %s", binding.Owner, key)
		}
		if previous, ok := classifiedRoutes[key]; ok {
			t.Fatalf("HTTP route %s is classified twice: %s and TypeScript SDK binding %s", key, previous, binding.Owner)
		}
		classifiedRoutes[key] = "TypeScript SDK binding " + binding.Owner
		for _, snippet := range binding.Snippets {
			if !strings.Contains(sdkSource, snippet) {
				t.Fatalf("TypeScript SDK binding %s for %s is missing source snippet %q", binding.Owner, key, snippet)
			}
		}
	}
	for _, route := range routesWithoutTypeScriptSDKBindings() {
		key := routeKey(route.routeFixture)
		if _, ok := fixtureRoutes[key]; !ok {
			t.Fatalf("route without TypeScript SDK binding references unknown HTTP route %s: %s", key, route.Reason)
		}
		if previous, ok := classifiedRoutes[key]; ok {
			t.Fatalf("HTTP route %s is classified twice: %s and no-SDK route %q", key, previous, route.Reason)
		}
		classifiedRoutes[key] = "no TypeScript SDK binding: " + route.Reason
	}
	for _, route := range fixtures {
		key := routeKey(route)
		if _, ok := classifiedRoutes[key]; !ok {
			t.Fatalf("HTTP route %s must have a TypeScript SDK binding or an explicit no-SDK reason", key)
		}
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
		"error_details:",
		"enum: [payload_bytes, json_depth, prototype_key, number_precision]",
		"application/csp-report:",
		"per sandbox_origin plus active_fingerprint plus source IP rate limiting",
		"Content-Security-Policy:",
		"Permissions-Policy:",
		"Service-Worker-Allowed:",
	} {
		if !strings.Contains(text, snippet) {
			t.Fatalf("OpenAPI schema missing snippet %q", snippet)
		}
	}
}

func readRouteFixtures(path string) ([]routeFixture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fixtures []routeFixture
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		return nil, err
	}
	return fixtures, nil
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

func typeScriptSDKRouteBindings() []typeScriptSDKRouteBinding {
	return []typeScriptSDKRouteBinding{
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/install"},
			Owner:        "PluginPlatformClient.installPlugin",
			Snippets:     []string{"installPlugin(request: PluginInstallRequest)", `#postJSON("/_redevplugin/api/plugins/install"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/enable"},
			Owner:        "PluginPlatformClient.enablePlugin",
			Snippets:     []string{"enablePlugin(pluginInstanceIdOrRequest", `#postJSON("/_redevplugin/api/plugins/enable"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/disable"},
			Owner:        "PluginPlatformClient.disablePlugin",
			Snippets:     []string{"disablePlugin(request: PluginDisableRequest)", `#postJSON("/_redevplugin/api/plugins/disable"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/uninstall"},
			Owner:        "PluginPlatformClient.uninstallPlugin",
			Snippets:     []string{"uninstallPlugin(request: PluginUninstallRequest)", `#postJSON("/_redevplugin/api/plugins/uninstall"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/update"},
			Owner:        "PluginPlatformClient.updatePlugin",
			Snippets:     []string{"updatePlugin(request: PluginUpdateRequest)", `#postJSON("/_redevplugin/api/plugins/update"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/downgrade"},
			Owner:        "PluginPlatformClient.downgradePlugin",
			Snippets:     []string{"downgradePlugin(request: PluginDowngradeRequest)", `#postJSON("/_redevplugin/api/plugins/downgrade"`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/catalog"},
			Owner:        "PluginPlatformClient.catalog",
			Snippets:     []string{"catalog(): Promise<PluginCatalogResult>", `#getJSON("/_redevplugin/api/plugins/catalog"`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/platform/compatibility"},
			Owner:        "PluginPlatformClient.getCompatibility",
			Snippets:     []string{"getCompatibility(): Promise<PluginCompatibilityManifest>", `#getJSON("/_redevplugin/api/plugins/platform/compatibility"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/open"},
			Owner:        "PluginPlatformClient.openSurface",
			Snippets:     []string{"openSurface(request: PluginOpenSurfaceRequest)", `#postJSON("/_redevplugin/api/plugins/surfaces/open"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token"},
			Owner:        "PluginSurfaceHost.#handleHandshake",
			Snippets:     []string{"async #handleHandshake(handshake: PluginBridgeHandshake)", `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/bridge-token`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/rpc"},
			Owner:        "PluginSurfaceHost.#callRPC",
			Snippets:     []string{"#callRPC(request: PluginBridgeRequest", "/_redevplugin/api/plugins/rpc"},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/confirm"},
			Owner:        "PluginSurfaceHost.#prepareConfirmation",
			Snippets:     []string{"#prepareConfirmation(request: PluginBridgeRequest)", "/_redevplugin/api/plugins/confirm"},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/intents"},
			Owner:        "PluginPlatformClient.listIntents",
			Snippets:     []string{"listIntents(options: PluginIntentListOptions", `/_redevplugin/api/plugins/intents${query`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/intents/invoke"},
			Owner:        "PluginPlatformClient.invokeIntent",
			Snippets:     []string{"invokeIntent<T = unknown>", `#postJSON("/_redevplugin/api/plugins/intents/invoke"`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/operations"},
			Owner:        "PluginPlatformClient.listOperations",
			Snippets:     []string{"listOperations(pluginInstanceId?: string)", `/_redevplugin/api/plugins/operations${query`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/operations/{operation_id}"},
			Owner:        "PluginPlatformClient.getOperation",
			Snippets:     []string{"getOperation(operationId: string)", `/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/operations/{operation_id}/cancel"},
			Owner:        "PluginPlatformClient.cancelOperation",
			Snippets:     []string{"cancelOperation(operationId: string", `/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}/cancel`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/runtime/health"},
			Owner:        "PluginPlatformClient.runtimeHealth",
			Snippets:     []string{"runtimeHealth(): Promise<PluginRuntimeHealth>", `#getJSON("/_redevplugin/api/plugins/runtime/health"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/refresh-enabled"},
			Owner:        "PluginPlatformClient.refreshEnabledRuntimeState",
			Snippets:     []string{"refreshEnabledRuntimeState(): Promise<PluginRuntimeRefreshResult>", `#postJSON("/_redevplugin/api/plugins/runtime/refresh-enabled"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/start"},
			Owner:        "PluginPlatformClient.startRuntime",
			Snippets:     []string{"startRuntime(request: PluginRuntimeStartRequest", `#postJSON("/_redevplugin/api/plugins/runtime/start"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/stop"},
			Owner:        "PluginPlatformClient.stopRuntime",
			Snippets:     []string{"stopRuntime(): Promise<PluginRuntimeStopResult>", `#postJSON("/_redevplugin/api/plugins/runtime/stop"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/data/export"},
			Owner:        "PluginPlatformClient.exportData",
			Snippets:     []string{"exportData(request: PluginDataExportRequest)", `#postJSON("/_redevplugin/api/plugins/data/export"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/data/import"},
			Owner:        "PluginPlatformClient.importData",
			Snippets:     []string{"importData(request: PluginDataImportRequest)", `#postJSON("/_redevplugin/api/plugins/data/import"`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/retained-data"},
			Owner:        "PluginPlatformClient.listRetainedData",
			Snippets:     []string{"listRetainedData(options: PluginRetainedDataListOptions", `/_redevplugin/api/plugins/retained-data${query`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/delete"},
			Owner:        "PluginPlatformClient.deleteRetainedData",
			Snippets:     []string{"deleteRetainedData(retainedId: string)", `#postJSON("/_redevplugin/api/plugins/retained-data/delete"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/bind"},
			Owner:        "PluginPlatformClient.bindRetainedData",
			Snippets:     []string{"bindRetainedData(request: PluginRetainedDataBindRequest)", `#postJSON("/_redevplugin/api/plugins/retained-data/bind"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/cleanup-expired"},
			Owner:        "PluginPlatformClient.cleanupExpiredRetainedData",
			Snippets:     []string{"cleanupExpiredRetainedData(request: PluginRetainedDataCleanupRequest", `#postJSON("/_redevplugin/api/plugins/retained-data/cleanup-expired"`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/permissions"},
			Owner:        "PluginPlatformClient.listPermissions",
			Snippets:     []string{"listPermissions(pluginInstanceId?: string", `/_redevplugin/api/plugins/permissions${query`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/permissions/grant"},
			Owner:        "PluginPlatformClient.grantPermission",
			Snippets:     []string{"grantPermission(request: PluginPermissionGrantRequest)", `#postJSON("/_redevplugin/api/plugins/permissions/grant"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/permissions/revoke"},
			Owner:        "PluginPlatformClient.revokePermission",
			Snippets:     []string{"revokePermission(request: PluginPermissionRevokeRequest)", `#postJSON("/_redevplugin/api/plugins/permissions/revoke"`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/audit"},
			Owner:        "PluginPlatformClient.listAuditEvents",
			Snippets:     []string{"listAuditEvents(options: PluginAuditListOptions", `/_redevplugin/api/plugins/audit${queryString(options)}`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/diagnostics"},
			Owner:        "PluginPlatformClient.listDiagnosticEvents",
			Snippets:     []string{"listDiagnosticEvents(options: PluginDiagnosticListOptions", `/_redevplugin/api/plugins/diagnostics${queryString(options)}`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/bind"},
			Owner:        "PluginPlatformClient.bindSecret",
			Snippets:     []string{"bindSecret(request: PluginSecretRefRequest)", `#postJSON("/_redevplugin/api/plugins/secrets/bind"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/test"},
			Owner:        "PluginPlatformClient.testSecret",
			Snippets:     []string{"testSecret(request: PluginSecretRefRequest)", `#postJSON("/_redevplugin/api/plugins/secrets/test"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/delete"},
			Owner:        "PluginPlatformClient.deleteSecret",
			Snippets:     []string{"deleteSecret(request: PluginSecretRefRequest)", `#postJSON("/_redevplugin/api/plugins/secrets/delete"`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings/schema"},
			Owner:        "PluginPlatformClient.getSettingsSchema",
			Snippets:     []string{"getSettingsSchema(pluginInstanceId: string)", `/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings/schema`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings"},
			Owner:        "PluginPlatformClient.getSettings",
			Snippets:     []string{"getSettings(pluginInstanceId: string)", `/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`},
		},
		{
			routeFixture: routeFixture{Method: "PATCH", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings"},
			Owner:        "PluginPlatformClient.patchSettings",
			Snippets:     []string{"patchSettings(pluginInstanceId: string", `/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`},
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/stream/{stream_id}"},
			Owner:        "readPluginStream",
			Snippets:     []string{"export async function readPluginStream", `/_redevplugin/stream/${encodeURIComponent(streamId)}?ticket=${encodeURIComponent(streamTicket)}`, `method: "GET"`},
		},
	}
}

func routesWithoutTypeScriptSDKBindings() []routeWithoutTypeScriptSDKBinding {
	return []routeWithoutTypeScriptSDKBinding{
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bootstrap"},
			Reason:       "asset-session exchange sets an HttpOnly cookie and is driven by the browser bootstrap shell",
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/bootstrap"},
			Reason:       "sandbox bootstrap entry is a browser protocol endpoint, not a management SDK call",
		},
		{
			routeFixture: routeFixture{Method: "GET", Path: "/_redevplugin/assets/{asset_session_id}/{asset_path...}"},
			Reason:       "asset fetches are browser resource loads guarded by the HttpOnly asset-session cookie",
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/csp-report"},
			Reason:       "CSP reports are browser telemetry posts without a product-shell SDK wrapper",
		},
	}
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

func routeKey(route routeFixture) string {
	return route.Method + " " + route.Path
}

func sortRoutes(routes []routeFixture) {
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
}
