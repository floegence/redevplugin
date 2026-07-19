package protocol

import (
	"bufio"
	"encoding/json"
	"fmt"
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
	Effect string `json:"effect"`
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
		got = append(got, routeFixture{Method: route.Method, Path: route.Path, Effect: string(route.Effect)})
	}
	sortRoutes(fixtures)
	sortRoutes(got)
	if !reflect.DeepEqual(got, fixtures) {
		t.Fatalf("route set mismatch\n got: %#v\nwant: %#v", got, fixtures)
	}
}

func TestOpenAPIRouteSetMatchesFixture(t *testing.T) {
	root := repoRoot(t)
	fixtures, err := readRouteFixtures(filepath.Join(root, "testdata", "contracts", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := readOpenAPIRoutes(filepath.Join(root, "spec", "openapi", "plugin-platform-v7.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sortRoutes(fixtures)
	sortRoutes(got)
	if !reflect.DeepEqual(got, fixtures) {
		t.Fatalf("OpenAPI route set mismatch\n got: %#v\nwant: %#v", got, fixtures)
	}
}

func TestHTTPRoutesClassifyTypeScriptSDKCoverage(t *testing.T) {
	root := repoRoot(t)
	fixtures, err := readRouteFixtures(filepath.Join(root, "testdata", "contracts", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	sdkSource := strings.NewReplacer(
		", requestOptions: PluginRequestOptions = {}", "",
		", options: PluginRequestOptions = {}", "",
		"options: PluginRequestOptions = {}", "",
	).Replace(readTypeScriptSources(t, root, "platform.ts", "surface.ts", "local-import.ts"))

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

func TestLocalImportRoutesUseDedicatedTypeScriptEntrypoint(t *testing.T) {
	root := repoRoot(t)
	defaultSDKRaw, err := os.ReadFile(filepath.Join(root, "packages", "redevplugin-ui", "src", "index.ts"))
	if err != nil {
		t.Fatal(err)
	}
	defaultSDK := string(defaultSDKRaw)
	for _, forbidden := range []string{
		"importLocalPackage(",
		"updateLocalPackage(",
	} {
		if strings.Contains(defaultSDK, forbidden) {
			t.Fatalf("default TypeScript entrypoint must not expose local-import symbol %q", forbidden)
		}
	}
	localImportRaw, err := os.ReadFile(filepath.Join(root, "packages", "redevplugin-ui", "src", "local-import.ts"))
	if err != nil {
		t.Fatal(err)
	}
	localImportSDK := string(localImportRaw)
	for _, snippet := range []string{
		"export class PluginLocalImportClient",
		"export type PluginUploadProgress",
		"importLocalPackage(pluginInstanceId: string, packageBlob: Blob",
		"/_redevplugin/api/plugins/${encodeURIComponent(canonicalPluginInstanceId)}/local-import",
		"updateLocalPackage(pluginInstanceId: string",
		"/_redevplugin/api/plugins/${encodeURIComponent(canonicalPluginInstanceId)}/local-import",
	} {
		if !strings.Contains(localImportSDK, snippet) {
			t.Fatalf("local-import TypeScript entrypoint missing snippet %q", snippet)
		}
	}
}

func TestOpenAPIDefinesJSONRequestBodies(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "spec", "openapi", "plugin-platform-v7.yaml")
	requestBodies, err := readOpenAPIRequestBodyRoutes(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[routeFixture]bool{}
	for _, route := range requestBodies {
		got[routeFixture{Method: route.Method, Path: route.Path}] = true
	}
	for _, route := range requiredJSONRequestBodyRoutes() {
		if !got[route] {
			t.Fatalf("OpenAPI route %s %s missing requestBody", route.Method, route.Path)
		}
	}
	mediaTypes, err := readOpenAPIRequestBodyMediaTypes(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(mediaTypes) == 0 {
		t.Fatal("OpenAPI does not define request body components")
	}
	for name, values := range mediaTypes {
		if !reflect.DeepEqual(values, []string{"application/json"}) {
			t.Fatalf("OpenAPI request body %s media types = %#v, want application/json only", name, values)
		}
	}
}

func TestOpenAPIDefinesBoundedPackageUploadBodies(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "openapi", "plugin-platform-v7.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, snippet := range []string{
		"/_redevplugin/api/plugins/{plugin_instance_id}/local-import:",
		"name: X-ReDevPlugin-Expected-Management-Revision",
		"in: header",
		"application/vnd.redevplugin.package+zip:",
	} {
		if !strings.Contains(text, snippet) {
			t.Fatalf("OpenAPI package upload contract missing %q", snippet)
		}
	}
}

func TestOpenAPIRequestSchemasDefineCriticalFields(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v7.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, snippet := range []string{
		"TrustedParentBridgeTokenRequest:",
		"handshake_transcript_sha256:",
		"plugin_gateway_token: { type: string, minLength: 1 }",
		"delete_data: { type: boolean }",
		"asset_ticket: { type: string, minLength: 1 }",
		"ui_protocol_version: { const: plugin-ui-v5 }",
		"management_revision: { type: integer, minimum: 1, maximum: 9007199254740991 }",
		"revoke_epoch: { type: integer, minimum: 1, maximum: 9007199254740991 }",
		"DisposeSurfaceRequest:",
		"required: [bridge_nonce]",
		"SurfacePreparation:",
		"../plugin/opaque-surface-document-v3.schema.json",
		"ReadSurfaceAssetRequest:",
		"ReadSurfaceStreamRequest:",
		"DisposeSurfaceRequest:",
		"scope: { type: string, enum: [user, environment] }",
		"PluginDataBinding:",
		"RetainedDataCleanupResult:",
		"RiskPlan:",
		"schema_version: { const: redevplugin.capability.risk_plan.v1 }",
		"severity:",
		"enum: [info, low, medium, high, critical]",
		"requires_admin: { type: boolean }",
		"error_details:",
		"manifest_field",
		"path:",
		"pointer:",
		"InstallReleaseRefRequest:",
		"UpdateReleaseRefRequest:",
		"PluginReleaseRef:",
		"PackageHashSet:",
		"release_metadata_sha256:",
		"trust_unavailable",
		"expected_hashes:",
		"package_sha256: { type: string, pattern: \"^(sha256:)?[0-9a-f]{64}$\" }",
	} {
		if !strings.Contains(text, snippet) {
			t.Fatalf("OpenAPI schema missing snippet %q", snippet)
		}
	}
	if strings.Contains(text, "enum: [bundled,") {
		t.Fatalf("OpenAPI TrustState must not expose bundled as a public target trust state")
	}
}

func TestOpenAPIRoutesSeparateClosedSuccessAndErrorResponses(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v7.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, route := range httpadapter.RouteSet() {
		block, ok := openAPIOperationContractBlock(text, route.Path, route.Method)
		if !ok {
			t.Fatalf("OpenAPI operation is missing for %s %s", route.Method, route.Path)
		}
		readErrors := strings.Count(block, `default: { $ref: "#/components/responses/PlatformErrorResponse" }`)
		mutationErrors := strings.Count(block, `default: { $ref: "#/components/responses/MutationPlatformErrorResponse" }`)
		if readErrors+mutationErrors != 1 {
			t.Fatalf("OpenAPI operation %s %s has read errors=%d mutation errors=%d, want exactly one closed error response", route.Method, route.Path, readErrors, mutationErrors)
		}
	}
	if strings.Contains(text, "#/components/responses/PlatformResponse") || strings.Contains(text, "    PlatformResponse:") {
		t.Fatal("OpenAPI must not expose a success/error response union as a 200 response")
	}
	for _, schemaName := range []string{
		"PluginCatalogResult",
		"PluginOperationList",
		"PluginIntentList",
		"PluginPermissionList",
		"PluginDiagnosticEventList",
		"PluginRuntimeHealth",
		"PluginSettingsSchema",
		"PluginSettingsSnapshot",
	} {
		block := openAPISchemaBlock(t, text, schemaName)
		if !strings.Contains(block, "additionalProperties: false") || !strings.Contains(block, "required:") {
			t.Fatalf("OpenAPI schema %s must be closed with explicit required fields: %s", schemaName, block)
		}
	}
	pluginRecord := openAPISchemaBlock(t, text, "PluginRecord")
	for _, snippet := range []string{
		"additionalProperties: false",
		"capability_contracts:",
		`$ref: "../plugin/manifest-v5.schema.json"`,
		`items: { $ref: "#/components/schemas/PackageEntry" }`,
	} {
		if !strings.Contains(pluginRecord, snippet) {
			t.Fatalf("PluginRecord missing closed contract snippet %q: %s", snippet, pluginRecord)
		}
	}
	for _, reason := range []string{"ambiguous_entry", "non_regular_entry", "invalid_utf8_path", "non_nfc_path"} {
		if !strings.Contains(text, reason) {
			t.Fatalf("OpenAPI ErrorDetails missing package reason %q", reason)
		}
	}
}

func TestOpenAPIListQueryContractsAreStrictAndComplete(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v7.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, snippet := range []string{
		"x-redevplugin-query-policy:",
		"reject_url_query_strings: true",
		"require_closed_json_bodies: true",
		"require_exact_origin: true",
		"require_csrf: true",
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("OpenAPI global query policy is missing %q", snippet)
		}
	}
	tests := []struct {
		path       string
		schema     string
		properties []string
		snippets   []string
	}{
		{path: "/_redevplugin/api/plugins/operations/query", schema: "ListOperationsQueryRequest", properties: []string{"cursor", "limit", "plugin_instance_id"}, snippets: []string{"minimum: 1, maximum: 500"}},
		{path: "/_redevplugin/api/plugins/intents/query", schema: "ListIntentsQueryRequest", properties: []string{"intent_id", "plugin_instance_id"}},
		{path: "/_redevplugin/api/plugins/permissions/query", schema: "ListPermissionsQueryRequest", properties: []string{"active_only", "plugin_instance_id"}, snippets: []string{"active_only: { type: boolean }"}},
		{path: "/_redevplugin/api/plugins/diagnostics/query", schema: "ListDiagnosticsQueryRequest", properties: []string{"limit", "plugin_id", "plugin_instance_id", "severity", "surface_instance_id", "type"}, snippets: []string{"enum: [info, warning]", "minimum: 1, maximum: 1000"}},
	}
	for _, tt := range tests {
		block, ok := openAPIOperationContractBlock(source, tt.path, "POST")
		if !ok {
			t.Fatalf("OpenAPI POST query operation is missing for %s", tt.path)
		}
		if strings.Contains(block, "in: query") || !strings.Contains(block, "#/components/requestBodies/"+tt.schema) {
			t.Fatalf("OpenAPI POST query %s does not use its closed body: %s", tt.path, block)
		}
		schema := openAPISchemaBlock(t, source, tt.schema)
		if !strings.Contains(schema, "additionalProperties: false") {
			t.Fatalf("OpenAPI schema %s is not closed: %s", tt.schema, schema)
		}
		var properties []string
		for _, line := range strings.Split(schema, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(line, "        ") && !strings.HasPrefix(line, "          ") && strings.Contains(trimmed, ":") {
				properties = append(properties, strings.SplitN(trimmed, ":", 2)[0])
			}
		}
		sort.Strings(properties)
		if !reflect.DeepEqual(properties, tt.properties) {
			t.Fatalf("OpenAPI schema %s properties = %#v, want %#v", tt.schema, properties, tt.properties)
		}
		for _, snippet := range tt.snippets {
			if !strings.Contains(schema, snippet) {
				t.Fatalf("OpenAPI schema %s is missing query contract %q", tt.schema, snippet)
			}
		}
	}
}

func TestOpenAPIRuntimeAndSecretMutationContractsAreClosed(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v7.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	emptyRequest := openAPISchemaBlock(t, source, "EmptyRequest")
	for _, snippet := range []string{"type: object", "additionalProperties: false", "maxProperties: 0"} {
		if !strings.Contains(emptyRequest, snippet) {
			t.Fatalf("OpenAPI EmptyRequest is missing %q: %s", snippet, emptyRequest)
		}
	}
	for _, path := range []string{
		"/_redevplugin/api/plugins/runtime/stop",
		"/_redevplugin/api/plugins/runtime/refresh-enabled",
	} {
		block, ok := openAPIOperationContractBlock(source, path, "POST")
		if !ok {
			t.Fatalf("OpenAPI POST operation is missing for %s", path)
		}
		for _, snippet := range []string{
			`$ref: "#/components/requestBodies/EmptyRequest"`,
			`default: { $ref: "#/components/responses/MutationPlatformErrorResponse" }`,
		} {
			if !strings.Contains(block, snippet) {
				t.Fatalf("OpenAPI POST %s is missing %q: %s", path, snippet, block)
			}
		}
	}
	secretTest, ok := openAPIOperationContractBlock(source, "/_redevplugin/api/plugins/secrets/test", "POST")
	if !ok || !strings.Contains(secretTest, `default: { $ref: "#/components/responses/MutationPlatformErrorResponse" }`) {
		t.Fatalf("OpenAPI secrets/test must use the mutation error family: %s", secretTest)
	}
	runtimeRefresh := openAPISchemaBlock(t, source, "PluginRuntimeRefreshResult")
	for _, snippet := range []string{"required: [results]", "additionalProperties: false", "results:"} {
		if !strings.Contains(runtimeRefresh, snippet) {
			t.Fatalf("PluginRuntimeRefreshResult is missing %q: %s", snippet, runtimeRefresh)
		}
	}
}

func TestOpenAPITrustedScopeAndRetainedDataMatchClosedGoDTOs(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v7.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	invokeIntent := openAPISchemaBlock(t, text, "InvokeIntentRequest")
	for _, forbidden := range []string{"owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"} {
		if strings.Contains(invokeIntent, forbidden) {
			t.Fatalf("InvokeIntentRequest must derive trusted scope server-side; found %q", forbidden)
		}
	}
	retainedData := openAPISchemaBlock(t, text, "PluginDataBinding")
	for _, required := range []string{"plugin_instance_id", "generation_id", "revision", "shape_hash", "enum: [active, retained]"} {
		if !strings.Contains(retainedData, required) {
			t.Fatalf("PluginDataBinding is missing %q", required)
		}
	}
	surfaceBootstrap := openAPISchemaBlock(t, text, "SurfaceBootstrap")
	if !strings.Contains(surfaceBootstrap, "- runtime_generation_id") {
		t.Fatal("SurfaceBootstrap must require runtime_generation_id")
	}
	assetRead := openAPISchemaBlock(t, text, "ReadSurfaceAssetRequest")
	if !strings.Contains(assetRead, "required: [asset_session, asset_session_id, binding_id]") || strings.Contains(assetRead, "asset_path") || strings.Contains(assetRead, "expected_sha256") {
		t.Fatalf("ReadSurfaceAssetRequest must expose only the prepared binding id: %s", assetRead)
	}
}

func openAPISchemaBlock(t *testing.T, source string, schemaName string) string {
	t.Helper()
	marker := "    " + schemaName + ":\n"
	start := strings.LastIndex(source, marker)
	if start < 0 {
		t.Fatalf("OpenAPI schema %s is missing", schemaName)
	}
	start += len(marker)
	rest := source[start:]
	lines := strings.Split(rest, "\n")
	end := len(lines)
	for i := 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "    ") && len(lines[i]) > 4 && lines[i][4] != ' ' {
			end = i
			break
		}
	}
	return strings.Join(lines[:end], "\n")
}

func TestReleaseRefMetadataSchemasDefineClosedContracts(t *testing.T) {
	root := repoRoot(t)
	schemas := []struct {
		path     string
		snippets []string
	}{
		{
			path: "release-metadata-v5.schema.json",
			snippets: []string{
				`"additionalProperties": false`,
				`"schema_version": { "const": "redevplugin.release_metadata.v5" }`,
				`"release_metadata_signature": { "$ref": "#/$defs/release_metadata_signature" }`,
				`"package_signature": { "$ref": "#/$defs/package_release_signature" }`,
				`"$ref": "host-capability-pin-v1.schema.json"`,
				`"source_policy_epoch": { "$ref": "#/$defs/decimal_epoch" }`,
				`"revocation_epoch": { "$ref": "#/$defs/decimal_epoch" }`,
			},
		},
		{
			path: "source-policy-v1.schema.json",
			snippets: []string{
				`"additionalProperties": false`,
				`"schema_version": { "const": "redevplugin.source_policy.v1" }`,
				`"unsigned_policy": { "enum": ["dev_only", "review_required", "block"] }`,
				`"revocation_evidence": { "$ref": "#/$defs/revocation_evidence" }`,
				`"revocation_epoch": { "$ref": "#/$defs/decimal_epoch" }`,
			},
		},
		{
			path: "source-revocations-v1.schema.json",
			snippets: []string{
				`"additionalProperties": false`,
				`"schema_version": { "const": "redevplugin.source_revocations.v1" }`,
				`"highest_seen_epoch": { "$ref": "#/$defs/decimal_epoch" }`,
				`"revoked_key_ids":`,
			},
		},
	}
	for _, schema := range schemas {
		raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", schema.path))
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, snippet := range schema.snippets {
			if !strings.Contains(text, snippet) {
				t.Fatalf("%s missing snippet %q", schema.path, snippet)
			}
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

func readTypeScriptSources(t *testing.T, root string, names ...string) string {
	t.Helper()
	var source strings.Builder
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(root, "packages", "redevplugin-ui", "src", name))
		if err != nil {
			t.Fatal(err)
		}
		source.Write(raw)
		source.WriteByte('\n')
	}
	return source.String()
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
		case "    put:":
			currentMethod = "PUT"
		case "    patch:":
			currentMethod = "PATCH"
		case "    post:":
			currentMethod = "POST"
		case "    delete:":
			currentMethod = "DELETE"
		case "      requestBody:":
			if currentMethod != "" {
				routes = append(routes, openAPIRequestBodyFixture{Method: currentMethod, Path: currentPath})
			}
		}
	}
	return routes, scanner.Err()
}

func readOpenAPIRequestBodyMediaTypes(path string) (map[string][]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	mediaTypes := map[string][]string{}
	inRequestBodies := false
	current := ""
	inContent := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "  requestBodies:" {
			inRequestBodies = true
			continue
		}
		if !inRequestBodies {
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			break
		}
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") && strings.HasSuffix(line, ":") {
			current = strings.TrimSuffix(strings.TrimSpace(line), ":")
			mediaTypes[current] = nil
			inContent = false
			continue
		}
		if current != "" && line == "      content:" {
			inContent = true
			continue
		}
		if inContent && strings.HasPrefix(line, "        ") && !strings.HasPrefix(line, "          ") && strings.HasSuffix(line, ":") {
			mediaTypes[current] = append(mediaTypes[current], strings.TrimSuffix(strings.TrimSpace(line), ":"))
			inContent = false
		}
	}
	return mediaTypes, scanner.Err()
}

func readOpenAPIRoutes(path string) ([]routeFixture, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var routes []routeFixture
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
			continue
		}
		if currentPath == "" {
			continue
		}
		switch line {
		case "    get:":
			currentMethod = "GET"
		case "    put:":
			currentMethod = "PUT"
		case "    patch:":
			currentMethod = "PATCH"
		case "    post:":
			currentMethod = "POST"
		case "    delete:":
			currentMethod = "DELETE"
		}
		const effectPrefix = "      x-redevplugin-route-effect: "
		if strings.HasPrefix(line, effectPrefix) {
			if currentMethod == "" {
				return nil, fmt.Errorf("OpenAPI route effect without method for %s", currentPath)
			}
			effect := strings.TrimPrefix(line, effectPrefix)
			if effect != "query" && effect != "mutation" {
				return nil, fmt.Errorf("OpenAPI route %s %s has invalid effect %q", currentMethod, currentPath, effect)
			}
			routes = append(routes, routeFixture{Method: currentMethod, Path: currentPath, Effect: effect})
			currentMethod = ""
		}
	}
	return routes, scanner.Err()
}

func typeScriptSDKRouteBindings() []typeScriptSDKRouteBinding {
	return []typeScriptSDKRouteBinding{
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/local-import"},
			Owner:        "PluginLocalImportClient.importLocalPackage",
			Snippets:     []string{"importLocalPackage(pluginInstanceId: string, packageBlob: Blob", "/_redevplugin/api/plugins/${encodeURIComponent(canonicalPluginInstanceId)}/local-import"},
		},
		{
			routeFixture: routeFixture{Method: "PUT", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/local-import"},
			Owner:        "PluginLocalImportClient.updateLocalPackage",
			Snippets:     []string{"updateLocalPackage(pluginInstanceId: string", "/_redevplugin/api/plugins/${encodeURIComponent(canonicalPluginInstanceId)}/local-import"},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/install-release-ref"},
			Owner:        "PluginPlatformClient.installReleaseRef",
			Snippets:     []string{"installReleaseRef(request: PluginInstallReleaseRefRequest)", `#requestMutation("POST", "/_redevplugin/api/plugins/install-release-ref"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/enable"},
			Owner:        "PluginPlatformClient.enablePlugin",
			Snippets:     []string{"enablePlugin(request: PluginEnableRequest)", `#requestMutation("POST", "/_redevplugin/api/plugins/enable"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/disable"},
			Owner:        "PluginPlatformClient.disablePlugin",
			Snippets:     []string{"disablePlugin(request: PluginDisableRequest)", `#mutatePlugin("/_redevplugin/api/plugins/disable"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/uninstall"},
			Owner:        "PluginPlatformClient.uninstallPlugin",
			Snippets:     []string{"uninstallPlugin(request: PluginUninstallRequest)", `#mutatePlugin("/_redevplugin/api/plugins/uninstall"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/update-release-ref"},
			Owner:        "PluginPlatformClient.updateReleaseRef",
			Snippets:     []string{"updateReleaseRef(request: PluginUpdateReleaseRefRequest)", `#mutatePlugin("/_redevplugin/api/plugins/update-release-ref"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/downgrade"},
			Owner:        "PluginPlatformClient.downgradePlugin",
			Snippets:     []string{"downgradePlugin(request: PluginDowngradeRequest)", `#mutatePlugin("/_redevplugin/api/plugins/downgrade"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/catalog/query"},
			Owner:        "PluginPlatformClient.catalog",
			Snippets:     []string{"catalog(): Promise<PluginCatalogResult>", `#requestQuery("/_redevplugin/api/plugins/catalog/query"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/features/query"},
			Owner:        "PluginPlatformClient.features",
			Snippets:     []string{"features(): Promise<PluginFeatures>", `#requestQuery("/_redevplugin/api/plugins/features/query"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/platform/compatibility/query"},
			Owner:        "PluginPlatformClient.getCompatibility",
			Snippets:     []string{"getCompatibility(): Promise<PluginCompatibilityManifest>", `#requestQuery("/_redevplugin/api/plugins/platform/compatibility/query"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/open"},
			Owner:        "PluginPlatformClient.openSurfaceInSlot",
			Snippets:     []string{"openSurfaceInSlot(", "#openSurface(request: PluginOpenSurfaceRequest)", `#requestMutation("POST", "/_redevplugin/api/plugins/surfaces/open"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/revoke-scope"},
			Owner:        "PluginPlatformClient.revokeSurfaceScope",
			Snippets:     []string{"revokeSurfaceScope(): Promise<PluginSurfaceScopeRevokeResult>", `#requestMutation<PluginSurfaceScopeRevokeResult>("POST", "/_redevplugin/api/plugins/surfaces/revoke-scope"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/prepare"},
			Owner:        "PluginSurfaceHost.#prepareSurface",
			Snippets:     []string{"#prepareSurface(): Promise<PluginSurfacePreparationResult>", `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/prepare`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token"},
			Owner:        "PluginSurfaceHost.#mintBridgeToken",
			Snippets:     []string{"#mintBridgeToken(previousGatewayToken?: string, direct = false): Promise<PluginGatewayTokenResult>", `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/bridge-token`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/assets/read"},
			Owner:        "PluginSurfaceHost.#handleAssetRead",
			Snippets:     []string{"async #handleAssetRead(message: SurfaceAssetReadMessage)", `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/assets/read`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/streams/read"},
			Owner:        "PluginSurfaceHost.#handleStreamRead",
			Snippets:     []string{"async #handleStreamRead(id: string, streamHandle: string)", `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/streams/read`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/streams/ack"},
			Owner:        "PluginSurfaceHost.#handleStreamAcknowledge",
			Snippets:     []string{"async #handleStreamAcknowledge(id: string, streamHandle: string, deliveryID: string)", `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/streams/ack`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/operations/cancel"},
			Owner:        "PluginSurfaceHost.#handleOperationCancel",
			Snippets:     []string{"async #handleOperationCancel(message: { id: string; operation_id: string; reason?: string })", `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/operations/cancel`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/confirmations/reject"},
			Owner:        "PluginSurfaceHost.#rejectConfirmation",
			Snippets:     []string{"async #rejectConfirmation(confirmationID: string, signal: AbortSignal)", `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/confirmations/reject`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/dispose"},
			Owner:        "PluginSurfaceHost and PluginSurfaceSlot lifecycle",
			Snippets:     []string{"close(): Promise<PluginSurfaceCloseResult>", "async #closeSurface(): Promise<PluginSurfaceCloseResult>", "async function revokeSurfaceBootstrap(", `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(bootstrap.surfaceInstanceId)}/dispose`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/rpc"},
			Owner:        "PluginSurfaceHost.#callRPC",
			Snippets:     []string{"#callRPC(request: PluginBridgeRequest", "/_redevplugin/api/plugins/rpc"},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/confirmations/prepare"},
			Owner:        "PluginSurfaceHost.#preparePluginMethodConfirmation",
			Snippets:     []string{"#preparePluginMethodConfirmation(request: PluginBridgeRequest, signal: AbortSignal)", "/_redevplugin/api/plugins/confirmations/prepare"},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/intents/query"},
			Owner:        "PluginPlatformClient.listIntents",
			Snippets:     []string{"listIntents(options: PluginIntentListOptions", `#requestQuery("/_redevplugin/api/plugins/intents/query"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/intents/invoke"},
			Owner:        "PluginPlatformClient.invokeIntent",
			Snippets:     []string{"invokeIntent<T = unknown>", `#requestMutation("POST", "/_redevplugin/api/plugins/intents/invoke"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/operations/query"},
			Owner:        "PluginPlatformClient.listOperations",
			Snippets:     []string{"listOperations(options: PluginOperationListOptions = {})", `#requestQuery("/_redevplugin/api/plugins/operations/query"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/operations/{operation_id}/query"},
			Owner:        "PluginPlatformClient.getOperation",
			Snippets:     []string{"getOperation(operationId: string)", `/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}/query`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/operations/{operation_id}/cancel"},
			Owner:        "PluginPlatformClient.cancelOperation",
			Snippets:     []string{"cancelOperation(operationId: string", `/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}/cancel`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/health/query"},
			Owner:        "PluginPlatformClient.runtimeHealth",
			Snippets:     []string{"runtimeHealth(): Promise<PluginRuntimeHealth>", `#requestQuery("/_redevplugin/api/plugins/runtime/health/query"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/refresh-enabled"},
			Owner:        "PluginPlatformClient.refreshEnabledRuntimeState",
			Snippets:     []string{"refreshEnabledRuntimeState(): Promise<PluginRuntimeRefreshResult>", `#requestMutation("POST", "/_redevplugin/api/plugins/runtime/refresh-enabled"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/start"},
			Owner:        "PluginPlatformClient.startRuntime",
			Snippets:     []string{"startRuntime(request: PluginRuntimeStartRequest", `#requestMutation("POST", "/_redevplugin/api/plugins/runtime/start"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/stop"},
			Owner:        "PluginPlatformClient.stopRuntime",
			Snippets:     []string{"stopRuntime(): Promise<PluginRuntimeStopResult>", `#requestMutation<PluginRuntimeStopResult>("POST", "/_redevplugin/api/plugins/runtime/stop"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/data/export"},
			Owner:        "PluginPlatformClient.exportData",
			Snippets:     []string{"exportData(request: PluginDataExportRequest)", `#requestMutation("POST", "/_redevplugin/api/plugins/data/export"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/data/export/delete"},
			Owner:        "PluginPlatformClient.deleteDataExport",
			Snippets:     []string{"deleteDataExport(request: PluginDataExportDeleteRequest)", `#requestMutation("POST", "/_redevplugin/api/plugins/data/export/delete"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/data/import"},
			Owner:        "PluginPlatformClient.importData",
			Snippets:     []string{"importData(request: PluginDataImportRequest)", `#mutatePluginAt("POST", "/_redevplugin/api/plugins/data/import"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/query"},
			Owner:        "PluginPlatformClient.listRetainedData",
			Snippets:     []string{"listRetainedData(options: PluginRetainedDataListOptions", `#requestQuery("/_redevplugin/api/plugins/retained-data/query"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/delete"},
			Owner:        "PluginPlatformClient.deleteRetainedData",
			Snippets:     []string{"deleteRetainedData(request: PluginRetainedDataDeleteRequest)", `#requestMutation("POST", "/_redevplugin/api/plugins/retained-data/delete"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/bind"},
			Owner:        "PluginPlatformClient.bindRetainedData",
			Snippets:     []string{"bindRetainedData(request: PluginRetainedDataBindRequest)", `#mutatePluginAt("POST", "/_redevplugin/api/plugins/retained-data/bind"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/cleanup-expired"},
			Owner:        "PluginPlatformClient.cleanupExpiredRetainedData",
			Snippets:     []string{"cleanupExpiredRetainedData(request: PluginRetainedDataCleanupRequest", `#requestMutation("POST", "/_redevplugin/api/plugins/retained-data/cleanup-expired"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/permissions/query"},
			Owner:        "PluginPlatformClient.listPermissions",
			Snippets:     []string{"listPermissions(options: PluginPermissionListOptions = {})", `#requestQuery("/_redevplugin/api/plugins/permissions/query"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/permissions/grant"},
			Owner:        "PluginPlatformClient.grantPermission",
			Snippets:     []string{"grantPermission(request: PluginPermissionGrantRequest)", `#mutatePlugin("/_redevplugin/api/plugins/permissions/grant"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/permissions/revoke"},
			Owner:        "PluginPlatformClient.revokePermission",
			Snippets:     []string{"revokePermission(request: PluginPermissionRevokeRequest)", `#mutatePlugin("/_redevplugin/api/plugins/permissions/revoke"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/security-policies/query"},
			Owner:        "PluginPlatformClient.listSecurityPolicies",
			Snippets:     []string{"listSecurityPolicies(): Promise<PluginSecurityPolicyList>", `#requestQuery("/_redevplugin/api/plugins/security-policies/query"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/security-policies/{plugin_instance_id}/query"},
			Owner:        "PluginPlatformClient.getSecurityPolicy",
			Snippets:     []string{"getSecurityPolicy(pluginInstanceId: string)", `/_redevplugin/api/plugins/security-policies/${encodeURIComponent(pluginInstanceId)}/query`},
		},
		{
			routeFixture: routeFixture{Method: "PUT", Path: "/_redevplugin/api/plugins/security-policies/{plugin_instance_id}"},
			Owner:        "PluginPlatformClient.putSecurityPolicy",
			Snippets:     []string{"putSecurityPolicy(pluginInstanceId: string", `#mutatePluginAt("PUT", `},
		},
		{
			routeFixture: routeFixture{Method: "DELETE", Path: "/_redevplugin/api/plugins/security-policies/{plugin_instance_id}"},
			Owner:        "PluginPlatformClient.deleteSecurityPolicy",
			Snippets:     []string{"deleteSecurityPolicy(pluginInstanceId: string", `#mutatePluginAt("DELETE", `},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/diagnostics/query"},
			Owner:        "PluginPlatformClient.listDiagnosticEvents",
			Snippets:     []string{"listDiagnosticEvents(options: PluginDiagnosticListOptions", `#requestQuery("/_redevplugin/api/plugins/diagnostics/query"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/bind"},
			Owner:        "PluginPlatformClient.bindSecret",
			Snippets:     []string{"bindSecret(request: PluginSecretRefRequest)", `#requestMutation("POST", "/_redevplugin/api/plugins/secrets/bind"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/test"},
			Owner:        "PluginPlatformClient.testSecret",
			Snippets:     []string{"testSecret(request: PluginSecretRefRequest)", `#requestMutation("POST", "/_redevplugin/api/plugins/secrets/test"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/delete"},
			Owner:        "PluginPlatformClient.deleteSecret",
			Snippets:     []string{"deleteSecret(request: PluginSecretRefRequest)", `#requestMutation("POST", "/_redevplugin/api/plugins/secrets/delete"`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings/schema/query"},
			Owner:        "PluginPlatformClient.getSettingsSchema",
			Snippets:     []string{"getSettingsSchema(pluginInstanceId: string, scope: PluginResourceScopeKind", `/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings/schema/query`},
		},
		{
			routeFixture: routeFixture{Method: "POST", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings/query"},
			Owner:        "PluginPlatformClient.getSettings",
			Snippets:     []string{"getSettings(pluginInstanceId: string, scope: PluginResourceScopeKind", `/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings/query`},
		},
		{
			routeFixture: routeFixture{Method: "PATCH", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings"},
			Owner:        "PluginPlatformClient.patchSettings",
			Snippets:     []string{"patchSettings(pluginInstanceId: string", `/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`},
		},
	}
}

func routesWithoutTypeScriptSDKBindings() []routeWithoutTypeScriptSDKBinding {
	return nil
}

func requiredJSONRequestBodyRoutes() []routeFixture {
	return []routeFixture{
		{Method: "POST", Path: "/_redevplugin/api/plugins/install-release-ref"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/enable"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/disable"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/uninstall"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/update-release-ref"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/downgrade"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/catalog/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/features/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/platform/compatibility/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/open"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/prepare"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/assets/read"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/streams/read"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/streams/ack"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/operations/cancel"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/confirmations/reject"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/dispose"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/rpc"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/confirmations/prepare"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/intents/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/intents/invoke"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/operations/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/operations/{operation_id}/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/operations/{operation_id}/cancel"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/start"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/stop"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/refresh-enabled"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/runtime/health/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/data/export"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/data/export/delete"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/data/import"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/delete"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/bind"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/retained-data/cleanup-expired"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/permissions/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/permissions/grant"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/permissions/revoke"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/security-policies/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/security-policies/{plugin_instance_id}/query"},
		{Method: "PUT", Path: "/_redevplugin/api/plugins/security-policies/{plugin_instance_id}"},
		{Method: "DELETE", Path: "/_redevplugin/api/plugins/security-policies/{plugin_instance_id}"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/diagnostics/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/bind"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/test"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/secrets/delete"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings/schema/query"},
		{Method: "POST", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings/query"},
		{Method: "PATCH", Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings"},
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

func openAPIOperationContractBlock(source, path, method string) (string, bool) {
	lines := strings.Split(source, "\n")
	pathMarker := "  " + path + ":"
	methodMarker := "    " + strings.ToLower(method) + ":"
	pathStart := -1
	for i, line := range lines {
		if line == pathMarker {
			pathStart = i
			break
		}
	}
	if pathStart < 0 {
		return "", false
	}
	pathEnd := len(lines)
	for i := pathStart + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "  /") || lines[i] == "components:" {
			pathEnd = i
			break
		}
	}
	methodStart := -1
	for i := pathStart + 1; i < pathEnd; i++ {
		if lines[i] == methodMarker {
			methodStart = i
			break
		}
	}
	if methodStart < 0 {
		return "", false
	}
	methodEnd := pathEnd
	for i := methodStart + 1; i < pathEnd; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed != "" && len(lines[i])-len(strings.TrimLeft(lines[i], " ")) <= 4 {
			methodEnd = i
			break
		}
	}
	return strings.Join(lines[methodStart:methodEnd], "\n"), true
}
