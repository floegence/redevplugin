package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestExternalPackageFeatureIsPublishedByTheOpenAPIContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "openapi", "plugin-platform-v8.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	block := openAPISchemaBlock(t, string(raw), "PluginFeaturesSuccessResponse")
	if !strings.Contains(block, "enum: [release, runtime, capability, connectivity, secrets, core_action, external_package]") {
		t.Fatalf("PluginFeaturesSuccessResponse does not publish external_package:\n%s", block)
	}
}

func TestExternalPackageRoutesExposeClosedInspectCommitAndQueryFlow(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "openapi", "plugin-platform-v8.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	tests := []struct {
		path          string
		operationID   string
		effect        string
		requestBody   string
		response      string
		errorResponse string
	}{
		{
			path:          "/_redevplugin/api/plugins/external-packages/inspect",
			operationID:   "inspectExternalPackage",
			effect:        "mutation",
			requestBody:   "InspectExternalPackageRequest",
			response:      "ExternalPackageInspectionResponse",
			errorResponse: "MutationPlatformErrorResponse",
		},
		{
			path:          "/_redevplugin/api/plugins/external-packages/commit",
			operationID:   "commitExternalPackage",
			effect:        "mutation",
			requestBody:   "CommitExternalPackageRequest",
			response:      "ExternalPackageCommitResponse",
			errorResponse: "MutationPlatformErrorResponse",
		},
		{
			path:          "/_redevplugin/api/plugins/external-packages/commit/query",
			operationID:   "queryExternalPackageCommit",
			effect:        "query",
			requestBody:   "QueryExternalPackageCommitRequest",
			response:      "ExternalPackageCommitResponse",
			errorResponse: "PlatformErrorResponse",
		},
	}
	for _, tt := range tests {
		block, ok := openAPIOperationContractBlock(source, tt.path, "POST")
		if !ok {
			t.Fatalf("OpenAPI POST operation is missing for %s", tt.path)
		}
		for _, snippet := range []string{
			"operationId: " + tt.operationID,
			"x-redevplugin-route-effect: " + tt.effect,
			`$ref: "#/components/requestBodies/` + tt.requestBody + `"`,
			`"200": { $ref: "#/components/responses/` + tt.response + `" }`,
			`default: { $ref: "#/components/responses/` + tt.errorResponse + `" }`,
		} {
			if !strings.Contains(block, snippet) {
				t.Fatalf("OpenAPI operation %s is missing %q:\n%s", tt.path, snippet, block)
			}
		}
	}
}

func TestExternalPackageRequestsExposeOnlyCallerControlledInputs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "openapi", "plugin-platform-v8.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	tests := []struct {
		schema     string
		properties []string
	}{
		{schema: "InspectExternalPackageRequest", properties: []string{"intent", "source"}},
		{schema: "CommitExternalPackageRequest", properties: []string{"confirmation_digest", "inspection_id"}},
		{schema: "QueryExternalPackageCommitRequest", properties: []string{"commit_id", "inspection_id"}},
	}
	for _, tt := range tests {
		block := openAPISchemaBlock(t, source, tt.schema)
		if !strings.Contains(block, "additionalProperties: false") {
			t.Fatalf("OpenAPI schema %s is not closed:\n%s", tt.schema, block)
		}
		properties := externalPackageTopLevelProperties(block)
		if !reflect.DeepEqual(properties, tt.properties) {
			t.Fatalf("OpenAPI schema %s properties = %#v, want %#v", tt.schema, properties, tt.properties)
		}
		for _, forbidden := range []string{
			"trust_state", "signature_assessment", "package_sha256", "publisher_id", "plugin_id", "version",
			"execution_approval", "approval", "source_provenance", "update_eligibility",
		} {
			if strings.Contains(block, "        "+forbidden+":") {
				t.Fatalf("OpenAPI schema %s must not accept server-derived field %q", tt.schema, forbidden)
			}
		}
	}

	intent := openAPISchemaBlock(t, source, "ExternalPackageIntent")
	for _, snippet := range []string{"action: { const: install }", "action: { const: update }", "plugin_instance_id:", "expected_management_revision:"} {
		if !strings.Contains(intent, snippet) {
			t.Fatalf("ExternalPackageIntent is missing %q:\n%s", snippet, intent)
		}
	}
	sourceSchema := openAPISchemaBlock(t, source, "ExternalPackageSource")
	for _, snippet := range []string{"kind: { const: package_url }", "kind: { const: github_repository }", "tag:", "maxLength: 255"} {
		if !strings.Contains(sourceSchema, snippet) {
			t.Fatalf("ExternalPackageSource is missing %q:\n%s", snippet, sourceSchema)
		}
	}
}

func TestExternalPackageResponsesKeepOrthogonalSecurityFacts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "openapi", "plugin-platform-v8.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	facts := []string{"signature_assessment", "source_provenance", "execution_approval", "update_eligibility"}
	for _, schemaName := range []string{"ExternalPackageInspection", "ExternalPackageCommitResult"} {
		block := openAPISchemaBlock(t, source, schemaName)
		for _, fact := range facts {
			if !strings.Contains(block, fact) {
				t.Fatalf("OpenAPI schema %s is missing orthogonal fact %q", schemaName, fact)
			}
		}
	}

	checks := map[string][]string{
		"ExternalPackageSignatureAssessment": {"verified", "absent", "unknown_signer", "invalid", "revoked", "unavailable", "assessed_hashes"},
		"ExternalPackageExecutionApproval":   {"pending", "user_approved", "policy_approved", "policy_blocked"},
		"ExternalPackageUpdateEligibility":   {"manual_only", "automatic_eligible"},
		"ExternalPackageSourceProvenance":    {"package_url", "github_repository", "repository_id", "release_id", "asset_id", "package_sha256", "resolved_commit_sha"},
	}
	for schemaName, snippets := range checks {
		block := openAPISchemaBlock(t, source, schemaName)
		if !strings.Contains(block, "additionalProperties: false") {
			t.Fatalf("OpenAPI schema %s must contain closed variants:\n%s", schemaName, block)
		}
		for _, snippet := range snippets {
			if !strings.Contains(block, snippet) {
				t.Fatalf("OpenAPI schema %s is missing %q", schemaName, snippet)
			}
		}
	}

	securitySummary := openAPISchemaBlock(t, source, "ExternalPackageSecuritySummary")
	for _, snippet := range []string{
		"additionalProperties: false", "summary_sha256", "permissions", "methods", "capability_contracts",
		"workers", "network", "storage", "secret_refs", "core_actions", "intents", "surfaces",
	} {
		if !strings.Contains(securitySummary, snippet) {
			t.Fatalf("ExternalPackageSecuritySummary is missing %q", snippet)
		}
	}
}

func TestExternalPackageProjectionPreservesLegacyTrustFields(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "openapi", "plugin-platform-v8.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	trustState := openAPISchemaBlock(t, source, "TrustState")
	if !strings.Contains(trustState, "enum: [verified, unsigned_local, untrusted, needs_review, trust_unavailable, blocked_security]") {
		t.Fatalf("TrustState compatibility enum changed unexpectedly:\n%s", trustState)
	}
	pluginRecord := openAPISchemaBlock(t, source, "PluginRecord")
	for _, snippet := range []string{"trust_state:", "trust_assessment:", "local_import_provenance:", "signature_assessment:", "source_provenance:", "execution_approval:", "update_eligibility:", "security_summary:"} {
		if !strings.Contains(pluginRecord, snippet) {
			t.Fatalf("PluginRecord is missing compatibility or external package projection %q", snippet)
		}
	}
}

func TestExternalPackageSecuritySummarySchemasMatchHostProjection(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "openapi", "plugin-platform-v8.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	tests := []struct {
		schema     string
		properties []string
	}{
		{schema: "ExternalPackagePermissionSummary", properties: []string{"methods", "permission_id"}},
		{schema: "ExternalPackageMethodRouteSummary", properties: []string{"action_id", "binding_id", "kind", "target_method", "worker_id"}},
		{schema: "ExternalPackageConfirmationSummary", properties: []string{"mode", "plan_hash_required", "preflight_method", "request_hash_fields"}},
		{schema: "ExternalPackageCancelSummary", properties: []string{"ack_timeout_ms", "cancelable", "disable_behavior", "uninstall_behavior"}},
		{schema: "ExternalPackageMethodSummary", properties: []string{"cancel", "confirmation", "dangerous", "effect", "execution", "method", "preflight_only", "required_permissions", "route"}},
		{schema: "ExternalPackageCapabilityContractSummary", properties: []string{"binding_id", "capability_id", "capability_version", "contract_sha256"}},
		{schema: "ExternalPackageWorkerSummary", properties: []string{"abi", "artifact", "idle_timeout_ms", "memory_limit_bytes", "mode", "scope", "worker_id"}},
		{schema: "ExternalPackageNetworkMethodAccessSummary", properties: []string{"http_methods", "method", "operations"}},
		{schema: "ExternalPackageNetworkSummary", properties: []string{"auth_declared", "connector_id", "destinations", "method_access", "scope", "tls_declared", "transport"}},
		{schema: "ExternalPackageStorageMethodAccessSummary", properties: []string{"method", "operations"}},
		{schema: "ExternalPackageStorageSummary", properties: []string{"kind", "method_access", "quota_bytes", "quota_files", "schema_version", "scope", "store_id"}},
		{schema: "ExternalPackageSecretRefSummary", properties: []string{"scope", "secret_ref", "setting_key"}},
		{schema: "ExternalPackageCoreActionSummary", properties: []string{"action_id", "effect", "method"}},
		{schema: "ExternalPackageIntentSummary", properties: []string{"intent_id", "method"}},
		{schema: "ExternalPackageSurfaceSummary", properties: []string{"default_size", "entry", "icon", "intent", "kind", "label", "surface_id"}},
		{schema: "ExternalPackageSizeSummary", properties: []string{"height", "width"}},
		{schema: "ExternalPackageSecuritySummary", properties: []string{"capability_contracts", "core_actions", "intents", "methods", "network", "permissions", "secret_refs", "storage", "summary_sha256", "surfaces", "workers"}},
	}
	for _, tt := range tests {
		block := openAPISchemaBlock(t, source, tt.schema)
		if !strings.Contains(block, "additionalProperties: false") {
			t.Fatalf("OpenAPI schema %s is not closed:\n%s", tt.schema, block)
		}
		if got := externalPackageTopLevelProperties(block); !reflect.DeepEqual(got, tt.properties) {
			t.Fatalf("OpenAPI schema %s properties = %#v, want %#v", tt.schema, got, tt.properties)
		}
	}
}

func TestExternalPackageRequestFixturesRemainMinimal(t *testing.T) {
	tests := []struct {
		name    string
		topKeys []string
		intent  []string
		source  []string
	}{
		{name: "external-package-inspect-install-request.json", topKeys: []string{"intent", "source"}, intent: []string{"action"}, source: []string{"kind", "url"}},
		{name: "external-package-inspect-update-request.json", topKeys: []string{"intent", "source"}, intent: []string{"action", "expected_management_revision", "plugin_instance_id"}, source: []string{"kind", "tag", "url"}},
		{name: "external-package-commit-request.json", topKeys: []string{"confirmation_digest", "inspection_id"}},
		{name: "external-package-query-request.json", topKeys: []string{"inspection_id"}},
	}
	for _, tt := range tests {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "contracts", tt.name))
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("decode %s: %v", tt.name, err)
		}
		if got := externalPackageMapKeys(value); !reflect.DeepEqual(got, tt.topKeys) {
			t.Fatalf("%s keys = %#v, want %#v", tt.name, got, tt.topKeys)
		}
		for key, want := range map[string][]string{"intent": tt.intent, "source": tt.source} {
			if want == nil {
				continue
			}
			nested, ok := value[key].(map[string]any)
			if !ok {
				t.Fatalf("%s %s must be an object", tt.name, key)
			}
			if got := externalPackageMapKeys(nested); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s %s keys = %#v, want %#v", tt.name, key, got, want)
			}
		}
	}
}

func externalPackageTopLevelProperties(schema string) []string {
	var properties []string
	for _, line := range strings.Split(schema, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "        ") && !strings.HasPrefix(line, "          ") && strings.Contains(trimmed, ":") {
			properties = append(properties, strings.SplitN(trimmed, ":", 2)[0])
		}
	}
	sort.Strings(properties)
	return properties
}

func externalPackageMapKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
