package host

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/registry"
)

func TestExternalPackageSourceProvenanceJSONMatchesOpenAPIUnion(t *testing.T) {
	resolvedAt := time.Date(2026, time.July, 24, 8, 30, 0, 0, time.UTC)
	hash := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name          string
		provenance    ExternalPackageSourceProvenance
		wantKeys      []string
		wantRedirects int
	}{
		{
			name: "package URL without redirects",
			provenance: ExternalPackageSourceProvenance{
				Kind: string(registry.PackageSourcePackageURL), SourceOrigin: "https://plugins.example.test:443",
				SourcePath: "/plugin.redevplugin", PackageSHA256: hash, ResolvedAt: resolvedAt,
			},
			wantKeys: []string{"kind", "package_sha256", "redirect_chain", "resolved_at", "source_origin", "source_path"},
		},
		{
			name: "package URL with redirects",
			provenance: ExternalPackageSourceProvenance{
				Kind: string(registry.PackageSourcePackageURL), SourceOrigin: "https://plugins.example.test:443",
				SourcePath: "/plugin.redevplugin", RedirectChain: []ExternalPackageRedirectHop{{Origin: "https://cdn.example.test:443", Path: "/plugin.redevplugin"}},
				PackageSHA256: hash, ResolvedAt: resolvedAt,
			},
			wantKeys: []string{"kind", "package_sha256", "redirect_chain", "resolved_at", "source_origin", "source_path"}, wantRedirects: 1,
		},
		{
			name: "uploaded package",
			provenance: ExternalPackageSourceProvenance{
				Kind: string(registry.PackageSourcePackageUpload), UploadID: "upload_test", PackageSHA256: hash, ResolvedAt: resolvedAt,
			},
			wantKeys: []string{"kind", "package_sha256", "resolved_at", "upload_id"}, wantRedirects: -1,
		},
		{
			name: "GitHub repository",
			provenance: ExternalPackageSourceProvenance{
				Kind: string(registry.PackageSourceGitHubRepository), RepositoryID: "1", ReleaseID: "2", AssetID: "3",
				RepositoryURL: "https://github.com/example/plugin", Owner: "example", Repository: "plugin",
				ResolvedCommitSHA: strings.Repeat("b", 40), ReleaseTag: "v1.0.0", AssetName: "plugin.redevplugin",
				PackageSHA256: hash, ResolvedAt: resolvedAt,
			},
			wantKeys: []string{"asset_id", "asset_name", "kind", "owner", "package_sha256", "release_id", "release_tag", "repository", "repository_id", "repository_url", "resolved_at", "resolved_commit_sha"}, wantRedirects: -1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.provenance)
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			keys := make([]string, 0, len(object))
			for key := range object {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			if !reflect.DeepEqual(keys, test.wantKeys) {
				t.Fatalf("JSON keys = %#v, want %#v; JSON=%s", keys, test.wantKeys, raw)
			}
			redirects, present := object["redirect_chain"]
			if test.wantRedirects < 0 {
				if present {
					t.Fatalf("redirect_chain must be absent from %s provenance: %s", test.provenance.Kind, raw)
				}
				return
			}
			var values []ExternalPackageRedirectHop
			if !present || json.Unmarshal(redirects, &values) != nil || len(values) != test.wantRedirects {
				t.Fatalf("redirect_chain = %s, want array length %d", redirects, test.wantRedirects)
			}
		})
	}

	invalid := ExternalPackageSourceProvenance{
		Kind: string(registry.PackageSourcePackageURL), UploadID: "upload_cross_kind",
		SourceOrigin: "https://plugins.example.test:443", SourcePath: "/plugin.redevplugin", PackageSHA256: hash, ResolvedAt: resolvedAt,
	}
	if _, err := json.Marshal(invalid); err == nil || !strings.Contains(err.Error(), "another source kind") {
		t.Fatalf("cross-kind provenance error = %v", err)
	}
}

func TestBuildExternalPackageSecuritySummaryProjectsCompleteManifest(t *testing.T) {
	m, pins, required := externalPackageProjectionFixture()

	summary, err := buildExternalPackageSecuritySummary(m, pins, required)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(summary.SummarySHA256, "sha256:") || len(summary.SummarySHA256) != len("sha256:")+64 {
		t.Fatalf("summary sha256 = %q", summary.SummarySHA256)
	}
	recomputed, err := externalPackageSecuritySummaryHash(summary)
	if err != nil {
		t.Fatal(err)
	}
	if recomputed != summary.SummarySHA256 {
		t.Fatalf("recomputed summary sha256 = %q, want %q", recomputed, summary.SummarySHA256)
	}
	if len(summary.Methods) != 3 || summary.Methods[0].Method != "documents.read" || summary.Methods[1].Method != "files.reveal" || summary.Methods[2].Method != "jobs.run" {
		t.Fatalf("methods = %#v", summary.Methods)
	}
	job := summary.Methods[2]
	if job.Route.Kind != "worker" || job.Route.WorkerID != "jobs" || job.Effect != "execute" || job.Execution != "operation" || !job.Dangerous {
		t.Fatalf("worker method projection = %#v", job)
	}
	if job.Confirmation.Mode != "risk_based" || job.Confirmation.PreflightMethod != "jobs.plan" || !job.Confirmation.PlanHashRequired ||
		!reflect.DeepEqual(job.Confirmation.RequestHashFields, []string{"path", "target"}) {
		t.Fatalf("worker method confirmation = %#v", job.Confirmation)
	}
	if job.Cancel == nil || !job.Cancel.Cancelable || job.Cancel.DisableBehavior != "cancel" ||
		job.Cancel.UninstallBehavior != "cancel_then_block_delete" || job.Cancel.AckTimeoutMS != 2500 {
		t.Fatalf("worker method cancel = %#v", job.Cancel)
	}
	if !reflect.DeepEqual(job.RequiredPermissions, []string{"jobs.execute", "network.use", "storage.write"}) {
		t.Fatalf("worker required permissions = %#v", job.RequiredPermissions)
	}
	capability := summary.Methods[0]
	if capability.Route.Kind != "capability" || capability.Route.BindingID != "documents" || capability.Route.TargetMethod != "documents.read" ||
		!reflect.DeepEqual(capability.RequiredPermissions, []string{"documents.read"}) {
		t.Fatalf("capability method projection = %#v", capability)
	}
	if len(summary.Permissions) != 4 || summary.Permissions[0].PermissionID != "documents.read" || summary.Permissions[3].PermissionID != "storage.write" {
		t.Fatalf("permissions = %#v", summary.Permissions)
	}
	if len(summary.CapabilityContracts) != 2 || summary.CapabilityContracts[0].BindingID != "documents" ||
		summary.CapabilityContracts[0].ContractSHA256 != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("capability contracts = %#v", summary.CapabilityContracts)
	}
	if len(summary.Workers) != 2 || summary.Workers[0].WorkerID != "cleanup" || summary.Workers[1].WorkerID != "jobs" || summary.Workers[1].IdleTimeoutMS != 5000 {
		t.Fatalf("workers = %#v", summary.Workers)
	}
	if len(summary.Network) != 2 || summary.Network[0].ConnectorID != "api" || !summary.Network[0].AuthDeclared || summary.Network[0].TLSDeclared ||
		len(summary.Network[0].MethodAccess) != 1 || !reflect.DeepEqual(summary.Network[0].MethodAccess[0].Operations, []string{"http", "http_stream"}) ||
		!reflect.DeepEqual(summary.Network[0].MethodAccess[0].HTTPMethods, []string{"GET", "POST"}) {
		t.Fatalf("network = %#v", summary.Network)
	}
	if summary.Network[1].ConnectorID != "socket" || summary.Network[1].AuthDeclared || !summary.Network[1].TLSDeclared {
		t.Fatalf("network presence flags = %#v", summary.Network[1])
	}
	if len(summary.Storage) != 2 || summary.Storage[0].StoreID != "cache" || summary.Storage[1].StoreID != "state" ||
		len(summary.Storage[1].MethodAccess) != 1 || !reflect.DeepEqual(summary.Storage[1].MethodAccess[0].Operations, []string{"put", "write"}) {
		t.Fatalf("storage = %#v", summary.Storage)
	}
	if len(summary.SecretRefs) != 1 || summary.SecretRefs[0] != (ExternalPackageSecretRefSummary{SettingKey: "api_token", SecretRef: "api.token", Scope: "environment"}) {
		t.Fatalf("secret refs = %#v", summary.SecretRefs)
	}
	if len(summary.CoreActions) != 1 || summary.CoreActions[0] != (ExternalPackageCoreActionSummary{Method: "files.reveal", ActionID: "files.reveal", Effect: "read"}) {
		t.Fatalf("core actions = %#v", summary.CoreActions)
	}
	if len(summary.Intents) != 2 || summary.Intents[0].IntentID != "jobs.open" || summary.Intents[1].IntentID != "reveal.file" {
		t.Fatalf("intents = %#v", summary.Intents)
	}
	if len(summary.Surfaces) != 2 || summary.Surfaces[0].SurfaceID != "background" || summary.Surfaces[1].SurfaceID != "main" ||
		summary.Surfaces[1].DefaultSize == nil || summary.Surfaces[1].DefaultSize.Width != 720 || summary.Surfaces[1].Entry != "ui/main.html" {
		t.Fatalf("surfaces = %#v", summary.Surfaces)
	}
}

func TestBuildExternalPackageSecuritySummaryIsCanonicalAcrossInputOrder(t *testing.T) {
	m, pins, required := externalPackageProjectionFixture()
	want, err := buildExternalPackageSecuritySummary(m, pins, required)
	if err != nil {
		t.Fatal(err)
	}

	slices.Reverse(m.Methods)
	slices.Reverse(m.CapabilityBindings)
	slices.Reverse(m.Workers)
	slices.Reverse(m.Storage.Stores)
	slices.Reverse(m.NetworkAccess.Connectors)
	slices.Reverse(m.Settings.Fields)
	slices.Reverse(m.Intents)
	slices.Reverse(m.Surfaces)
	slices.Reverse(pins)
	for index := range m.Methods {
		if m.Methods[index].BrokerAccess == nil {
			continue
		}
		slices.Reverse(m.Methods[index].BrokerAccess.Storage)
		slices.Reverse(m.Methods[index].BrokerAccess.Network)
		for accessIndex := range m.Methods[index].BrokerAccess.Storage {
			slices.Reverse(m.Methods[index].BrokerAccess.Storage[accessIndex].Operations)
		}
		for accessIndex := range m.Methods[index].BrokerAccess.Network {
			slices.Reverse(m.Methods[index].BrokerAccess.Network[accessIndex].Operations)
			slices.Reverse(m.Methods[index].BrokerAccess.Network[accessIndex].HTTPMethods)
		}
	}
	for index := range m.NetworkAccess.Connectors {
		slices.Reverse(m.NetworkAccess.Connectors[index].Destinations)
	}
	for method := range required {
		slices.Reverse(required[method])
	}

	got, err := buildExternalPackageSecuritySummary(m, pins, required)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reordered summary differs\n got: %#v\nwant: %#v", got, want)
	}

	changed := m
	changed.Workers = append([]manifest.WorkerSpec(nil), m.Workers...)
	changed.Workers[0].MemoryLimitBytes++
	different, err := buildExternalPackageSecuritySummary(changed, pins, required)
	if err != nil {
		t.Fatal(err)
	}
	if different.SummarySHA256 == want.SummarySHA256 {
		t.Fatal("security-relevant worker change did not change summary hash")
	}
}

func TestBuildExternalPackageSecuritySummaryRejectsIncompleteResolution(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*manifest.Manifest, *[]capabilitycontract.Pin, map[string][]string)
		contains string
	}{
		{
			name: "missing pin",
			mutate: func(_ *manifest.Manifest, pins *[]capabilitycontract.Pin, _ map[string][]string) {
				*pins = (*pins)[:1]
			},
			contains: "was not resolved",
		},
		{
			name: "unknown permission method",
			mutate: func(_ *manifest.Manifest, _ *[]capabilitycontract.Pin, required map[string][]string) {
				required["missing.method"] = []string{"missing.permission"}
			},
			contains: "unknown method",
		},
		{
			name: "unknown storage",
			mutate: func(m *manifest.Manifest, _ *[]capabilitycontract.Pin, _ map[string][]string) {
				m.Methods[0].BrokerAccess = &manifest.MethodBrokerAccessSpec{Storage: []manifest.StorageBrokerAccessSpec{{StoreID: "missing", Operations: []string{"read"}}}}
			},
			contains: "undeclared storage",
		},
		{
			name: "unknown network",
			mutate: func(m *manifest.Manifest, _ *[]capabilitycontract.Pin, _ map[string][]string) {
				m.Methods[0].BrokerAccess = &manifest.MethodBrokerAccessSpec{Network: []manifest.NetworkBrokerAccessSpec{{ConnectorID: "missing", Transport: "http", Operations: []string{"http"}}}}
			},
			contains: "undeclared network",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture, fixturePins, fixtureRequired := externalPackageProjectionFixture()
			tt.mutate(&fixture, &fixturePins, fixtureRequired)
			_, err := buildExternalPackageSecuritySummary(fixture, fixturePins, fixtureRequired)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("error = %v, want containing %q", err, tt.contains)
			}
		})
	}
}

func TestExternalPackageSecuritySummaryJSONFieldsMatchOpenAPI(t *testing.T) {
	tests := []struct {
		value any
		want  []string
	}{
		{value: ExternalPackagePermissionSummary{}, want: []string{"methods", "permission_id"}},
		{value: ExternalPackageMethodRouteSummary{}, want: []string{"action_id", "binding_id", "kind", "target_method", "worker_id"}},
		{value: ExternalPackageConfirmationSummary{}, want: []string{"mode", "plan_hash_required", "preflight_method", "request_hash_fields"}},
		{value: ExternalPackageCancelSummary{}, want: []string{"ack_timeout_ms", "cancelable", "disable_behavior", "uninstall_behavior"}},
		{value: ExternalPackageMethodSummary{}, want: []string{"cancel", "confirmation", "dangerous", "effect", "execution", "method", "preflight_only", "required_permissions", "route"}},
		{value: ExternalPackageCapabilityContractSummary{}, want: []string{"binding_id", "capability_id", "capability_version", "contract_sha256"}},
		{value: ExternalPackageWorkerSummary{}, want: []string{"abi", "artifact", "idle_timeout_ms", "memory_limit_bytes", "mode", "scope", "worker_id"}},
		{value: ExternalPackageNetworkMethodAccessSummary{}, want: []string{"http_methods", "method", "operations"}},
		{value: ExternalPackageNetworkSummary{}, want: []string{"auth_declared", "connector_id", "destinations", "method_access", "scope", "tls_declared", "transport"}},
		{value: ExternalPackageStorageMethodAccessSummary{}, want: []string{"method", "operations"}},
		{value: ExternalPackageStorageSummary{}, want: []string{"kind", "method_access", "quota_bytes", "quota_files", "schema_version", "scope", "store_id"}},
		{value: ExternalPackageSecretRefSummary{}, want: []string{"scope", "secret_ref", "setting_key"}},
		{value: ExternalPackageCoreActionSummary{}, want: []string{"action_id", "effect", "method"}},
		{value: ExternalPackageIntentSummary{}, want: []string{"intent_id", "method"}},
		{value: ExternalPackageSurfaceSummary{}, want: []string{"default_size", "entry", "icon", "intent", "kind", "label", "surface_id"}},
		{value: ExternalPackageSizeSummary{}, want: []string{"height", "width"}},
		{value: ExternalPackageSecuritySummary{}, want: []string{"capability_contracts", "core_actions", "intents", "methods", "network", "permissions", "secret_refs", "storage", "summary_sha256", "surfaces", "workers"}},
	}
	for _, tt := range tests {
		typeOf := reflect.TypeOf(tt.value)
		got := make([]string, 0, typeOf.NumField())
		for i := 0; i < typeOf.NumField(); i++ {
			name := strings.Split(typeOf.Field(i).Tag.Get("json"), ",")[0]
			got = append(got, name)
		}
		slices.Sort(got)
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("%s JSON fields = %#v, want %#v", typeOf.Name(), got, tt.want)
		}
	}
}

func externalPackageProjectionFixture() (manifest.Manifest, []capabilitycontract.Pin, map[string][]string) {
	quotaFiles := int64(1200)
	preflight := "jobs.plan"
	documentsPin := capabilitycontract.Pin{
		PublisherID: "redev.official", ContractID: "documents", ContractVersion: "1.2.0",
		ArtifactSHA256: strings.Repeat("a", 64),
	}
	terminalPin := capabilitycontract.Pin{
		PublisherID: "redev.official", ContractID: "terminal", ContractVersion: "2.0.0",
		ArtifactSHA256: "sha256:" + strings.Repeat("b", 64),
	}
	m := manifest.Manifest{
		SchemaVersion: "redevplugin.manifest.v5",
		Publisher:     manifest.Publisher{PublisherID: "example.publisher"},
		Plugin: manifest.Plugin{
			PluginID: "example.external", DisplayName: "External", Version: "2.0.1", APIVersion: "plugin-v1",
			MinRuntimeVersion: "1.0.0", UIProtocolVersion: "plugin-ui-v5",
		},
		CapabilityBindings: []manifest.CapabilityBinding{
			{BindingID: "terminal", Contract: terminalPin},
			{BindingID: "documents", Contract: documentsPin},
		},
		Methods: []manifest.MethodSpec{
			{
				Method: "jobs.run", Effect: manifest.MethodEffectExecute, Execution: manifest.MethodExecutionOperation, Dangerous: true,
				Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "jobs"},
				Confirmation: &manifest.ConfirmationSpec{
					Mode: manifest.ConfirmationRiskBased, PreflightMethod: &preflight, RequestHashFields: []string{"target", "path"}, PlanHashRequired: true,
				},
				CancelPolicy: &manifest.CancelPolicySpec{
					Cancelable: true, DisableBehavior: "cancel", UninstallBehavior: "cancel_then_block_delete", AckTimeoutMS: 2500,
				},
				BrokerAccess: &manifest.MethodBrokerAccessSpec{
					Storage: []manifest.StorageBrokerAccessSpec{{StoreID: "state", Operations: []string{"write", "put"}}},
					Network: []manifest.NetworkBrokerAccessSpec{{
						ConnectorID: "api", Transport: "http", Scope: "environment", Operations: []string{"http_stream", "http"}, HTTPMethods: []string{"POST", "GET"},
					}},
				},
			},
			{
				Method: "files.reveal", Effect: manifest.MethodEffectRead, Execution: manifest.MethodExecutionSync,
				Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCoreAction, ActionID: "files.reveal"},
			},
			{
				Method: "documents.read",
				Route:  manifest.MethodRouteSpec{Kind: manifest.MethodRouteCapability, BindingID: "documents", TargetMethod: "documents.read"},
			},
		},
		Workers: []manifest.WorkerSpec{
			{WorkerID: "jobs", Artifact: "workers/jobs.wasm", ABI: "redevplugin-wasm-worker-v2", Mode: manifest.WorkerModeJob, Scope: "environment", MemoryLimitBytes: 64 << 20, IdleTimeoutMS: 5000},
			{WorkerID: "cleanup", Artifact: "workers/cleanup.wasm", ABI: "redevplugin-wasm-worker-v2", Mode: manifest.WorkerModeJob, Scope: "user", MemoryLimitBytes: 32 << 20},
		},
		Storage: &manifest.StorageSpec{Stores: []manifest.StoreSpec{
			{StoreID: "state", Kind: "sqlite", Scope: "environment", QuotaBytes: 8 << 20, QuotaFiles: &quotaFiles, SchemaVersion: 3},
			{StoreID: "cache", Kind: "files", Scope: "user", QuotaBytes: 16 << 20, SchemaVersion: 1},
		}},
		NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{
			{ConnectorID: "socket", Transport: "websocket", Scope: "user", Destinations: []string{"wss://events.example.test"}, TLS: map[string]any{}},
			{ConnectorID: "api", Transport: "http", Scope: "environment", Destinations: []string{"https://uploads.example.test", "https://api.example.test"}, Auth: map[string]any{}},
		}},
		Settings: &manifest.SettingsSpec{SchemaVersion: 1, Fields: []manifest.SettingFieldSpec{
			{Key: "theme", Type: "string", Label: "Theme", Scope: "user"},
			{Key: "api_token", Type: "string", Label: "API token", Scope: "environment", SecretRef: "api.token"},
		}},
		Intents: []manifest.IntentSpec{
			{IntentID: "reveal.file", Method: "files.reveal"},
			{IntentID: "jobs.open", Method: "jobs.run"},
		},
		Surfaces: []manifest.SurfaceSpec{
			{SurfaceID: "main", Kind: manifest.SurfaceView, Intent: manifest.SurfaceIntentPrimary, Label: "Main", Entry: "ui/main.html", Icon: "icons/main.png", DefaultSize: &manifest.WidgetSizeSpec{Width: 720, Height: 480}},
			{SurfaceID: "background", Kind: manifest.SurfaceBackground, Intent: manifest.SurfaceIntentUtility, Label: "Background", Entry: "ui/background.html"},
		},
	}
	required := map[string][]string{
		"jobs.run":       {"storage.write", "jobs.execute", "network.use", "jobs.execute"},
		"documents.read": {"documents.read"},
		"files.reveal":   {},
	}
	return m, []capabilitycontract.Pin{terminalPin, documentsPin}, required
}
