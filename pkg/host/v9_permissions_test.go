package host

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/floegence/redevplugin/v2/pkg/permissions"
	"github.com/floegence/redevplugin/v2/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v2/pkg/registry"
)

func TestV9ExternalPackagePermissionConfirmationCoversWorkerIO(t *testing.T) {
	for _, test := range []struct {
		name        string
		approved    []string
		wantStatus  registry.ReleaseInstallActivationStatus
		wantEnabled registry.EnableState
	}{
		{name: "missing approval", wantStatus: registry.ReleaseInstallActivationNeedsAttention, wantEnabled: registry.EnableDisabled},
		{name: "approved", approved: []string{"network.client", "fs.environment.write", "fs.environment.read"}, wantStatus: registry.ReleaseInstallActivationEnabled, wantEnabled: registry.EnableEnabled},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
			stage := &externalPackageTestStage{pkg: readTestPackage(t, buildV9IOPermissionFixturePackage(t))}
			configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})

			inspection, err := h.InspectUploadedExternalPackage(hostTestContext(), InspectUploadedExternalPackageRequest{
				Intent: ExternalPackageIntent{Action: "install"}, Package: bytes.NewReader([]byte("package")), DeclaredSize: 7,
			})
			if err != nil {
				t.Fatal(err)
			}
			wantPermissions := []ExternalPackagePermissionSummary{
				{PermissionID: "fs.environment.read", Methods: []string{"io.run"}},
				{PermissionID: "fs.environment.write", Methods: []string{"io.run"}},
				{PermissionID: "network.client", Methods: []string{"io.run"}},
			}
			if !reflect.DeepEqual(inspection.SecuritySummary.Permissions, wantPermissions) {
				t.Fatalf("inspection permissions = %#v, want %#v", inspection.SecuritySummary.Permissions, wantPermissions)
			}
			if len(inspection.SecuritySummary.Methods) != 1 || !reflect.DeepEqual(inspection.SecuritySummary.Methods[0].RequiredPermissions, []string{
				"fs.environment.read", "fs.environment.write", "network.client",
			}) {
				t.Fatalf("inspection worker methods = %#v", inspection.SecuritySummary.Methods)
			}

			installed, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
				InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256,
				ApprovedPermissionIDs: test.approved,
			})
			if err != nil {
				t.Fatal(err)
			}
			if installed.Plugin == nil || installed.Plugin.EnableState != test.wantEnabled || installed.Activation.Status != test.wantStatus {
				t.Fatalf("activation = %#v, plugin = %#v", installed.Activation, installed.Plugin)
			}
			wantMissing := []string(nil)
			if len(test.approved) == 0 {
				wantMissing = []string{"fs.environment.read", "fs.environment.write", "network.client"}
			}
			if !reflect.DeepEqual(installed.Activation.MissingPermissionIDs, wantMissing) {
				t.Fatalf("missing permissions = %#v, want %#v", installed.Activation.MissingPermissionIDs, wantMissing)
			}
			grants, err := h.ListPermissionGrants(hostTestContext(), ListPermissionGrantsRequest{PluginInstanceID: installed.Plugin.PluginInstanceID})
			if err != nil {
				t.Fatal(err)
			}
			if len(grants) != len(test.approved) {
				t.Fatalf("permission grants = %#v, want %d", grants, len(test.approved))
			}
		})
	}
}

func TestV9WorkerMethodRequiresGrantedPackagePermissions(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	installed := installAndEnablePlugin(t, h, buildV9IOPermissionFixturePackage(t))
	grants, err := h.ListPermissionGrants(hostTestContext(), ListPermissionGrantsRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("local import silently granted v9 permissions: %#v", grants)
	}
	record, err := h.getPluginRecord(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	method, ok := manifestMethod(record.Manifest, "io.run")
	if !ok {
		t.Fatal("persisted v9 worker method is missing")
	}
	required, err := h.requiredPermissionsForMethod(record, method)
	if err != nil {
		t.Fatal(err)
	}
	wantRequired := []string{"fs.environment.read", "fs.environment.write", "network.client"}
	if !reflect.DeepEqual(required, wantRequired) {
		t.Fatalf("persisted v9 worker required permissions = %#v source=%q model=%#v, want %#v", required, record.ManifestModel.SchemaSource, record.ManifestModel.Permissions, wantRequired)
	}
	for _, permissionID := range wantRequired {
		revisions := mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
		if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{
			PluginInstanceID: installed.PluginInstanceID, PermissionID: permissionID,
			ExpectedPolicyRevision: revisions.PolicyRevision, ExpectedManagementRevision: revisions.ManagementRevision,
			ExpectedRevokeEpoch: revisions.RevokeEpoch,
		}); err != nil {
			t.Fatal(err)
		}
	}
	revisions := mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
	if _, err := h.RevokePermission(hostTestContext(), RevokePermissionRequest{
		PluginInstanceID: installed.PluginInstanceID, PermissionID: "network.client",
		ExpectedPolicyRevision: revisions.PolicyRevision, ExpectedManagementRevision: revisions.ManagementRevision,
		ExpectedRevokeEpoch: revisions.RevokeEpoch,
	}); err != nil {
		t.Fatal(err)
	}
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "io.view")
	call := CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "io.run", Params: map[string]any{},
	}
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("CallPluginMethod() after v9 package grant revoke error = %v, want %v", err, permissions.ErrPermissionDenied)
	}
}

func buildV9IOPermissionFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), `{
  "schema_version": "redevplugin.manifest.v9",
  "publisher": {"publisher_id": "com.example", "display_name": "Example"},
  "plugin": {"plugin_id": "com.example.io-v9", "display_name": "I/O v9", "version": "9.0.0"},
  "api": {"surface": 1, "worker": 1, "required_features": ["io.stream.v1", "fs.environment.v1", "net.http.v1"]},
  "permissions": ["fs.environment.read", "fs.environment.write", "network.client"],
  "presentation": {"locales": {"default": "en-US"}},
  "surfaces": [{"surface_id": "io.view", "kind": "view", "label": "I/O", "entry": "ui/index.html"}],
  "workers": [{"worker_id": "io_worker", "artifact": "workers/io.wasm", "mode": "job", "scope": "environment", "memory_limit_bytes": 16777216}],
  "methods": [{"method": "io.run", "worker_id": "io_worker", "effect": "execute", "execution": "sync", "request_schema": {"type": "object", "additionalProperties": false}, "response_schema": {"type": "object", "additionalProperties": false}}]
}`)
	writeSurfaceFixture(t, dir, "I/O v9")
	writeBytes(t, filepath.Join(dir, "workers", "io.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var output bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &output, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
