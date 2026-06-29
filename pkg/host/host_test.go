package host

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestLifecycleInstallEnableDisableUninstall(t *testing.T) {
	host, surfaces, audits := newTestHost(t, true, true)
	packageBytes := buildFixturePackage(t)

	installed, err := InstallPackageBytes(context.Background(), host, packageBytes, registry.TrustVerified)
	if err != nil {
		t.Fatalf("InstallPackageBytes() error = %v", err)
	}
	if installed.EnableState != registry.EnableDisabled {
		t.Fatalf("install EnableState = %s", installed.EnableState)
	}
	if installed.PolicyRevision == 0 || installed.ManagementRevision == 0 {
		t.Fatalf("revision fields not initialized: %#v", installed)
	}

	enabled, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable EnableState = %s", enabled.EnableState)
	}
	if len(surfaces.snapshots) != 1 || len(surfaces.snapshots[0].Surfaces) != 1 {
		t.Fatalf("surface publish mismatch: %#v", surfaces.snapshots)
	}

	disabled, err := host.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "test"})
	if err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if disabled.EnableState != registry.EnableDisabled {
		t.Fatalf("disable EnableState = %s", disabled.EnableState)
	}
	if len(surfaces.snapshots) != 2 || len(surfaces.snapshots[1].Surfaces) != 0 {
		t.Fatalf("disable did not clear surfaces: %#v", surfaces.snapshots)
	}

	uninstalled, err := host.UninstallPlugin(context.Background(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true})
	if err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	if uninstalled.RetainedDataState != registry.RetainedDataDeleted {
		t.Fatalf("RetainedDataState = %s", uninstalled.RetainedDataState)
	}
	if _, err := host.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID); err != registry.ErrNotFound {
		t.Fatalf("GetPlugin after uninstall error = %v", err)
	}
	if len(audits.events) != 4 {
		t.Fatalf("audit count = %d", len(audits.events))
	}
}

func TestEnableRejectsUntrusted(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	installed, err := InstallPackageBytes(context.Background(), host, buildFixturePackage(t), registry.TrustUntrusted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err == nil {
		t.Fatal("EnablePlugin() expected untrusted error")
	}
}

func TestEnableUnsignedLocalRequiresPolicy(t *testing.T) {
	host, _, _ := newTestHost(t, false, true)
	installed, err := InstallPackageBytes(context.Background(), host, buildFixturePackage(t), registry.TrustUnsignedLocal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err == nil {
		t.Fatal("EnablePlugin() expected policy error")
	}
	record, err := host.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if record.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("EnableState = %s", record.EnableState)
	}
}

func newTestHost(t *testing.T, developerMode bool, localGenerated bool) (*Host, *surfaceSink, *auditSink) {
	t.Helper()
	surfaces := &surfaceSink{}
	audits := &auditSink{}
	host, err := New(Adapters{
		SessionResolver: fakeSessionResolver{},
		Policy: policyAdapter{
			developerMode:  developerMode,
			localGenerated: localGenerated,
		},
		SurfaceCatalog: surfaces,
		Audit:          audits,
	})
	if err != nil {
		t.Fatal(err)
	}
	return host, surfaces, audits
}

func buildFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), fixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Plugin</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeFile(t *testing.T, filename string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.lifecycle",
			"display_name": "Lifecycle",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "lifecycle.activity", "kind": "activity", "label": "Lifecycle", "entry": "ui/index.html"}
		]
	}`
}

type fakeSessionResolver struct{}

func (fakeSessionResolver) ResolveSession(context.Context, string) (sessionctx.Context, error) {
	return sessionctx.Context{}, nil
}

type policyAdapter struct {
	developerMode  bool
	localGenerated bool
}

func (p policyAdapter) EvaluateLocalPolicy(context.Context, sessionctx.Context, PluginRef, manifest.MethodSpec) (PolicyDecision, error) {
	return PolicyAllow, nil
}

func (p policyAdapter) DeveloperModeEnabled(context.Context, sessionctx.Context) (bool, error) {
	return p.developerMode, nil
}

func (p policyAdapter) LocalGeneratedPluginsEnabled(context.Context, sessionctx.Context) (bool, error) {
	return p.localGenerated, nil
}

type surfaceSink struct {
	snapshots []SurfaceSnapshot
}

func (s *surfaceSink) PublishSurfaces(_ context.Context, snapshot SurfaceSnapshot) error {
	s.snapshots = append(s.snapshots, snapshot)
	return nil
}

type auditSink struct {
	events []AuditEvent
}

func (s *auditSink) AppendPluginAudit(_ context.Context, event AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}
