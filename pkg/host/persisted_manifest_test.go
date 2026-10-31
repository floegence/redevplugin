package host

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func TestPersistedPreWebPackageRemainsManageableButCannotRun(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	record, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	record.Manifest.Surfaces[0].Web = manifest.SurfaceWebSpec{}
	if registry.RunnablePluginRecord(record) {
		t.Fatal("retired package admitted")
	}
	if err := h.canRun(hostTestContext(), record); !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("execution error: %v", err)
	}
	state := h.pluginActionState(hostTestContext(), record)
	if state.CanOpen || state.CanEnable || !state.CanDisable || !state.CanUninstall || state.BlockedReason != PluginActionBlockedIncompatible {
		t.Fatalf("action state: %+v", state)
	}
}

func TestPersistedPreWebHostRestartUpdateAndSiblingIsolation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	assetsPath := filepath.Join(t.TempDir(), "assets")
	openAssets := func() *pluginpkg.FileAssetStore {
		store, err := pluginpkg.NewFileAssetStore(assetsPath)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	options := testHostOptions{stateRoot: root, assets: openAssets(), developerMode: true, localGenerated: true}
	h, _, _ := newTestHostWithOptions(t, options)
	ctx := hostTestContext()
	old, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildVersionedLifecyclePackage(t, "1.0.0", "Retained"))
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "control.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := db.QueryRow("SELECT record_json FROM plugin_records WHERE plugin_instance_id=?", old.PluginInstanceID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(stored["manifest"], &document); err != nil {
		t.Fatal(err)
	}
	for _, surface := range document["surfaces"].([]any) {
		delete(surface.(map[string]any), "web")
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := manifest.CanonicalJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	hash := "sha256:" + hex.EncodeToString(digest[:])
	stored["manifest"] = canonical
	stored["manifest_hash"], _ = json.Marshal(hash)
	assessment := old.SignatureAssessment
	assessment.ManifestSHA256 = hash
	assessment.AssessedHashes.ManifestSHA256 = hash
	stored["signature_assessment"], _ = json.Marshal(assessment)
	trust := old.TrustAssessment
	trust.VerifiedHashes.ManifestSHA256 = hash
	stored["trust_assessment"], _ = json.Marshal(trust)
	encoded, err = json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE plugin_records SET record_json=?,manifest_sha256=? WHERE plugin_instance_id=?", string(encoded), hash, old.PluginInstanceID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	options.assets = openAssets()
	h, _, _ = newTestHostWithOptions(t, options)
	inventory, err := h.ListPluginInventory(ctx)
	if err != nil || len(inventory) != 2 {
		t.Fatalf("inventory: %+v %v", inventory, err)
	}
	for _, item := range inventory {
		if item.Plugin.PluginInstanceID == old.PluginInstanceID && (item.ActionState.CanOpen || item.ActionState.BlockedReason != PluginActionBlockedIncompatible) {
			t.Fatalf("retained action: %+v", item.ActionState)
		}
		if item.Plugin.PluginInstanceID == sibling.PluginInstanceID && !item.ActionState.CanOpen {
			t.Fatalf("sibling blocked: %+v", item.ActionState)
		}
	}
	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{PluginInstanceID: old.PluginInstanceID, SurfaceID: "lifecycle.view", ExpectedManagementRevision: mustManagementRevision(t, h, old.PluginInstanceID)}); !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("retained open: %v", err)
	}
	retainedDisabled, err := h.DisablePlugin(ctx, DisableRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, old.PluginInstanceID)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: retainedDisabled.ManagementRevision}); !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("retired enable admitted: %v", err)
	}
	if mustManagementRevision(t, h, old.PluginInstanceID) != retainedDisabled.ManagementRevision {
		t.Fatal("rejected enable mutated retained state")
	}
	next := buildVersionedLifecyclePackage(t, "2.0.0", "Web")
	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{PluginInstanceID: old.PluginInstanceID, PackageReader: bytes.NewReader(next), PackageSize: int64(len(next)), ExpectedManagementRevision: mustManagementRevision(t, h, old.PluginInstanceID)})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.VersionHistory) != 1 || updated.VersionHistory[0].CanonicalManifest != string(canonical) {
		t.Fatal("Web update discarded retained identity")
	}
	updated, err = h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: updated.PluginInstanceID, ExpectedManagementRevision: updated.ManagementRevision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.DowngradePlugin(ctx, DowngradeRequest{PluginInstanceID: updated.PluginInstanceID, Version: "1.0.0", ExpectedManagementRevision: updated.ManagementRevision}); !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("retired downgrade admitted: %v", err)
	}
	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{PluginInstanceID: updated.PluginInstanceID, SurfaceID: "lifecycle.view", ExpectedManagementRevision: updated.ManagementRevision}); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	options.assets = openAssets()
	h, _, _ = newTestHostWithOptions(t, options)
	if _, err := h.ListPluginInventory(ctx); err != nil {
		t.Fatal(err)
	}
	disabled, err := h.DisablePlugin(ctx, DisableRequest{PluginInstanceID: updated.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, updated.PluginInstanceID)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.DowngradePlugin(ctx, DowngradeRequest{PluginInstanceID: updated.PluginInstanceID, Version: "1.0.0", ExpectedManagementRevision: disabled.ManagementRevision}); !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("disabled retired downgrade admitted: %v", err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: updated.PluginInstanceID, DeleteData: false, ExpectedManagementRevision: disabled.ManagementRevision}); err != nil {
		t.Fatal(err)
	}
	inventory, err = h.ListPluginInventory(ctx)
	if err != nil || len(inventory) != 1 || inventory[0].Plugin.PluginInstanceID != sibling.PluginInstanceID || !inventory[0].ActionState.CanOpen {
		t.Fatalf("sibling after uninstall: %+v %v", inventory, err)
	}
}
