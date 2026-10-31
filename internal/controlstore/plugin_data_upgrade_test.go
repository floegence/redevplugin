package controlstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func TestPluginDataUpgradeCommitsPackageAndBothGenerations(t *testing.T) {
	ctx := pluginDataCatalogContext("env-upgrade", "user-upgrade")
	path := filepath.Join(t.TempDir(), "control.sqlite")
	store, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	current := putPluginDataCatalogRecord(t, store, ctx, "upgrade-instance")
	previous, found, err := store.GetBinding(ctx, current.PluginInstanceID)
	if err != nil || !found {
		t.Fatalf("current binding: %v %v", found, err)
	}
	next := pluginDataUpgradeRecord(t, current, "2.0.0")
	binding := previous
	binding.GenerationID = "generation-upgraded"
	binding.Revision++
	stored, err := store.CommitPluginDataUpgrade(ctx, current, next, previous, binding, time.Now().UTC(), false)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != next.Version || stored.ManagementRevision != current.ManagementRevision+1 || stored.RevokeEpoch != current.RevokeEpoch+1 {
		t.Fatalf("record: %#v", stored)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := store.Registry().GetPlugin(ctx, current.OwnerEnvHash, current.PluginInstanceID)
	if err != nil || persisted.Manifest.Plugin.Version != next.Version || persisted.CanonicalManifest != next.CanonicalManifest || persisted.ManifestHash != next.ManifestHash {
		t.Fatalf("persisted manifest version = %q, want %q: %v", persisted.Manifest.Plugin.Version, next.Version, err)
	}
	active, found, err := store.GetBinding(ctx, current.PluginInstanceID)
	if err != nil || !found || !plugindata.SameBinding(active, binding) {
		t.Fatalf("active: %#v %v", active, err)
	}
	history, err := store.GetPluginDataHistory(ctx, current.PluginInstanceID, previous.GenerationID)
	if err != nil || history.Record.Version != current.Version || !plugindata.SameBinding(history.Binding, previous) {
		t.Fatalf("history: %#v %v", history, err)
	}
	references, _, err := store.ListAllBindingsForMaintenance(ctx, "", 10)
	if err != nil || len(references) != 2 {
		t.Fatalf("generation references = %d, want 2: %v", len(references), err)
	}
	if _, err := store.CommitPluginDataUpgrade(ctx, current, next, previous, binding, time.Now().UTC(), false); !errors.Is(err, registry.ErrAuthorizationRevisionConflict) {
		t.Fatalf("stale commit: %v", err)
	}
	foreign := pluginDataCatalogContext("another-environment", "user-upgrade")
	if _, err := store.GetPluginDataHistory(foreign, current.PluginInstanceID, previous.GenerationID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("foreign history: %v", err)
	}
}

func TestPluginDataUpgradeFailureRollsBackPackageBindingAndHistory(t *testing.T) {
	ctx := pluginDataCatalogContext("env-upgrade-failure", "user-upgrade")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	current := putPluginDataCatalogRecord(t, store, ctx, "upgrade-failure")
	previous, _, err := store.GetBinding(ctx, current.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	next := pluginDataUpgradeRecord(t, current, "2.0.0")
	binding := previous
	binding.GenerationID = "generation-rejected"
	binding.Revision++
	if _, err := store.db.Exec("CREATE TRIGGER reject_upgrade BEFORE UPDATE ON plugin_data_bindings BEGIN SELECT RAISE(ABORT, 'injected upgrade failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitPluginDataUpgrade(ctx, current, next, previous, binding, time.Now().UTC(), false); err == nil || !strings.Contains(err.Error(), "injected upgrade failure") {
		t.Fatalf("injected transaction failure was not reached: %v", err)
	}
	actual, err := store.Registry().GetPlugin(ctx, current.OwnerEnvHash, current.PluginInstanceID)
	if err != nil || actual.Version != current.Version || actual.ManagementRevision != current.ManagementRevision {
		t.Fatalf("record changed: %#v %v", actual, err)
	}
	active, _, err := store.GetBinding(ctx, current.PluginInstanceID)
	if err != nil || !plugindata.SameBinding(active, previous) {
		t.Fatalf("binding changed: %#v %v", active, err)
	}
	if _, err := store.GetPluginDataHistory(ctx, current.PluginInstanceID, previous.GenerationID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("history changed: %v", err)
	}
}

func pluginDataUpgradeRecord(t *testing.T, current registry.PluginRecord, version string) registry.PluginRecord {
	t.Helper()
	next := current
	raw, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot registry.PluginVersion
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.CanonicalManifest = current.CanonicalManifest
	snapshot.ActivatedAt = time.Now().UTC()
	next.VersionHistory = append(append([]registry.PluginVersion(nil), current.VersionHistory...), snapshot)
	next.Version = version
	next.Manifest.Plugin.Version = version
	canonical, err := manifest.MarshalCanonical(next.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	next.CanonicalManifest = string(canonical)
	sum := sha256.Sum256(canonical)
	next.ManifestHash = "sha256:" + hex.EncodeToString(sum[:])
	next.SignatureAssessment.ManifestSHA256 = next.ManifestHash
	next.SignatureAssessment.AssessedHashes.ManifestSHA256 = next.ManifestHash
	next.TrustAssessment.VerifiedHashes.ManifestSHA256 = next.ManifestHash
	next.ActiveFingerprint = "sha256:fingerprint-" + version
	next.PackageHash = "sha256:package-" + version
	next.ExecutionApproval.PackageSHA256 = next.PackageHash
	next.SignatureAssessment.PackageSHA256 = next.PackageHash
	next.SignatureAssessment.AssessedHashes.PackageSHA256 = next.PackageHash
	next.TrustAssessment.VerifiedHashes.PackageSHA256 = next.PackageHash
	next.PackageSourceProvenance.PackageSHA256 = next.PackageHash
	return next
}

func TestPluginDataUpgradeRejectsInconsistentPackageIdentity(t *testing.T) {
	for _, field := range []string{"canonical", "hash", "version", "publisher", "plugin", "management_overflow", "revoke_overflow"} {
		t.Run(field, func(t *testing.T) {
			ctx := pluginDataCatalogContext("env-identity", "user")
			store := openPluginDataCatalogStore(t)
			defer store.Close()
			current := putPluginDataCatalogRecord(t, store, ctx, "identity")
			previous, _, err := store.GetBinding(ctx, current.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			next := pluginDataUpgradeRecord(t, current, "2.0.0")
			switch field {
			case "canonical":
				next.CanonicalManifest = current.CanonicalManifest
			case "hash":
				next.ManifestHash = current.ManifestHash
			case "version":
				next.Version = "3.0.0"
			case "publisher":
				next.PublisherID = "another"
			case "plugin":
				next.PluginID = "com.example.another"
			case "management_overflow":
				current.ManagementRevision = 1<<63 - 1
			case "revoke_overflow":
				current.RevokeEpoch = 1<<63 - 1
			}
			binding := previous
			binding.GenerationID = "new-generation"
			binding.Revision++
			if _, err := store.CommitPluginDataUpgrade(ctx, current, next, previous, binding, time.Now().UTC(), false); err == nil {
				t.Fatal("inconsistent identity accepted")
			}
			var count int
			if err := store.db.QueryRowContext(context.Background(), "SELECT count(*) FROM plugin_data_history").Scan(&count); err != nil || count != 0 {
				t.Fatalf("rejected identity mutated history: %d %v", count, err)
			}
		})
	}
}

func TestPluginDataRestoreRollsBackHistoryAndRejectsStaleBinding(t *testing.T) {
	ctx := pluginDataCatalogContext("env-restore", "user")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	old := putPluginDataCatalogRecord(t, store, ctx, "restore")
	before, _, err := store.GetBinding(ctx, old.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	nextBinding := before
	nextBinding.GenerationID = "upgraded-generation"
	nextBinding.Revision++
	current, err := store.CommitPluginDataUpgrade(ctx, old, pluginDataUpgradeRecord(t, old, "2.0.0"), before, nextBinding, time.Now().UTC(), false)
	if err != nil {
		t.Fatal(err)
	}
	restore := before
	restore.Revision = nextBinding.Revision + 1
	target := old
	target.ManagementRevision = current.ManagementRevision
	target.RevokeEpoch = current.RevokeEpoch
	if _, err := store.db.Exec("CREATE TRIGGER reject_restore BEFORE UPDATE ON plugin_data_bindings BEGIN SELECT RAISE(ABORT, 'injected restore failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitPluginDataRestore(ctx, current, target, nextBinding, restore, before, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "injected restore failure") {
		t.Fatalf("restore failure: %v", err)
	}
	active, _, err := store.GetBinding(ctx, old.PluginInstanceID)
	if err != nil || !plugindata.SameBinding(active, nextBinding) {
		t.Fatalf("binding mutated: %+v %v", active, err)
	}
	if _, err := store.GetPluginDataHistory(ctx, old.PluginInstanceID, before.GenerationID); err != nil {
		t.Fatalf("retained history deleted: %v", err)
	}
	if _, err := store.GetPluginDataHistory(ctx, old.PluginInstanceID, nextBinding.GenerationID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("active history inserted: %v", err)
	}
	if _, err := store.db.Exec("DROP TRIGGER reject_restore"); err != nil {
		t.Fatal(err)
	}
	stale := before
	stale.Revision++
	if _, err := store.CommitPluginDataRestore(ctx, current, target, nextBinding, restore, stale, time.Now().UTC()); !errors.Is(err, plugindata.ErrBindingConflict) {
		t.Fatalf("stale history: %v", err)
	}
	if _, err := store.CommitPluginDataRestore(ctx, current, target, nextBinding, restore, before, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitPluginDataRestore(ctx, current, target, nextBinding, restore, before, time.Now().UTC()); !errors.Is(err, registry.ErrAuthorizationRevisionConflict) {
		t.Fatalf("replayed restore: %v", err)
	}
}

func TestPluginDataUpgradeMaintenancePaginationAndRetention(t *testing.T) {
	for _, disposition := range []string{"delete_uninstall", "delete_retained", "expire_retained"} {
		t.Run(disposition, func(t *testing.T) {
			ctx := pluginDataCatalogContext("env-history", "user")
			store := openPluginDataCatalogStore(t)
			defer store.Close()
			current := putPluginDataCatalogRecord(t, store, ctx, "history")
			for _, version := range []string{"2.0.0", "3.0.0"} {
				previous, _, err := store.GetBinding(ctx, current.PluginInstanceID)
				if err != nil {
					t.Fatal(err)
				}
				next := previous
				next.GenerationID = "generation-" + version
				next.Revision++
				current, err = store.CommitPluginDataUpgrade(ctx, current, pluginDataUpgradeRecord(t, current, version), previous, next, time.Now().UTC(), false)
				if err != nil {
					t.Fatal(err)
				}
			}
			foreign := pluginDataCatalogContext("env-other", "user")
			putPluginDataCatalogRecord(t, store, foreign, "history")
			seen := map[string]bool{}
			cursor := ""
			for {
				page, next, err := store.ListAllBindingsForMaintenance(ctx, cursor, 1)
				if err != nil {
					t.Fatal(err)
				}
				for _, item := range page {
					key := item.Scope.OwnerEnvHash + "/" + item.Binding.GenerationID
					if seen[key] {
						t.Fatalf("duplicate page entry %s", key)
					}
					seen[key] = true
				}
				if next == "" {
					break
				}
				if next == cursor {
					t.Fatal("cursor did not advance")
				}
				cursor = next
			}
			if len(seen) != 4 {
				t.Fatalf("references = %d, want 4", len(seen))
			}
			bindings, _, err := store.ListBindings(ctx, "", 10)
			if err != nil || len(bindings) != 1 {
				t.Fatalf("history exposed as installed binding: %v %v", bindings, err)
			}
			now := time.Now().UTC()
			expires := now.Add(time.Hour)
			_, err = store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision, DeleteData: disposition == "delete_uninstall", RetainUntil: &expires, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if disposition != "delete_uninstall" {
				references, _, err := store.ListAllBindingsForMaintenance(ctx, "", 10)
				if err != nil || len(references) != 4 {
					t.Fatalf("retained upgrade generations lost: %d %v", len(references), err)
				}
				retained, _, err := store.GetBinding(ctx, current.PluginInstanceID)
				if err != nil {
					t.Fatal(err)
				}
				if disposition == "delete_retained" {
					err = store.DeleteRetained(ctx, retained)
				} else {
					_, err = store.CleanupExpired(ctx, expires, []plugindata.Binding{retained})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			references, _, err := store.ListAllBindingsForMaintenance(ctx, "", 10)
			if err != nil || len(references) != 1 || references[0].Scope.OwnerEnvHash != "env-other" {
				t.Fatalf("deleted history still retained or foreign binding changed: %#v %v", references, err)
			}
		})
	}
}

func TestPluginDataUpgradeImportRebindsOnlySharedActiveHistory(t *testing.T) {
	ctx := pluginDataCatalogContext("env-import-history", "user")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	first := putPluginDataCatalogRecord(t, store, ctx, "import-history")
	original, _, err := store.GetBinding(ctx, first.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	before := original
	before.GenerationID = "converted-generation"
	before.Revision++
	second, err := store.CommitPluginDataUpgrade(ctx, first, pluginDataUpgradeRecord(t, first, "2.0.0"), original, before, time.Now().UTC(), false)
	if err != nil {
		t.Fatal(err)
	}
	third, err := store.Registry().PutPlugin(ctx, first.OwnerEnvHash, pluginDataUpgradeRecord(t, second, "3.0.0"), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	third, err = store.Registry().SetEnableState(ctx, first.OwnerEnvHash, first.PluginInstanceID, registry.EnableDisabledByUser, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	next := before
	next.GenerationID = "imported-generation"
	next.Revision++
	shape, err := plugindata.ShapeFromManifest(third.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SwapImport(ctx, third.ManagementRevision, &before, next, shape, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	actual, err := store.Registry().GetPlugin(ctx, first.OwnerEnvHash, first.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(actual.VersionHistory) != 2 {
		t.Fatalf("lost version history: %+v", actual.VersionHistory)
	}
	for _, snapshot := range actual.VersionHistory {
		want := original.GenerationID
		if snapshot.PackageHash == second.PackageHash {
			want = next.GenerationID
		}
		if snapshot.DataGenerationID != want {
			t.Fatalf("version %s generation %s want %s", snapshot.Version, snapshot.DataGenerationID, want)
		}
	}
	history, err := store.GetPluginDataHistory(ctx, first.PluginInstanceID, original.GenerationID)
	if err != nil || !plugindata.SameBinding(history.Binding, original) {
		t.Fatalf("independent retained data changed: %+v %v", history, err)
	}
}

func TestPluginDataUpgradeExternalAuthorizationTransaction(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			ctx := pluginDataCatalogContext("env-external-upgrade", "user")
			store := openPluginDataCatalogStore(t)
			defer store.Close()
			old := putPluginDataCatalogRecord(t, store, ctx, "external-upgrade")
			old, err := store.Registry().SetEnableState(ctx, old.OwnerEnvHash, old.PluginInstanceID, registry.EnableDisabledByUser, "", time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec("INSERT INTO permission_grants VALUES(?,?,?,?,?)", old.OwnerEnvHash, old.PluginInstanceID, "existing", "{}", 1); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec("INSERT INTO security_policies VALUES(?,?,?,?,?)", old.OwnerEnvHash, old.PluginInstanceID, "{}", 1, time.Now().UnixNano()); err != nil {
				t.Fatal(err)
			}
			before, _, err := store.GetBinding(ctx, old.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			next := pluginDataUpgradeRecord(t, old, "2.0.0")
			next.EnableState = registry.EnableEnabled
			active := before
			active.GenerationID = "external-upgraded"
			active.Revision++
			if fail {
				if _, err := store.db.Exec("CREATE TRIGGER reject_policy_clear BEFORE DELETE ON security_policies BEGIN SELECT RAISE(ABORT, 'injected policy clear failure'); END"); err != nil {
					t.Fatal(err)
				}
			}
			result, err := store.CommitPluginDataUpgrade(ctx, old, next, before, active, time.Now().UTC(), true)
			if fail && (err == nil || !strings.Contains(err.Error(), "injected policy clear failure")) {
				t.Fatalf("wrong rollback: %v", err)
			}
			if !fail && (err != nil || result.EnableState != registry.EnableEnabled) {
				t.Fatalf("external update did not enable: %s %v", result.EnableState, err)
			}
			for _, table := range []string{"permission_grants", "security_policies"} {
				var count int
				if err := store.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil {
					t.Fatal(err)
				}
				want := 0
				if fail {
					want = 1
				}
				if count != want {
					t.Fatalf("%s count %d want %d", table, count, want)
				}
			}
			binding, _, err := store.GetBinding(ctx, old.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			want := active
			if fail {
				want = before
			}
			if !plugindata.SameBinding(binding, want) {
				t.Fatal("authorization cleanup and binding were not atomic")
			}
		})
	}
}
