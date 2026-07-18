package registry

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/plugindata"
)

func TestCatalogManagementMutationsAreAtomic(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := registryTestContext()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
			record := putCatalogPlugin(t, store, "plugini_atomic", now)
			shape, err := plugindata.ShapeFromManifest(record.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := plugindata.HashShape(shape)
			if err != nil {
				t.Fatal(err)
			}
			binding := plugindata.Binding{PluginInstanceID: record.PluginInstanceID, GenerationID: "gen_atomic", State: plugindata.BindingActive, Revision: 1, ShapeHash: hash}
			if err := store.CommitEnable(ctx, record.ManagementRevision+1, nil, binding, shape, now.Add(time.Second)); !errors.Is(err, ErrManagementRevisionConflict) {
				t.Fatalf("stale CommitEnable() error = %v", err)
			}
			if _, found, err := store.GetBinding(ctx, record.PluginInstanceID); err != nil || found {
				t.Fatalf("binding found = %v, err = %v", found, err)
			}
			unchanged, err := store.GetPlugin(ctx, record.PluginInstanceID)
			if err != nil || unchanged.EnableState != EnableDisabled || unchanged.ManagementRevision != record.ManagementRevision {
				t.Fatalf("unchanged = %#v, err = %v", unchanged, err)
			}
			if err := store.CommitEnable(ctx, record.ManagementRevision, nil, binding, shape, now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			enabled, _ := store.GetPlugin(ctx, record.PluginInstanceID)
			if enabled.EnableState != EnableEnabled || enabled.ManagementRevision != record.ManagementRevision+1 || enabled.RevokeEpoch != record.RevokeEpoch+1 {
				t.Fatalf("enabled = %#v", enabled)
			}

			next := binding
			next.GenerationID = "gen_import"
			next.Revision++
			if err := store.SwapImport(ctx, enabled.ManagementRevision, &binding, next, shape, now.Add(3*time.Second)); !errors.Is(err, plugindata.ErrBindingConflict) {
				t.Fatalf("enabled SwapImport() error = %v", err)
			}
			actual, _, _ := store.GetBinding(ctx, record.PluginInstanceID)
			if actual.GenerationID != binding.GenerationID || actual.Revision != binding.Revision {
				t.Fatalf("binding changed after rejected import: %#v", actual)
			}
		})
	}
}

func TestCommitUninstallWithoutBinding(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			record := putCatalogPlugin(t, store, "plugini_missing_data", time.Now())
			result, err := store.CommitUninstall(registryTestContext(), plugindata.CommitUninstallRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, Now: time.Now()})
			if err != nil {
				t.Fatalf("CommitUninstall() error = %v", err)
			}
			if result.ManagementRevision != record.ManagementRevision+1 || result.RevokeEpoch != record.RevokeEpoch+1 || result.DeletedAt.IsZero() {
				t.Fatalf("CommitUninstall() result = %#v", result)
			}
			if _, err := store.GetPlugin(registryTestContext(), record.PluginInstanceID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("GetPlugin() error = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestCatalogPagesBindingsAndObjects(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := registryTestContext()
			store := tc.open(t)
			for i := 0; i < 17; i++ {
				instanceID := fmt.Sprintf("plugini_page_%02d", i)
				record := putCatalogPlugin(t, store, instanceID, time.Now())
				shape, err := plugindata.ShapeFromManifest(record.Manifest)
				if err != nil {
					t.Fatal(err)
				}
				shapeHash, err := plugindata.HashShape(shape)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.CommitEnable(ctx, record.ManagementRevision, nil, plugindata.Binding{PluginInstanceID: instanceID, GenerationID: fmt.Sprintf("gen_page_%02d", i), State: plugindata.BindingActive, Revision: 1, ShapeHash: shapeHash}, shape, time.Now()); err != nil {
					t.Fatal(err)
				}
				objectID := fmt.Sprintf("obj_page_%02d", i)
				if err := store.CreateObject(ctx, plugindata.Object{ObjectID: objectID, ContentHash: strings.Repeat("a", 64), ShapeHash: strings.Repeat("b", 64), SizeBytes: 1, CreatedAt: time.Now()}); err != nil {
					t.Fatal(err)
				}
			}
			bindingCount := 0
			objectCount := 0
			bindingCursor := ""
			objectCursor := ""
			for bindingCursor != "done" {
				page, next, err := store.ListBindings(ctx, bindingCursor, 7)
				if err != nil {
					t.Fatal(err)
				}
				bindingCount += len(page)
				if next == "" {
					bindingCursor = "done"
				} else {
					bindingCursor = next
				}
			}
			for objectCursor != "done" {
				page, next, err := store.ListObjects(ctx, objectCursor, 7)
				if err != nil {
					t.Fatal(err)
				}
				objectCount += len(page)
				if next == "" {
					objectCursor = "done"
				} else {
					objectCursor = next
				}
			}
			if bindingCount != 17 || objectCount != 17 {
				t.Fatalf("paged counts: bindings=%d objects=%d", bindingCount, objectCount)
			}
		})
	}
}

func TestSQLiteCommitUninstallReportsUnknownAndKeepsCommittedState(t *testing.T) {
	ctx := registryTestContext()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := putCatalogPlugin(t, store, "plugini_unknown", time.Now())
	shape, _ := plugindata.ShapeFromManifest(record.Manifest)
	hash, _ := plugindata.HashShape(shape)
	binding := plugindata.Binding{PluginInstanceID: record.PluginInstanceID, GenerationID: "gen_unknown", State: plugindata.BindingActive, Revision: 1, ShapeHash: hash}
	if err := store.CommitEnable(ctx, record.ManagementRevision, nil, binding, shape, time.Now()); err != nil {
		t.Fatal(err)
	}
	enabled, _ := store.GetPlugin(ctx, record.PluginInstanceID)
	store.commitTx = func(tx *sql.Tx) error {
		if err := tx.Commit(); err != nil {
			return err
		}
		return errors.New("commit acknowledgement lost")
	}
	_, err = store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: enabled.ManagementRevision, DeleteData: true, Now: time.Now()})
	if outcome := mutation.ForError(err); outcome != mutation.OutcomeUnknown {
		t.Fatalf("outcome = %q, err = %v", outcome, err)
	}
	if _, err := store.GetPlugin(ctx, record.PluginInstanceID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPlugin() error = %v, want committed deletion", err)
	}
	if _, found, err := store.GetBinding(ctx, record.PluginInstanceID); err != nil || found {
		t.Fatalf("binding found = %v, err = %v", found, err)
	}
}

func putCatalogPlugin(t *testing.T, store Store, instanceID string, now time.Time) PluginRecord {
	t.Helper()
	quotaFiles := int64(16)
	record, err := store.PutPlugin(registryTestContext(), PluginRecord{
		PluginInstanceID:  instanceID,
		PublisherID:       "example",
		PluginID:          "com.example.atomic",
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:" + instanceID,
		TrustState:        TrustVerified,
		EnableState:       EnableDisabled,
		Manifest: manifest.Manifest{
			Publisher: manifest.Publisher{PublisherID: "example"},
			Plugin:    manifest.Plugin{PluginID: "com.example.atomic", Version: "1.0.0"},
			Settings:  &manifest.SettingsSpec{SchemaVersion: 1, Fields: []manifest.SettingFieldSpec{{Key: "theme", Type: "string", Scope: "user", Label: "Theme"}}},
			Storage:   &manifest.StorageSpec{Stores: []manifest.StoreSpec{{StoreID: "files", Kind: "files", Scope: "user", QuotaBytes: 1024, QuotaFiles: &quotaFiles, SchemaVersion: 1}}},
		},
	}, PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return record
}
