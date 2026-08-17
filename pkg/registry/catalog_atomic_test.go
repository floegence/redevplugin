package registry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestCatalogImportMutationIsAtomic(t *testing.T) {
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
			seedCatalogBinding(t, store, ctx, binding)
			next := binding
			next.GenerationID = "gen_import"
			next.Revision++
			if err := store.SwapImport(ctx, record.ManagementRevision+1, &binding, next, shape, now.Add(time.Second)); !errors.Is(err, ErrManagementRevisionConflict) {
				t.Fatalf("stale SwapImport() error = %v", err)
			}
			actual, _, _ := store.GetBinding(ctx, record.PluginInstanceID)
			if actual.GenerationID != binding.GenerationID || actual.Revision != binding.Revision {
				t.Fatalf("binding changed after stale import: %#v", actual)
			}
			if err := store.SwapImport(ctx, record.ManagementRevision, &binding, next, shape, now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			stored, err := store.GetPlugin(ctx, record.PluginInstanceID)
			if err != nil || stored.EnableState != EnableDisabledByUser || stored.ManagementRevision != record.ManagementRevision+1 || stored.RevokeEpoch != record.RevokeEpoch+1 {
				t.Fatalf("stored = %#v, err = %v", stored, err)
			}
			actual, _, _ = store.GetBinding(ctx, record.PluginInstanceID)
			if actual.GenerationID != next.GenerationID || actual.Revision != next.Revision {
				t.Fatalf("binding after import = %#v", actual)
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
			const objectPluginInstanceID = "plugini_page_objects"
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
				seedCatalogBinding(t, store, ctx, plugindata.Binding{PluginInstanceID: instanceID, GenerationID: fmt.Sprintf("gen_page_%02d", i), State: plugindata.BindingActive, Revision: 1, ShapeHash: shapeHash})
				objectID := fmt.Sprintf("obj_page_%02d", i)
				if err := store.CreateObject(ctx, sessionctx.ScopeUser, plugindata.Object{PluginInstanceID: objectPluginInstanceID, ObjectID: objectID, ContentHash: strings.Repeat("a", 64), ShapeHash: strings.Repeat("b", 64), SizeBytes: 1, CreatedAt: time.Now()}); err != nil {
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
				page, next, err := store.ListObjects(ctx, sessionctx.ScopeUser, objectPluginInstanceID, objectCursor, 7)
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

func seedCatalogBinding(t testing.TB, store Store, ctx context.Context, binding plugindata.Binding) {
	t.Helper()
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDataBinding(binding); err != nil {
		t.Fatal(err)
	}
	switch concrete := store.(type) {
	case *MemoryStore:
		concrete.mu.Lock()
		defer concrete.mu.Unlock()
		key := environmentRecordKey(ownerEnvHash, binding.PluginInstanceID)
		if _, exists := concrete.dataBindings[key]; exists {
			t.Fatalf("binding %q already exists", binding.PluginInstanceID)
		}
		concrete.dataBindings[key] = cloneDataBinding(binding)
	default:
		t.Fatalf("unsupported catalog type %T", store)
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
		PackageSourceProvenance: PackageSourceProvenance{
			Kind: PackageSourceLocalGenerated,
		},
		EnableState: EnableDisabledByUser,
		Manifest: manifest.Manifest{SchemaVersion: manifest.SchemaVersionV9,
			Publisher: manifest.Publisher{PublisherID: "example"},
			Plugin:    manifest.Plugin{PluginID: "com.example.atomic", DisplayName: "Atomic", Version: "1.0.0"},
			API:       manifest.PublicAPIRequirement{Major: manifest.PluginAPIMajor},
			Presentation: manifest.PresentationSpec{DefaultLocale: "en-US", Summary: "Atomic", Description: []string{"Atomic"},
				Keywords: []string{"atomic"}},
			Surfaces: []manifest.SurfaceSpec{{SurfaceID: "main", Kind: manifest.SurfaceView, Label: "Atomic", Entry: "ui/index.html"}},
			Settings: &manifest.SettingsSpec{SchemaVersion: 1, Fields: []manifest.SettingFieldSpec{{Key: "theme", Type: "string", Scope: "user", Label: "Theme"}}},
			Storage:  &manifest.StorageSpec{Stores: []manifest.StoreSpec{{StoreID: "files", Kind: "files", Scope: "user", QuotaBytes: 1024, QuotaFiles: &quotaFiles, SchemaVersion: 1}}},
		},
	}, PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return record
}
