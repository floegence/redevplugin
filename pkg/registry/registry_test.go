package registry

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
)

func TestStoreRevisionsAndList(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
			record := PluginRecord{
				PluginInstanceID:  "plugini_test",
				PublisherID:       "example",
				PluginID:          "com.example.test",
				Version:           "1.0.0",
				ActiveFingerprint: "sha256:test",
				TrustState:        TrustVerified,
				EnableState:       EnableDisabled,
				Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.test", Version: "1.0.0"}},
			}
			stored, err := store.PutPlugin(context.Background(), record, PutOptions{Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if stored.PolicyRevision != 1 || stored.ManagementRevision != 1 || stored.RevokeEpoch != 0 {
				t.Fatalf("initial revisions = %#v", stored)
			}

			enabled, err := store.SetEnableState(context.Background(), stored.PluginInstanceID, EnableEnabled, "", now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if enabled.ManagementRevision != 2 || enabled.RevokeEpoch != 1 || enabled.EnabledAt == nil {
				t.Fatalf("enable revisions = %#v", enabled)
			}

			granted, err := store.BumpPolicyRevision(context.Background(), stored.PluginInstanceID, false, now.Add(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if granted.PolicyRevision != 2 || granted.ManagementRevision != 2 || granted.RevokeEpoch != 1 {
				t.Fatalf("grant policy revisions = %#v", granted)
			}

			revoked, err := store.BumpPolicyRevision(context.Background(), stored.PluginInstanceID, true, now.Add(3*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if revoked.PolicyRevision != 3 || revoked.ManagementRevision != 2 || revoked.RevokeEpoch != 2 {
				t.Fatalf("revoke policy revisions = %#v", revoked)
			}

			uninstalled, err := store.MarkUninstalled(context.Background(), stored.PluginInstanceID, RetainedDataDeleted, now.Add(4*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if uninstalled.ManagementRevision != 3 || uninstalled.PolicyRevision != 3 || uninstalled.RevokeEpoch != 3 || uninstalled.DeletedAt == nil {
				t.Fatalf("uninstall revisions = %#v", uninstalled)
			}
			list, err := store.ListPlugins(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != 0 {
				t.Fatalf("ListPlugins() returned deleted record: %#v", list)
			}
		})
	}
}

func TestStorePreservesVersionHistoryOnOverwrite(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
			record := PluginRecord{
				PluginInstanceID:  "plugini_test",
				PublisherID:       "example",
				PluginID:          "com.example.test",
				Version:           "1.0.0",
				ActiveFingerprint: "sha256:v1",
				PackageHash:       "sha256:v1",
				TrustState:        TrustVerified,
				EnableState:       EnableEnabled,
				Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.test", Version: "1.0.0"}},
				Metadata:          map[string]string{"trust.key_id": "publisher-key"},
			}
			stored, err := store.PutPlugin(context.Background(), record, PutOptions{Now: now})
			if err != nil {
				t.Fatal(err)
			}
			stored.Version = "2.0.0"
			stored.ActiveFingerprint = "sha256:v2"
			stored.PackageHash = "sha256:v2"
			stored.VersionHistory = []PluginVersion{{Version: "1.0.0", PackageHash: "sha256:v1"}}
			updated, err := store.PutPlugin(context.Background(), stored, PutOptions{Now: now.Add(time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			if updated.ManagementRevision != 2 ||
				updated.RevokeEpoch != 1 ||
				len(updated.VersionHistory) != 1 ||
				updated.VersionHistory[0].Version != "1.0.0" ||
				updated.Metadata["trust.key_id"] != "publisher-key" {
				t.Fatalf("updated record mismatch: %#v", updated)
			}
		})
	}
}

func TestStoreDeletePlugin(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			record := PluginRecord{
				PluginInstanceID:  "plugini_delete",
				PublisherID:       "example",
				PluginID:          "com.example.delete",
				Version:           "1.0.0",
				ActiveFingerprint: "sha256:delete",
				TrustState:        TrustVerified,
				EnableState:       EnableDisabled,
				Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.delete", Version: "1.0.0"}},
			}
			if _, err := store.PutPlugin(context.Background(), record, PutOptions{}); err != nil {
				t.Fatal(err)
			}
			if err := store.DeletePlugin(context.Background(), record.PluginInstanceID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.GetPlugin(context.Background(), record.PluginInstanceID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("GetPlugin() after delete error = %v, want %v", err, ErrNotFound)
			}
			if err := store.DeletePlugin(context.Background(), record.PluginInstanceID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("DeletePlugin() after delete error = %v, want %v", err, ErrNotFound)
			}
		})
	}
}

func TestSQLiteStorePersistsRecordsAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
	store, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	record := PluginRecord{
		PluginInstanceID:  "plugini_persist",
		PublisherID:       "example",
		PluginID:          "com.example.persist",
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:persist",
		PackageHash:       "sha256:pkg",
		ManifestHash:      "sha256:manifest",
		EntriesHash:       "sha256:entries",
		TrustState:        TrustVerified,
		EnableState:       EnableEnabled,
		Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.persist", Version: "1.0.0"}},
		Metadata:          map[string]string{"source": "sqlite-test"},
	}
	stored, err := store.PutPlugin(context.Background(), record, PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})
	got, err := reopened.GetPlugin(context.Background(), stored.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PluginID != record.PluginID ||
		got.PackageHash != "sha256:pkg" ||
		got.Manifest.Plugin.PluginID != record.PluginID ||
		got.Metadata["source"] != "sqlite-test" ||
		!got.InstalledAt.Equal(now) {
		t.Fatalf("persisted record mismatch: %#v", got)
	}
}

func TestSQLiteStoreRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `PRAGMA user_version = 999`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(context.Background(), path); err == nil {
		t.Fatal("NewSQLiteStore() accepted newer schema version")
	}
}

func TestRunnableTrustState(t *testing.T) {
	for _, state := range []TrustState{TrustBundled, TrustVerified, TrustUnsignedLocal} {
		if !RunnableTrustState(state) {
			t.Fatalf("%s should be runnable", state)
		}
	}
	for _, state := range []TrustState{TrustUntrusted, TrustNeedsReview, TrustBlockedSecurity} {
		if RunnableTrustState(state) {
			t.Fatalf("%s should not be runnable", state)
		}
	}
}

type registryStoreCase struct {
	name string
	open func(t *testing.T) Store
}

func registryStoreCases() []registryStoreCase {
	return []registryStoreCase{
		{
			name: "memory",
			open: func(t *testing.T) Store {
				t.Helper()
				return NewMemoryStore()
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) Store {
				t.Helper()
				store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "registry.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = store.Close()
				})
				return store
			},
		},
	}
}
