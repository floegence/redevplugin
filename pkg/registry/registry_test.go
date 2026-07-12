package registry

import (
	"context"
	"database/sql"
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

func TestStoreSourceSecurityFloorRejectsRollback(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
			initial := SourceSecurityFloor{
				SourceID:                 "official",
				PolicyEpoch:              "10",
				KeyRotationEpoch:         "20",
				RevocationEpoch:          "30",
				SourcePolicySnapshotHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				RevocationMetadataSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			}
			stored, err := store.PutSourceSecurityFloor(context.Background(), initial, PutOptions{Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if !stored.UpdatedAt.Equal(now) {
				t.Fatalf("stored updated_at = %s, want %s", stored.UpdatedAt, now)
			}
			got, err := store.GetSourceSecurityFloor(context.Background(), initial.SourceID)
			if err != nil {
				t.Fatal(err)
			}
			if got.PolicyEpoch != "10" || got.KeyRotationEpoch != "20" || got.RevocationEpoch != "30" {
				t.Fatalf("source floor mismatch: %#v", got)
			}

			higher := initial
			higher.PolicyEpoch = "11"
			higher.KeyRotationEpoch = "21"
			higher.RevocationEpoch = "31"
			if _, err := store.PutSourceSecurityFloor(context.Background(), higher, PutOptions{Now: now.Add(time.Second)}); err != nil {
				t.Fatalf("PutSourceSecurityFloor(higher) error = %v", err)
			}

			for _, tc := range []struct {
				name   string
				mutate func(SourceSecurityFloor) SourceSecurityFloor
			}{
				{name: "policy", mutate: func(floor SourceSecurityFloor) SourceSecurityFloor {
					floor.PolicyEpoch = "10"
					return floor
				}},
				{name: "key rotation", mutate: func(floor SourceSecurityFloor) SourceSecurityFloor {
					floor.KeyRotationEpoch = "20"
					return floor
				}},
				{name: "revocation", mutate: func(floor SourceSecurityFloor) SourceSecurityFloor {
					floor.RevocationEpoch = "30"
					return floor
				}},
				{name: "revocation metadata", mutate: func(floor SourceSecurityFloor) SourceSecurityFloor {
					floor.RevocationMetadataSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
					return floor
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := store.PutSourceSecurityFloor(context.Background(), tc.mutate(higher), PutOptions{Now: now.Add(2 * time.Second)}); !errors.Is(err, ErrSourceSecurityFloorRollback) {
						t.Fatalf("PutSourceSecurityFloor rollback error = %v, want %v", err, ErrSourceSecurityFloorRollback)
					}
				})
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
		TrustAssessment: TrustAssessment{
			TrustState:  TrustVerified,
			ReasonCodes: []string{"sqlite_round_trip"},
			VerifiedHashes: TrustHashSet{
				PackageSHA256:  "sha256:pkg",
				ManifestSHA256: "sha256:manifest",
				EntriesSHA256:  "sha256:entries",
			},
			VerifiedSignature:    &VerifiedSignature{Algorithm: "ed25519", KeyID: "official"},
			TrustAssessmentEpoch: "trust_epoch_1",
			PolicyEpoch:          "1",
			RevocationEpoch:      "1",
			Metadata:             map[string]string{"trust.key_id": "official"},
		},
		LocalImportProvenance: &LocalImportProvenance{
			ImportID:       "local_import",
			Distribution:   "local_import",
			PolicyEpoch:    "local_import",
			UnsignedPolicy: "dev_only",
			AssessedAt:     "2026-06-29T00:00:00Z",
		},
		EnableState: EnableEnabled,
		Manifest:    manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.persist", Version: "1.0.0"}},
		Metadata:    map[string]string{"source": "sqlite-test"},
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
		got.TrustAssessment.TrustState != TrustVerified ||
		got.TrustAssessment.ReasonCodes[0] != "sqlite_round_trip" ||
		got.TrustAssessment.VerifiedSignature == nil ||
		got.TrustAssessment.VerifiedSignature.KeyID != "official" ||
		got.TrustAssessment.PolicyEpoch != "1" ||
		got.TrustAssessment.RevocationEpoch != "1" ||
		got.TrustAssessment.Metadata["trust.key_id"] != "official" ||
		got.LocalImportProvenance == nil ||
		got.LocalImportProvenance.UnsignedPolicy != "dev_only" ||
		!got.InstalledAt.Equal(now) {
		t.Fatalf("persisted record mismatch: %#v", got)
	}
	listed, err := reopened.ListPlugins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].TrustAssessment.VerifiedSignature == nil || listed[0].TrustAssessment.VerifiedSignature.KeyID != "official" {
		t.Fatalf("ListPlugins() trust assessment mismatch: %#v", listed)
	}
}

func TestSQLiteStoreMigratesV1TrustAssessmentAndUpdatesUserVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `
CREATE TABLE plugin_registry_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
);
CREATE TABLE plugin_records (
	plugin_instance_id TEXT PRIMARY KEY,
	publisher_id TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	version TEXT NOT NULL,
	active_fingerprint TEXT NOT NULL,
	package_hash TEXT NOT NULL,
	manifest_hash TEXT NOT NULL,
	entries_hash TEXT NOT NULL,
	trust_state TEXT NOT NULL,
	enable_state TEXT NOT NULL,
	disabled_reason TEXT NOT NULL,
	retained_data_state TEXT NOT NULL,
	policy_revision INTEGER NOT NULL,
	management_revision INTEGER NOT NULL,
	revoke_epoch INTEGER NOT NULL,
	manifest_json TEXT NOT NULL,
	package_entries_json TEXT NOT NULL,
	version_history_json TEXT NOT NULL,
	installed_at INTEGER NOT NULL,
	enabled_at INTEGER,
	updated_at INTEGER NOT NULL,
	deleted_at INTEGER,
	metadata_json TEXT NOT NULL
);
PRAGMA user_version = 1;
INSERT INTO plugin_registry_schema_migrations(version, applied_at) VALUES(1, 1);
`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var userVersion int
	if err := store.db.QueryRowContext(context.Background(), `PRAGMA user_version`).Scan(&userVersion); err != nil {
		t.Fatal(err)
	}
	if userVersion != sqliteSchemaVersion {
		t.Fatalf("user_version = %d, want %d", userVersion, sqliteSchemaVersion)
	}
	if _, err := store.PutPlugin(context.Background(), PluginRecord{
		PluginInstanceID:  "plugini_migrated",
		PublisherID:       "example",
		PluginID:          "com.example.migrated",
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:migrated",
		PackageHash:       "sha256:pkg",
		ManifestHash:      "sha256:manifest",
		EntriesHash:       "sha256:entries",
		TrustState:        TrustVerified,
		EnableState:       EnableDisabled,
		Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.migrated", Version: "1.0.0"}},
	}, PutOptions{}); err != nil {
		t.Fatalf("PutPlugin() after v1 migration error = %v", err)
	}
	if _, err := store.PutSourceSecurityFloor(context.Background(), SourceSecurityFloor{
		SourceID:                 "official",
		PolicyEpoch:              "1",
		KeyRotationEpoch:         "1",
		RevocationEpoch:          "1",
		SourcePolicySnapshotHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RevocationMetadataSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}, PutOptions{}); err != nil {
		t.Fatalf("PutSourceSecurityFloor() after v1 migration error = %v", err)
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
	for _, state := range []TrustState{TrustVerified, TrustUnsignedLocal} {
		if !RunnableTrustState(state) {
			t.Fatalf("%s should be runnable", state)
		}
	}
	for _, state := range []TrustState{TrustUntrusted, TrustNeedsReview, TrustUnavailable, TrustBlockedSecurity} {
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
