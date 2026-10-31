package controlstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

// Released pre-Web packages omitted web on every surface. Their signed bytes
// remain data identity after executable admission moves to ordinary Web apps.
func storedPreWebManifest(t *testing.T, record registry.PluginRecord) registry.PluginRecord {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(record.CanonicalManifest), &document); err != nil {
		t.Fatal(err)
	}
	for _, value := range document["surfaces"].([]any) {
		delete(value.(map[string]any), "web")
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := manifest.CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	record.CanonicalManifest = string(canonical)
	sum := sha256.Sum256(canonical)
	record.ManifestHash = "sha256:" + hex.EncodeToString(sum[:])
	record.SignatureAssessment.ManifestSHA256 = record.ManifestHash
	record.SignatureAssessment.AssessedHashes.ManifestSHA256 = record.ManifestHash
	record.TrustAssessment.VerifiedHashes.ManifestSHA256 = record.ManifestHash
	return record
}

func TestPersistedPreWebMigrationRejectsTamperingWithoutMutation(t *testing.T) {
	for _, damage := range []string{"unknown", "partial_web", "hash", "shape"} {
		t.Run(damage, func(t *testing.T) {
			db, path := pluginDataHistoricalDatabase(t, 3)
			ctx := pluginDataCatalogContext("env-retained", "user")
			record := putPluginDataCatalogRecord(t, &Store{db: db, ready: true, generation: 1}, ctx, "retained")
			next := pluginDataUpgradeRecord(t, record, "2.0.0")
			next.VersionHistory[0].DataGenerationID = ""
			old := storedPreWebManifest(t, record)
			next.VersionHistory[0].ManifestHash = old.ManifestHash
			switch damage {
			case "hash":
				next.VersionHistory[0].ManifestHash = "sha256:incorrect"
			case "shape":
				if _, err := db.Exec("UPDATE plugin_data_bindings SET shape_hash='changed'"); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				old.CanonicalManifest = string(bytes.Replace([]byte(old.CanonicalManifest), []byte(`"entry":"ui/index.html"`), []byte(`"entry":"ui/index.html","unknown":true`), 1))
			case "partial_web":
				old.CanonicalManifest = string(bytes.Replace([]byte(old.CanonicalManifest), []byte(`"entry":"ui/index.html"`), []byte(`"entry":"ui/index.html","web":{}`), 1))
			}
			raw, err := json.Marshal(durableRegistryPluginRecord{PluginRecord: next, Manifest: json.RawMessage(next.CanonicalManifest), VersionHistory: []durablePluginVersion{{PluginVersion: next.VersionHistory[0], Manifest: json.RawMessage(old.CanonicalManifest)}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec("UPDATE plugin_records SET record_json=?", string(raw)); err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if store, err := Open(ctx, Config{Path: path}); err == nil {
				store.Close()
				t.Fatal("corrupt retained state accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("rejected state mutated")
			}
		})
	}
}

func TestPersistedPreWebMigrationRollsBackAndResumes(t *testing.T) {
	db, path := pluginDataHistoricalDatabase(t, 3)
	ctx := pluginDataCatalogContext("env-retained", "user")
	record := putPluginDataCatalogRecord(t, &Store{db: db, ready: true, generation: 1}, ctx, "retained")
	next := pluginDataUpgradeRecord(t, record, "2.0.0")
	next.VersionHistory[0].DataGenerationID = ""
	old := storedPreWebManifest(t, record)
	next.VersionHistory[0].ManifestHash = old.ManifestHash
	raw, err := json.Marshal(durableRegistryPluginRecord{PluginRecord: next, Manifest: json.RawMessage(next.CanonicalManifest), VersionHistory: []durablePluginVersion{{PluginVersion: next.VersionHistory[0], Manifest: json.RawMessage(old.CanonicalManifest)}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE plugin_records SET record_json=?", string(raw)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = migratePluginDataHistory(ctx, failingPluginDataHistoryMigration{tx}); err == nil {
		t.Fatal("interruption not reached")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var persisted string
	if err = db.QueryRow("SELECT record_json FROM plugin_records").Scan(&persisted); err != nil || persisted != string(raw) {
		t.Fatal("rollback changed historical bytes")
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
}

func TestPersistedPreWebManifestMigration(t *testing.T) {
	for _, version := range []int{1, 2, 3, 4, 5} {
		for _, legacyCurrent := range []bool{false, true} {
			t.Run(fmt.Sprintf("schema_%d/current_%t", version, legacyCurrent), func(t *testing.T) {
				db, path := pluginDataHistoricalDatabase(t, min(version, 4))
				if version == 5 {
					if err := migrateBackgroundIntervals(pluginDataCatalogContext("env-retained", "user"), db); err != nil {
						t.Fatal(err)
					}
				}
				ctx := pluginDataCatalogContext("env-retained", "user")
				prior := &Store{db: db, ready: true, generation: 1}
				record := putPluginDataCatalogRecord(t, prior, ctx, "retained-instance")
				next := pluginDataUpgradeRecord(t, record, "2.0.0")
				next.VersionHistory[0].DataGenerationID = ""
				if version >= 4 {
					next.VersionHistory[0].DataGenerationID = "gen_retained-instance"
				}
				if legacyCurrent {
					next = storedPreWebManifest(t, next)
				}
				old := storedPreWebManifest(t, record)
				next.VersionHistory[0].ManifestHash = old.ManifestHash
				next.VersionHistory[0].SignatureAssessment = old.SignatureAssessment
				next.VersionHistory[0].TrustAssessment = old.TrustAssessment
				// Write the exact historical wire form, without the current encoder.
				raw, err := json.Marshal(durableRegistryPluginRecord{PluginRecord: next, Manifest: json.RawMessage(next.CanonicalManifest), VersionHistory: []durablePluginVersion{{PluginVersion: next.VersionHistory[0], Manifest: json.RawMessage(old.CanonicalManifest)}}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("UPDATE plugin_records SET record_json=? WHERE plugin_instance_id=?", string(raw), record.PluginInstanceID); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					store, err := Open(ctx, Config{Path: path})
					if err != nil {
						t.Fatal(err)
					}
					actual, err := store.Registry().GetPlugin(ctx, record.OwnerEnvHash, record.PluginInstanceID)
					if err != nil {
						t.Fatal(err)
					}
					if actual.CanonicalManifest != next.CanonicalManifest || len(actual.VersionHistory) != 1 || actual.VersionHistory[0].CanonicalManifest != old.CanonicalManifest {
						t.Fatal("signed manifest bytes changed")
					}
					if actual.VersionHistory[0].DataGenerationID != "gen_retained-instance" {
						t.Fatal("historical data generation lost")
					}
					if _, _, err := manifest.DecodeCanonical(bytes.NewBufferString(old.CanonicalManifest)); err == nil {
						t.Fatal("historical surface became executable")
					}
					if registry.RunnablePluginRecord(actual) == legacyCurrent {
						t.Fatal("execution admission differs from the current package")
					}
					if _, err := store.Registry().SetEnableState(ctx, record.OwnerEnvHash, record.PluginInstanceID, registry.EnableDisabledByUser, "", time.Now().UTC()); err != nil {
						t.Fatal(err)
					}
					if err := store.Close(); err != nil {
						t.Fatal(err)
					}
				}
				store, err := Open(ctx, Config{Path: path})
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				actual, err := store.Registry().GetPlugin(ctx, record.OwnerEnvHash, record.PluginInstanceID)
				if err != nil {
					t.Fatal(err)
				}
				replacement := pluginDataUpgradeRecord(t, record, "3.0.0")
				snapshot := replacement.VersionHistory[0]
				snapshot.Version, snapshot.Manifest, snapshot.CanonicalManifest, snapshot.ManifestHash = actual.Version, actual.Manifest, actual.CanonicalManifest, actual.ManifestHash
				snapshot.PackageHash, snapshot.EntriesHash, snapshot.ActiveFingerprint = actual.PackageHash, actual.EntriesHash, actual.ActiveFingerprint
				snapshot.SignatureAssessment, snapshot.TrustAssessment, snapshot.PackageSourceProvenance, snapshot.ExecutionApproval = actual.SignatureAssessment, actual.TrustAssessment, actual.PackageSourceProvenance, actual.ExecutionApproval
				snapshot.DataGenerationID = "gen_retained-instance"
				replacement.VersionHistory = append(actual.VersionHistory, snapshot)
				replacement.EnableState = actual.EnableState
				updated, err := store.Registry().PutPlugin(ctx, record.OwnerEnvHash, replacement, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				if len(updated.VersionHistory) != 2 || updated.VersionHistory[0].CanonicalManifest != old.CanonicalManifest || updated.VersionHistory[1].CanonicalManifest != actual.CanonicalManifest {
					t.Fatal("Web update discarded signed history")
				}
				binding, found, err := store.GetBinding(ctx, record.PluginInstanceID)
				if err != nil || !found || binding.GenerationID != "gen_retained-instance" {
					t.Fatal("Web update lost data binding")
				}
			})
		}
	}
}
