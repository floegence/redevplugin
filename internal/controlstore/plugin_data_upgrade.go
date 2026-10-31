package controlstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

// PluginDataHistory binds a retained generation to its exact former package.
// It is not an installed instance and cannot authorize plugin execution.
type PluginDataHistory struct {
	Record     registry.PluginRecord
	Binding    plugindata.Binding
	RetainedAt time.Time
}

func deletePluginDataHistory(ctx context.Context, tx *sql.Tx, owner, instanceID string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_history WHERE owner_env_hash=? AND plugin_instance_id=?`, owner, instanceID)
	return err
}

type dataHistoryMigrator interface {
	schemaReader
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func migratePluginDataHistory(ctx context.Context, q dataHistoryMigrator) error {
	updates, err := legacyVersionDataBindings(ctx, q)
	if err != nil {
		return err
	}
	if _, err := q.ExecContext(ctx, `CREATE TABLE plugin_data_history (owner_env_hash TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, generation_id TEXT NOT NULL, record_json TEXT NOT NULL, binding_json TEXT NOT NULL, retained_at INTEGER NOT NULL, PRIMARY KEY(owner_env_hash,plugin_instance_id,generation_id), FOREIGN KEY(owner_env_hash,plugin_instance_id) REFERENCES plugin_records(owner_env_hash,plugin_instance_id) ON DELETE CASCADE)`); err != nil {
		return err
	}
	for _, update := range updates {
		if _, err := q.ExecContext(ctx, "UPDATE plugin_records SET record_json=? WHERE owner_env_hash=? AND plugin_instance_id=?", update.raw, update.owner, update.instance); err != nil {
			return err
		}
	}
	_, err = q.ExecContext(ctx, "UPDATE control_schema SET version=4 WHERE id=1 AND version=3")
	return err
}

type legacyVersionDataUpdate struct{ owner, instance, raw string }

// Released pre-v4 versions could only switch packages without changing shape.
// Bind that proven shared history once, inside the schema migration transaction.
func legacyVersionDataBindings(ctx context.Context, q schemaReader) ([]legacyVersionDataUpdate, error) {
	rows, err := q.QueryContext(ctx, "SELECT p.owner_env_hash,p.plugin_instance_id,p.record_json,b.generation_id,b.shape_hash FROM plugin_records p LEFT JOIN plugin_data_bindings b ON b.owner_env_hash=p.owner_env_hash AND b.plugin_instance_id=p.plugin_instance_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var updates []legacyVersionDataUpdate
	for rows.Next() {
		var owner, instance, raw string
		var generation, shapeHash sql.NullString
		if err := rows.Scan(&owner, &instance, &raw, &generation, &shapeHash); err != nil {
			return nil, err
		}
		record, err := decodeRegistryPluginRecord([]byte(raw))
		if err != nil {
			return nil, err
		}
		if len(record.VersionHistory) == 0 {
			continue
		}
		if record.PluginInstanceID != instance || validatePluginDataPackageIdentity(record) != nil {
			return nil, ErrIncompatible
		}
		currentShape, err := plugindata.ShapeFromManifest(record.Manifest)
		if err != nil {
			return nil, err
		}
		currentHash, err := plugindata.HashShape(currentShape)
		if err != nil {
			return nil, err
		}
		if generation.Valid && (generation.String == "" || !shapeHash.Valid || shapeHash.String != currentHash) {
			return nil, ErrIncompatible
		}
		for index, snapshot := range record.VersionHistory {
			prior := record
			prior.Version, prior.Manifest, prior.CanonicalManifest = snapshot.Version, snapshot.Manifest, snapshot.CanonicalManifest
			prior.ManifestHash = snapshot.ManifestHash
			shape, err := plugindata.ShapeFromManifest(snapshot.Manifest)
			if err != nil {
				return nil, err
			}
			hash, err := plugindata.HashShape(shape)
			if err != nil {
				return nil, err
			}
			if snapshot.DataGenerationID != "" || hash != currentHash || validatePluginDataPackageIdentity(prior) != nil {
				return nil, ErrIncompatible
			}
			if generation.Valid {
				record.VersionHistory[index].DataGenerationID = generation.String
			}
		}
		if !generation.Valid {
			continue
		}
		encoded, err := encodeRegistryPluginRecord(record)
		if err != nil {
			return nil, err
		}
		updates = append(updates, legacyVersionDataUpdate{owner: owner, instance: instance, raw: string(encoded)})
	}
	return updates, rows.Err()
}

// CommitPluginDataUpgrade moves package identity and the active binding at one
// commit point. Before it commits, both readers and restart see the old package.
func (s *Store) CommitPluginDataUpgrade(ctx context.Context, expected, next registry.PluginRecord, previous, active plugindata.Binding, now time.Time, external bool) (registry.PluginRecord, error) {
	return s.commitPluginDataVersion(ctx, expected, next, previous, active, nil, now, external)
}

// CommitPluginDataRestore exchanges a verified historical generation with the
// current generation in the same package/data transaction used by upgrades.
func (s *Store) CommitPluginDataRestore(ctx context.Context, expected, next registry.PluginRecord, previous, active, retained plugindata.Binding, now time.Time) (registry.PluginRecord, error) {
	return s.commitPluginDataVersion(ctx, expected, next, previous, active, &retained, now, false)
}

func (s *Store) commitPluginDataVersion(ctx context.Context, expected, next registry.PluginRecord, previous, active plugindata.Binding, retained *plugindata.Binding, now time.Time, external bool) (registry.PluginRecord, error) {
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if now.IsZero() || expected.OwnerEnvHash != owner || next.OwnerEnvHash != owner ||
		expected.PluginInstanceID != next.PluginInstanceID || previous.PluginInstanceID != next.PluginInstanceID || active.PluginInstanceID != next.PluginInstanceID ||
		expected.PublisherID != next.PublisherID || expected.PluginID != next.PluginID || expected.Version == next.Version ||
		previous.State != plugindata.BindingActive || active.State != plugindata.BindingActive || previous.GenerationID == active.GenerationID ||
		previous.Revision >= math.MaxInt64 || active.Revision != previous.Revision+1 || expected.DeletedAt != nil || next.DeletedAt != nil ||
		expected.ManagementRevision >= math.MaxInt64 || expected.RevokeEpoch >= math.MaxInt64 {
		return registry.PluginRecord{}, plugindata.ErrInvalidArgument
	}
	if err := validatePluginDataPackageIdentity(next); err != nil {
		return registry.PluginRecord{}, err
	}
	for _, binding := range []plugindata.Binding{previous, active} {
		if err := validateControlDataBinding(binding); err != nil {
			return registry.PluginRecord{}, err
		}
	}
	shape, err := plugindata.ShapeFromManifest(next.Manifest)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := validateControlRecordDataShape(next, active, shape); err != nil {
		return registry.PluginRecord{}, err
	}
	var stored registry.PluginRecord
	readyToCommit := false
	err = s.pluginDataMutation(ctx, func(tx *sql.Tx) error {
		current, err := getControlPluginRecord(ctx, tx, owner, expected.PluginInstanceID)
		if err != nil {
			return err
		}
		if current.ActiveFingerprint != expected.ActiveFingerprint || registry.AuthorizationRevisionsFromRecord(current) != registry.AuthorizationRevisionsFromRecord(expected) || current.EnableState != expected.EnableState {
			return registry.ErrAuthorizationRevisionConflict
		}
		if err := validatePluginDataPackageIdentity(current); err != nil {
			return err
		}
		binding, found, err := getControlDataBinding(ctx, tx, owner, current.PluginInstanceID)
		if err != nil {
			return err
		}
		if !found || !plugindata.SameBinding(binding, previous) {
			return plugindata.ErrBindingRevisionConflict
		}
		oldShape, err := plugindata.ShapeFromManifest(current.Manifest)
		if err != nil {
			return err
		}
		if err := validateControlRecordDataShape(current, previous, oldShape); err != nil {
			return err
		}
		if retained != nil {
			var recordRaw, bindingRaw string
			var retainedAt int64
			err := tx.QueryRowContext(ctx, `SELECT record_json,binding_json,retained_at FROM plugin_data_history WHERE owner_env_hash=? AND plugin_instance_id=? AND generation_id=?`, owner, current.PluginInstanceID, retained.GenerationID).Scan(&recordRaw, &bindingRaw, &retainedAt)
			if errors.Is(err, sql.ErrNoRows) {
				return plugindata.ErrBindingConflict
			}
			if err != nil {
				return err
			}
			history, err := decodePluginDataHistory(owner, current.PluginInstanceID, retained.GenerationID, recordRaw, bindingRaw, retainedAt)
			if err != nil {
				return err
			}
			if !plugindata.SameBinding(history.Binding, *retained) || active.GenerationID != retained.GenerationID || active.ShapeHash != retained.ShapeHash ||
				!versionUsesGeneration(current, next, retained.GenerationID) {
				return plugindata.ErrBindingConflict
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_history WHERE owner_env_hash=? AND plugin_instance_id=? AND generation_id=?`, owner, current.PluginInstanceID, retained.GenerationID); err != nil {
				return err
			}
		} else {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM plugin_data_history WHERE owner_env_hash=? AND generation_id=?`, owner, active.GenerationID).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				return plugindata.ErrBindingConflict
			}
		}
		if !external {
			next.EnableState, next.DisabledReason = current.EnableState, current.DisabledReason
		}
		stored, err = registry.PreparePluginPut(owner, next, &current, now)
		if err != nil {
			return err
		}
		bindPreviousPackageData(&stored, current.PackageHash, previous.GenerationID)
		// Version history belongs to the installed record. A retained generation
		// needs only the exact package that last used it, not a nested copy of
		// every prior package snapshot.
		historical := current
		historical.VersionHistory = nil
		recordRaw, err := encodeRegistryPluginRecord(historical)
		if err != nil {
			return err
		}
		bindingRaw, err := json.Marshal(previous)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_data_history(owner_env_hash,plugin_instance_id,generation_id,record_json,binding_json,retained_at) VALUES(?,?,?,?,?,?)`, owner, current.PluginInstanceID, previous.GenerationID, string(recordRaw), string(bindingRaw), now.UnixNano()); err != nil {
			return err
		}
		if err := updateExactControlDataBinding(ctx, tx, owner, previous, active); err != nil {
			return err
		}
		if err := persistControlPluginRecord(ctx, tx, stored); err != nil {
			return err
		}
		if external {
			for _, table := range []string{"permission_grants", "security_policies"} {
				if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE owner_env_hash=? AND plugin_instance_id=?", owner, current.PluginInstanceID); err != nil {
					return err
				}
			}
		}
		readyToCommit = true
		return nil
	})
	if err != nil {
		if readyToCommit {
			err = mutation.Unknown(err)
		}
		return registry.PluginRecord{}, err
	}
	return stored, nil
}

// Only the installed record's version history can bind a package to retained
// data. The last package to use that generation may be a different same-shape
// version, so retained package identity alone cannot select the data.
func versionUsesGeneration(current, target registry.PluginRecord, generationID string) bool {
	for _, snapshot := range current.VersionHistory {
		if snapshot.PackageHash == target.PackageHash && snapshot.ManifestHash == target.ManifestHash && snapshot.ActiveFingerprint == target.ActiveFingerprint && snapshot.DataGenerationID == generationID {
			return true
		}
	}
	return false
}

// Explicit dataset replacement applies to every version sharing that dataset;
// independently retained conversion generations keep their own binding.
func rebindSharedVersionData(record *registry.PluginRecord, previous, next string) {
	for index := range record.VersionHistory {
		if record.VersionHistory[index].DataGenerationID == previous {
			record.VersionHistory[index].DataGenerationID = next
		}
	}
}

func bindPreviousPackageData(record *registry.PluginRecord, packageHash, generationID string) {
	for index := range record.VersionHistory {
		if record.VersionHistory[index].PackageHash == packageHash {
			record.VersionHistory[index].DataGenerationID = generationID
		}
	}
}

func bindVersionSwitchData(ctx context.Context, tx *sql.Tx, owner string, record *registry.PluginRecord, previous registry.PluginRecord) error {
	if record.PackageHash == previous.PackageHash {
		return nil
	}
	binding, found, err := getControlDataBinding(ctx, tx, owner, record.PluginInstanceID)
	if err != nil {
		return err
	}
	if !found {
		return plugindata.ErrBindingNotFound
	}
	bindPreviousPackageData(record, previous.PackageHash, binding.GenerationID)
	return nil
}

func (s *Store) GetPluginDataHistory(ctx context.Context, instanceID, generationID string) (PluginDataHistory, error) {
	if err := s.pluginDataReady(); err != nil {
		return PluginDataHistory{}, err
	}
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return PluginDataHistory{}, err
	}
	var recordRaw, bindingRaw string
	var retainedAt int64
	err = s.db.QueryRowContext(ctx, `SELECT record_json,binding_json,retained_at FROM plugin_data_history WHERE owner_env_hash=? AND plugin_instance_id=? AND generation_id=?`, owner, instanceID, generationID).Scan(&recordRaw, &bindingRaw, &retainedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return PluginDataHistory{}, registry.ErrNotFound
	}
	if err != nil {
		return PluginDataHistory{}, err
	}
	return decodePluginDataHistory(owner, instanceID, generationID, recordRaw, bindingRaw, retainedAt)
}

func decodePluginDataHistory(owner, instanceID, generationID, recordRaw, bindingRaw string, retainedAt int64) (PluginDataHistory, error) {
	record, err := decodeRegistryPluginRecord([]byte(recordRaw))
	if err != nil {
		return PluginDataHistory{}, err
	}
	record.OwnerEnvHash = owner
	if err := validatePluginDataPackageIdentity(record); err != nil {
		return PluginDataHistory{}, fmt.Errorf("%w: retained package identity: %v", ErrIncompatible, err)
	}
	var binding plugindata.Binding
	if err := json.Unmarshal([]byte(bindingRaw), &binding); err != nil {
		return PluginDataHistory{}, ErrIncompatible
	}
	shape, err := plugindata.ShapeFromManifest(record.Manifest)
	if err != nil || validateControlRecordDataShape(record, binding, shape) != nil || validateControlDataBinding(binding) != nil ||
		record.OwnerEnvHash != owner || record.PluginInstanceID != instanceID || binding.PluginInstanceID != instanceID || binding.GenerationID != generationID || retainedAt <= 0 {
		return PluginDataHistory{}, ErrIncompatible
	}
	return PluginDataHistory{Record: record, Binding: binding, RetainedAt: time.Unix(0, retainedAt).UTC()}, nil
}

// Preserve the signed canonical bytes while requiring their normalized meaning
// to match the package record used for the new data shape.
func validatePluginDataPackageIdentity(record registry.PluginRecord) error {
	decoded, canonical, err := decodeExactCanonicalManifest(json.RawMessage(record.CanonicalManifest))
	if err != nil {
		return fmt.Errorf("%w: canonical package manifest: %v", plugindata.ErrInvalidArgument, err)
	}
	sum := sha256.Sum256([]byte(canonical))
	if record.ManifestHash != "sha256:"+hex.EncodeToString(sum[:]) || record.Version != decoded.Plugin.Version ||
		record.PluginID != decoded.PluginID() || record.PublisherID != decoded.Publisher.PublisherID {
		return fmt.Errorf("%w: package identity differs from its canonical manifest", plugindata.ErrInvalidArgument)
	}
	// Presentation hydration is derived from package-local locale assets, not a
	// second signed manifest source. Compare the remaining normalized data exactly.
	actualManifest := record.Manifest
	actualManifest.Presentation = decoded.Presentation
	actualManifest.Presentation.DefaultLocale = record.Manifest.Presentation.DefaultLocale
	actualManifest.Presentation.Icon = record.Manifest.Presentation.Icon
	expected, err := json.Marshal(decoded)
	if err != nil {
		return err
	}
	actual, err := json.Marshal(actualManifest)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("%w: package manifest differs from signed content", plugindata.ErrInvalidArgument)
	}
	return nil
}
