package controlstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/internal/jsonvalue"
	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/sessionscope"
)

var ErrRecordNotFound = errors.New("control store record not found")
var ErrRevisionConflict = errors.New("control store revision conflict")
var ErrStateConflict = errors.New("control store state conflict")

type RegistryView struct{ store *Store }
type ExecutionView struct{ store *Store }
type ConfirmationView struct{ store *Store }
type SessionView struct{ store *Store }

type ExecutionOwner struct {
	OwnerSessionHash     string
	OwnerUserHash        string
	OwnerEnvHash         string
	SessionChannelIDHash string
}

type ExecutionReconcileResult struct {
	Orphaned int
	Canceled int
	Records  []execution.Execution
}

type ExecutionPruneRequest struct {
	Before                      time.Time
	Limit                       int
	MaxTerminalRecordsPerPlugin int
}

type ExecutionPruneResult struct{ Deleted int }

const releaseInstallPayloadKind = "release_install_v1"

type releaseInstallPayload struct {
	Kind      string                           `json:"kind"`
	Operation registry.ReleaseInstallOperation `json:"operation"`
	Release   registry.ReleaseInstallIdentity  `json:"release"`
}

type durableRegistryPluginRecord struct {
	registry.PluginRecord
	Manifest       json.RawMessage        `json:"manifest"`
	VersionHistory []durablePluginVersion `json:"version_history,omitempty"`
}

type durablePluginVersion struct {
	registry.PluginVersion
	Manifest json.RawMessage `json:"manifest"`
}

func encodeRegistryPluginRecord(record registry.PluginRecord) ([]byte, error) {
	canonical, err := exactCanonicalManifest(record.Manifest, record.CanonicalManifest)
	if err != nil {
		return nil, err
	}
	versions := make([]durablePluginVersion, len(record.VersionHistory))
	for index := range record.VersionHistory {
		versionCanonical, err := exactCanonicalManifest(record.VersionHistory[index].Manifest, record.VersionHistory[index].CanonicalManifest)
		if err != nil {
			return nil, fmt.Errorf("version history %d: %w", index, err)
		}
		versions[index] = durablePluginVersion{PluginVersion: record.VersionHistory[index], Manifest: versionCanonical}
	}
	return json.Marshal(durableRegistryPluginRecord{
		PluginRecord:   record,
		Manifest:       canonical,
		VersionHistory: versions,
	})
}

func decodeRegistryPluginRecord(raw []byte) (registry.PluginRecord, error) {
	var durable durableRegistryPluginRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&durable); err != nil {
		return registry.PluginRecord{}, fmt.Errorf("%w: plugin record JSON: %v", ErrIncompatible, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return registry.PluginRecord{}, fmt.Errorf("%w: plugin record JSON trailing value", ErrIncompatible)
	}
	record := durable.PluginRecord
	current, canonical, err := decodeExactCanonicalManifest(durable.Manifest)
	if err != nil {
		return registry.PluginRecord{}, fmt.Errorf("%w: current manifest: %v", ErrIncompatible, err)
	}
	record.Manifest = current
	record.CanonicalManifest = canonical
	record.VersionHistory = make([]registry.PluginVersion, len(durable.VersionHistory))
	for index, version := range durable.VersionHistory {
		decoded, versionCanonical, err := decodeExactCanonicalManifest(version.Manifest)
		if err != nil {
			return registry.PluginRecord{}, fmt.Errorf("%w: version history %d manifest: %v", ErrIncompatible, index, err)
		}
		record.VersionHistory[index] = version.PluginVersion
		record.VersionHistory[index].Manifest = decoded
		record.VersionHistory[index].CanonicalManifest = versionCanonical
	}
	return record, nil
}

func exactCanonicalManifest(value manifest.Manifest, supplied string) (json.RawMessage, error) {
	if supplied != "" {
		_, canonical, err := decodeExactCanonicalManifest(json.RawMessage(supplied))
		if err != nil {
			return nil, err
		}
		return json.RawMessage(canonical), nil
	}
	canonical, err := manifest.MarshalCanonical(value)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canonical), nil
}

func decodeExactCanonicalManifest(raw json.RawMessage) (manifest.Manifest, string, error) {
	if len(raw) == 0 {
		return manifest.Manifest{}, "", errors.New("canonical manifest is required")
	}
	decoded, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		return manifest.Manifest{}, "", err
	}
	canonical, err := manifest.CanonicalJSON(raw)
	if err != nil {
		return manifest.Manifest{}, "", err
	}
	if !bytes.Equal(raw, canonical) {
		return manifest.Manifest{}, "", errors.New("manifest JSON is not canonical")
	}
	return decoded, string(canonical), nil
}

func encodeReleaseInstallOperation(operation registry.ReleaseInstallOperation) ([]byte, error) {
	return json.Marshal(releaseInstallPayload{
		Kind: releaseInstallPayloadKind, Operation: operation, Release: operation.Release,
	})
}

func (owner ExecutionOwner) Valid() bool {
	return owner.OwnerSessionHash != "" && owner.OwnerUserHash != "" && owner.OwnerEnvHash != "" && owner.SessionChannelIDHash != ""
}

func (s *Store) Registry() RegistryView          { return RegistryView{store: s} }
func (s *Store) Executions() ExecutionView       { return ExecutionView{store: s} }
func (s *Store) Confirmations() ConfirmationView { return ConfirmationView{store: s} }
func (s *Store) Sessions() SessionView           { return SessionView{store: s} }
func (v RegistryView) Generation() uint64        { return v.store.Generation() }
func (v ExecutionView) Generation() uint64       { return v.store.Generation() }
func (v ConfirmationView) Generation() uint64    { return v.store.Generation() }
func (v SessionView) Generation() uint64         { return v.store.Generation() }

type PluginRecord struct {
	OwnerEnvHash       string
	PluginInstanceID   string
	PublisherID        string
	PluginID           string
	Version            string
	ActiveFingerprint  string
	PackageSHA256      string
	ManifestSHA256     string
	EntriesSHA256      string
	State              string
	DisabledReason     string
	PolicyRevision     uint64
	ManagementRevision uint64
	RevokeEpoch        uint64
	InstalledAt        int64
	EnabledAt          *int64
	UpdatedAt          int64
	DeletedAt          *int64
	RawJSON            json.RawMessage
}

type Grant struct {
	CapabilityID string
	Revision     uint64
	RawJSON      json.RawMessage
}

type Policy struct {
	Revision  uint64
	UpdatedAt int64
	RawJSON   json.RawMessage
}

type PluginInstall struct {
	Record PluginRecord
	Grants []Grant
	Policy *Policy
}

type PluginSnapshot struct {
	Record PluginRecord
	Grants []Grant
	Policy *Policy
}

// UpdateExternalPackage commits an update to an existing active record and
// clears its grants and policy in the same control-DB transaction. Fresh and
// reinstalled packages use Store.InstallCommit so every installation shares
// the plugin-data binding and tombstone revoke-floor transaction.
func (v RegistryView) UpdateExternalPackage(ctx context.Context, ownerEnvHash string, req registry.InstallExternalPackageRequest) (registry.PluginRecord, error) {
	if err := v.ready(); err != nil {
		return registry.PluginRecord{}, err
	}
	if req.Intent != registry.ExternalPackageUpdate {
		return registry.PluginRecord{}, registry.ErrInvalidExternalPackageInstall
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer tx.Rollback()
	var raw string
	err = tx.QueryRowContext(ctx, `SELECT record_json FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=? AND deleted_at IS NULL`, ownerEnvHash, req.Record.PluginInstanceID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return registry.PluginRecord{}, registry.ErrNotFound
	}
	if err != nil {
		return registry.PluginRecord{}, err
	}
	existing, err := decodeRegistryPluginRecord([]byte(raw))
	if err != nil {
		return registry.PluginRecord{}, err
	}
	record, err := registry.PrepareExternalPackageInstall(ownerEnvHash, req, &existing)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	recordJSON, err := encodeRegistryPluginRecord(record)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	controlRecord := controlPluginRecord(record, recordJSON)
	if err := upsertControlPlugin(ctx, tx, controlRecord); err != nil {
		return registry.PluginRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM permission_grants WHERE owner_env_hash=? AND plugin_instance_id=?`, ownerEnvHash, record.PluginInstanceID); err != nil {
		return registry.PluginRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM security_policies WHERE owner_env_hash=? AND plugin_instance_id=?`, ownerEnvHash, record.PluginInstanceID); err != nil {
		return registry.PluginRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return registry.PluginRecord{}, err
	}
	return record, nil
}

func (v RegistryView) GetPlugin(ctx context.Context, ownerEnvHash, pluginInstanceID string) (registry.PluginRecord, error) {
	snapshot, err := v.Get(ctx, ownerEnvHash, pluginInstanceID)
	if err != nil {
		if errors.Is(err, ErrRecordNotFound) {
			return registry.PluginRecord{}, registry.ErrNotFound
		}
		return registry.PluginRecord{}, err
	}
	record, err := decodeRegistryPluginRecord(snapshot.Record.RawJSON)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	record.OwnerEnvHash = snapshot.Record.OwnerEnvHash
	return record, nil
}

func (v RegistryView) GetAuthorization(ctx context.Context, ownerEnvHash, pluginInstanceID string) (registry.AuthorizationSnapshot, error) {
	snapshot, err := v.Get(ctx, ownerEnvHash, pluginInstanceID)
	if err != nil {
		if errors.Is(err, ErrRecordNotFound) {
			return registry.AuthorizationSnapshot{}, registry.ErrNotFound
		}
		return registry.AuthorizationSnapshot{}, err
	}
	return decodeAuthorizationSnapshot(snapshot)
}

func (v RegistryView) ListAuthorization(ctx context.Context, ownerEnvHash string) ([]registry.AuthorizationSnapshot, error) {
	records, err := v.ListPlugins(ctx, ownerEnvHash)
	if err != nil {
		return nil, err
	}
	result := make([]registry.AuthorizationSnapshot, 0, len(records))
	for _, record := range records {
		snapshot, err := v.GetAuthorization(ctx, ownerEnvHash, record.PluginInstanceID)
		if err != nil {
			return nil, err
		}
		result = append(result, snapshot)
	}
	return result, nil
}

func decodeAuthorizationSnapshot(snapshot PluginSnapshot) (registry.AuthorizationSnapshot, error) {
	var result registry.AuthorizationSnapshot
	plugin, err := decodeRegistryPluginRecord(snapshot.Record.RawJSON)
	if err != nil {
		return result, err
	}
	result.Plugin = plugin
	result.Plugin.OwnerEnvHash = snapshot.Record.OwnerEnvHash
	result.Grants = make([]permissions.Record, len(snapshot.Grants))
	for index, grant := range snapshot.Grants {
		if err := json.Unmarshal(grant.RawJSON, &result.Grants[index]); err != nil {
			return result, fmt.Errorf("%w: permission grant JSON: %v", ErrIncompatible, err)
		}
	}
	if snapshot.Policy != nil {
		var policy security.PolicyRecord
		if err := json.Unmarshal(snapshot.Policy.RawJSON, &policy); err != nil {
			return result, fmt.Errorf("%w: security policy JSON: %v", ErrIncompatible, err)
		}
		result.Policy = &policy
	}
	return result, nil
}

func (v RegistryView) ReplaceAuthorizationSnapshot(ctx context.Context, snapshot registry.AuthorizationSnapshot, expected registry.AuthorizationRevisions) error {
	recordRaw, err := encodeRegistryPluginRecord(snapshot.Plugin)
	if err != nil {
		return err
	}
	record := controlPluginRecord(snapshot.Plugin, recordRaw)
	grants := make([]Grant, len(snapshot.Grants))
	for index, value := range snapshot.Grants {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		grants[index] = Grant{CapabilityID: value.PermissionID, Revision: snapshot.Plugin.PolicyRevision, RawJSON: raw}
	}
	var policy *Policy
	if snapshot.Policy != nil {
		raw, err := json.Marshal(snapshot.Policy)
		if err != nil {
			return err
		}
		policy = &Policy{Revision: snapshot.Plugin.PolicyRevision, UpdatedAt: snapshot.Policy.UpdatedAt.UnixNano(), RawJSON: raw}
	}
	return v.ReplaceAuthorization(ctx, record, expected, grants, policy)
}

func (v RegistryView) ListPlugins(ctx context.Context, ownerEnvHash string) ([]registry.PluginRecord, error) {
	if err := v.ready(); err != nil {
		return nil, err
	}
	rows, err := v.store.db.QueryContext(ctx, `SELECT record_json FROM plugin_records WHERE owner_env_hash=? AND deleted_at IS NULL ORDER BY installed_at,plugin_instance_id`, ownerEnvHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]registry.PluginRecord, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		record, err := decodeRegistryPluginRecord([]byte(raw))
		if err != nil {
			return nil, err
		}
		record.OwnerEnvHash = ownerEnvHash
		result = append(result, record)
	}
	return result, rows.Err()
}

func (v RegistryView) PutPlugin(ctx context.Context, ownerEnvHash string, record registry.PluginRecord, now time.Time) (registry.PluginRecord, error) {
	if err := v.ready(); err != nil {
		return registry.PluginRecord{}, err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer tx.Rollback()
	var raw string
	err = tx.QueryRowContext(ctx, `SELECT record_json FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=?`, ownerEnvHash, record.PluginInstanceID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return registry.PluginRecord{}, registry.ErrNotFound
	}
	if err != nil {
		return registry.PluginRecord{}, err
	}
	existing, err := decodeRegistryPluginRecord([]byte(raw))
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if existing.DeletedAt != nil {
		return registry.PluginRecord{}, registry.ErrNotFound
	}
	record, err = registry.PreparePluginPut(ownerEnvHash, record, &existing, now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	recordJSON, err := encodeRegistryPluginRecord(record)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	control := controlPluginRecord(record, recordJSON)
	result, err := tx.ExecContext(ctx, `UPDATE plugin_records SET publisher_id=?,plugin_id=?,version=?,active_fingerprint=?,package_sha256=?,manifest_sha256=?,entries_sha256=?,state=?,disabled_reason=?,policy_revision=?,management_revision=?,revoke_epoch=?,installed_at=?,enabled_at=?,updated_at=?,deleted_at=?,record_json=? WHERE owner_env_hash=? AND plugin_instance_id=? AND deleted_at IS NULL`, control.PublisherID, control.PluginID, control.Version, control.ActiveFingerprint, control.PackageSHA256, control.ManifestSHA256, control.EntriesSHA256, control.State, control.DisabledReason, control.PolicyRevision, control.ManagementRevision, control.RevokeEpoch, control.InstalledAt, optionalInt64(control.EnabledAt), control.UpdatedAt, optionalInt64(control.DeletedAt), string(control.RawJSON), control.OwnerEnvHash, control.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if changed, rowsErr := result.RowsAffected(); rowsErr != nil {
		return registry.PluginRecord{}, rowsErr
	} else if changed != 1 {
		return registry.PluginRecord{}, registry.ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return registry.PluginRecord{}, err
	}
	return record, nil
}

func (v RegistryView) SetEnableState(ctx context.Context, ownerEnvHash, pluginInstanceID string, state registry.EnableState, reason string, now time.Time) (registry.PluginRecord, error) {
	record, err := v.GetPlugin(ctx, ownerEnvHash, pluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	record, err = registry.PrepareEnableState(record, state, reason, now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	raw, err := encodeRegistryPluginRecord(record)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	control := controlPluginRecord(record, raw)
	result, err := v.store.db.ExecContext(ctx, `UPDATE plugin_records SET state=?,disabled_reason=?,management_revision=?,revoke_epoch=?,enabled_at=?,updated_at=?,record_json=? WHERE owner_env_hash=? AND plugin_instance_id=?`, control.State, control.DisabledReason, control.ManagementRevision, control.RevokeEpoch, optionalInt64(control.EnabledAt), control.UpdatedAt, string(raw), ownerEnvHash, pluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return registry.PluginRecord{}, registry.ErrNotFound
	}
	return record, nil
}

func (v RegistryView) BumpRevokeEpoch(ctx context.Context, ownerEnvHash, pluginInstanceID string, now time.Time) (registry.PluginRecord, error) {
	if err := v.ready(); err != nil {
		return registry.PluginRecord{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer tx.Rollback()
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT record_json FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=? AND deleted_at IS NULL`, ownerEnvHash, pluginInstanceID).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return registry.PluginRecord{}, registry.ErrNotFound
	} else if err != nil {
		return registry.PluginRecord{}, err
	}
	record, err := decodeRegistryPluginRecord([]byte(raw))
	if err != nil {
		return registry.PluginRecord{}, err
	}
	record.OwnerEnvHash = ownerEnvHash
	previousEpoch := record.RevokeEpoch
	record.RevokeEpoch++
	record.UpdatedAt = now
	encoded, err := encodeRegistryPluginRecord(record)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE plugin_records SET revoke_epoch=?,updated_at=?,record_json=? WHERE owner_env_hash=? AND plugin_instance_id=? AND revoke_epoch=? AND deleted_at IS NULL`, record.RevokeEpoch, record.UpdatedAt.UnixNano(), string(encoded), ownerEnvHash, pluginInstanceID, previousEpoch)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return registry.PluginRecord{}, ErrRevisionConflict
	}
	if err := tx.Commit(); err != nil {
		return registry.PluginRecord{}, err
	}
	return record, nil
}

func (v RegistryView) AbortInstall(ctx context.Context, ownerEnvHash, pluginInstanceID string) error {
	result, err := v.store.db.ExecContext(ctx, `DELETE FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=?`, ownerEnvHash, pluginInstanceID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return registry.ErrNotFound
	}
	return nil
}

func controlPluginRecord(record registry.PluginRecord, raw []byte) PluginRecord {
	result := PluginRecord{
		OwnerEnvHash: record.OwnerEnvHash, PluginInstanceID: record.PluginInstanceID,
		PublisherID: record.PublisherID, PluginID: record.PluginID, Version: record.Version,
		ActiveFingerprint: record.ActiveFingerprint, PackageSHA256: record.PackageHash,
		ManifestSHA256: record.ManifestHash, EntriesSHA256: record.EntriesHash,
		State: string(record.EnableState), DisabledReason: record.DisabledReason,
		PolicyRevision: record.PolicyRevision, ManagementRevision: record.ManagementRevision,
		RevokeEpoch: record.RevokeEpoch, InstalledAt: record.InstalledAt.UnixNano(),
		UpdatedAt: record.UpdatedAt.UnixNano(), RawJSON: append(json.RawMessage(nil), raw...),
	}
	if record.EnabledAt != nil {
		value := record.EnabledAt.UnixNano()
		result.EnabledAt = &value
	}
	if record.DeletedAt != nil {
		value := record.DeletedAt.UnixNano()
		result.DeletedAt = &value
	}
	return result
}

func upsertControlPlugin(ctx context.Context, tx *sql.Tx, record PluginRecord) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO plugin_records(owner_env_hash,plugin_instance_id,publisher_id,plugin_id,version,active_fingerprint,package_sha256,manifest_sha256,entries_sha256,state,disabled_reason,policy_revision,management_revision,revoke_epoch,installed_at,enabled_at,updated_at,deleted_at,record_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(owner_env_hash,plugin_instance_id) DO UPDATE SET publisher_id=excluded.publisher_id,plugin_id=excluded.plugin_id,version=excluded.version,active_fingerprint=excluded.active_fingerprint,package_sha256=excluded.package_sha256,manifest_sha256=excluded.manifest_sha256,entries_sha256=excluded.entries_sha256,state=excluded.state,disabled_reason=excluded.disabled_reason,policy_revision=excluded.policy_revision,management_revision=excluded.management_revision,revoke_epoch=excluded.revoke_epoch,installed_at=excluded.installed_at,enabled_at=excluded.enabled_at,updated_at=excluded.updated_at,deleted_at=excluded.deleted_at,record_json=excluded.record_json`, record.OwnerEnvHash, record.PluginInstanceID, record.PublisherID, record.PluginID, record.Version, record.ActiveFingerprint, record.PackageSHA256, record.ManifestSHA256, record.EntriesSHA256, record.State, record.DisabledReason, record.PolicyRevision, record.ManagementRevision, record.RevokeEpoch, record.InstalledAt, optionalInt64(record.EnabledAt), record.UpdatedAt, optionalInt64(record.DeletedAt), string(record.RawJSON))
	return err
}

func (v RegistryView) ReplaceAuthorization(ctx context.Context, record PluginRecord, expected registry.AuthorizationRevisions, grants []Grant, policy *Policy) error {
	if err := v.ready(); err != nil {
		return err
	}
	if err := validatePluginRecord(record); err != nil {
		return err
	}
	if record.PolicyRevision <= expected.PolicyRevision {
		return ErrRevisionConflict
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE plugin_records SET policy_revision=?,management_revision=?,revoke_epoch=?,updated_at=?,record_json=? WHERE owner_env_hash=? AND plugin_instance_id=? AND policy_revision=? AND management_revision=? AND revoke_epoch=?`, record.PolicyRevision, record.ManagementRevision, record.RevokeEpoch, record.UpdatedAt, string(record.RawJSON), record.OwnerEnvHash, record.PluginInstanceID, expected.PolicyRevision, expected.ManagementRevision, expected.RevokeEpoch)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrRevisionConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM permission_grants WHERE owner_env_hash=? AND plugin_instance_id=?`, record.OwnerEnvHash, record.PluginInstanceID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, grant := range grants {
		if grant.CapabilityID == "" || seen[grant.CapabilityID] || grant.Revision != record.PolicyRevision || !validRawJSON(grant.RawJSON) {
			return errors.New("grant is invalid")
		}
		seen[grant.CapabilityID] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO permission_grants(owner_env_hash,plugin_instance_id,capability_id,grant_json,revision) VALUES(?,?,?,?,?)`, record.OwnerEnvHash, record.PluginInstanceID, grant.CapabilityID, string(grant.RawJSON), grant.Revision); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM security_policies WHERE owner_env_hash=? AND plugin_instance_id=?`, record.OwnerEnvHash, record.PluginInstanceID); err != nil {
		return err
	}
	if policy != nil {
		if policy.Revision != record.PolicyRevision || !validRawJSON(policy.RawJSON) {
			return errors.New("policy is invalid")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_policies(owner_env_hash,plugin_instance_id,policy_json,revision,updated_at) VALUES(?,?,?,?,?)`, record.OwnerEnvHash, record.PluginInstanceID, string(policy.RawJSON), policy.Revision, policy.UpdatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (v RegistryView) Install(ctx context.Context, value PluginInstall) error {
	if err := v.ready(); err != nil {
		return err
	}
	if err := validatePluginRecord(value.Record); err != nil {
		return err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	record := value.Record
	if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_records(owner_env_hash,plugin_instance_id,publisher_id,plugin_id,version,active_fingerprint,package_sha256,manifest_sha256,entries_sha256,state,disabled_reason,policy_revision,management_revision,revoke_epoch,installed_at,enabled_at,updated_at,deleted_at,record_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, record.OwnerEnvHash, record.PluginInstanceID, record.PublisherID, record.PluginID, record.Version, record.ActiveFingerprint, record.PackageSHA256, record.ManifestSHA256, record.EntriesSHA256, record.State, record.DisabledReason, record.PolicyRevision, record.ManagementRevision, record.RevokeEpoch, record.InstalledAt, optionalInt64(record.EnabledAt), record.UpdatedAt, optionalInt64(record.DeletedAt), string(record.RawJSON)); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, grant := range value.Grants {
		if strings.TrimSpace(grant.CapabilityID) == "" || seen[grant.CapabilityID] || !validRawJSON(grant.RawJSON) {
			return errors.New("grant is invalid")
		}
		seen[grant.CapabilityID] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO permission_grants(owner_env_hash,plugin_instance_id,capability_id,grant_json,revision) VALUES(?,?,?,?,?)`, record.OwnerEnvHash, record.PluginInstanceID, grant.CapabilityID, string(grant.RawJSON), grant.Revision); err != nil {
			return err
		}
	}
	if value.Policy != nil {
		if !validRawJSON(value.Policy.RawJSON) {
			return errors.New("policy is invalid")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_policies(owner_env_hash,plugin_instance_id,policy_json,revision,updated_at) VALUES(?,?,?,?,?)`, record.OwnerEnvHash, record.PluginInstanceID, string(value.Policy.RawJSON), value.Policy.Revision, value.Policy.UpdatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (v RegistryView) Get(ctx context.Context, ownerEnvHash, pluginInstanceID string) (PluginSnapshot, error) {
	if err := v.ready(); err != nil {
		return PluginSnapshot{}, err
	}
	var result PluginSnapshot
	var enabledAt, deletedAt sql.NullInt64
	var raw string
	err := v.store.db.QueryRowContext(ctx, `SELECT owner_env_hash,plugin_instance_id,publisher_id,plugin_id,version,active_fingerprint,package_sha256,manifest_sha256,entries_sha256,state,disabled_reason,policy_revision,management_revision,revoke_epoch,installed_at,enabled_at,updated_at,deleted_at,record_json FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=? AND deleted_at IS NULL`, ownerEnvHash, pluginInstanceID).Scan(&result.Record.OwnerEnvHash, &result.Record.PluginInstanceID, &result.Record.PublisherID, &result.Record.PluginID, &result.Record.Version, &result.Record.ActiveFingerprint, &result.Record.PackageSHA256, &result.Record.ManifestSHA256, &result.Record.EntriesSHA256, &result.Record.State, &result.Record.DisabledReason, &result.Record.PolicyRevision, &result.Record.ManagementRevision, &result.Record.RevokeEpoch, &result.Record.InstalledAt, &enabledAt, &result.Record.UpdatedAt, &deletedAt, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return PluginSnapshot{}, ErrRecordNotFound
	}
	if err != nil {
		return PluginSnapshot{}, err
	}
	result.Record.EnabledAt = nullIntPointer(enabledAt)
	result.Record.DeletedAt = nullIntPointer(deletedAt)
	result.Record.RawJSON = json.RawMessage(raw)
	rows, err := v.store.db.QueryContext(ctx, `SELECT capability_id,revision,grant_json FROM permission_grants WHERE owner_env_hash=? AND plugin_instance_id=? ORDER BY capability_id`, ownerEnvHash, pluginInstanceID)
	if err != nil {
		return PluginSnapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var grant Grant
		var raw string
		if err := rows.Scan(&grant.CapabilityID, &grant.Revision, &raw); err != nil {
			return PluginSnapshot{}, err
		}
		grant.RawJSON = json.RawMessage(raw)
		result.Grants = append(result.Grants, grant)
	}
	if err := rows.Err(); err != nil {
		return PluginSnapshot{}, err
	}
	var policy Policy
	if err := v.store.db.QueryRowContext(ctx, `SELECT revision,updated_at,policy_json FROM security_policies WHERE owner_env_hash=? AND plugin_instance_id=?`, ownerEnvHash, pluginInstanceID).Scan(&policy.Revision, &policy.UpdatedAt, &raw); err == nil {
		policy.RawJSON = json.RawMessage(raw)
		result.Policy = &policy
	} else if !errors.Is(err, sql.ErrNoRows) {
		return PluginSnapshot{}, err
	}
	return result, nil
}

func validatePluginRecord(value PluginRecord) error {
	if strings.TrimSpace(value.OwnerEnvHash) == "" || strings.TrimSpace(value.PluginInstanceID) == "" || strings.TrimSpace(value.PluginID) == "" || strings.TrimSpace(value.Version) == "" || strings.TrimSpace(value.State) == "" || !validRawJSON(value.RawJSON) {
		return errors.New("plugin record is invalid")
	}
	return nil
}

func (v ExecutionView) Create(ctx context.Context, value execution.Execution) error {
	return v.CreateOwned(ctx, value, ExecutionOwner{
		OwnerSessionHash: "internal_unowned", OwnerUserHash: "internal_unowned",
		OwnerEnvHash: "internal_unowned", SessionChannelIDHash: "internal_unowned",
	})
}

func (v ExecutionView) CreateOwned(ctx context.Context, value execution.Execution, owner ExecutionOwner) error {
	if err := v.ready(); err != nil {
		return err
	}
	if !owner.Valid() {
		return errors.New("execution owner is invalid")
	}
	if value.Status != "" && value.Status != execution.StatusRunning || value.Cursor != 0 || value.CancelRequestedAt != nil || value.TerminalAt != nil {
		return execution.ErrInvalidTransition
	}
	value, err := execution.New(value)
	if err != nil {
		return err
	}
	_, err = v.store.db.ExecContext(ctx, `INSERT INTO execution(execution_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,kind,status,cursor,failure_code,cancelable,created_at,updated_at,cancel_requested_at,terminal_at,operation_json,stream_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'{}','null')`, value.ID, value.PluginInstanceID, owner.OwnerSessionHash, owner.OwnerUserHash, owner.OwnerEnvHash, owner.SessionChannelIDHash, value.Kind, value.Status, value.Cursor, value.FailureCode, value.Cancelable, value.CreatedAt.UnixNano(), value.UpdatedAt.UnixNano(), optionalTime(value.CancelRequestedAt), optionalTime(value.TerminalAt))
	return err
}

func (v ExecutionView) StartReleaseInstall(ctx context.Context, owner ExecutionOwner, req registry.StartReleaseInstallOperationRequest) (registry.ReleaseInstallOperation, bool, error) {
	if err := v.ready(); err != nil {
		return registry.ReleaseInstallOperation{}, false, err
	}
	if !owner.Valid() || owner.OwnerEnvHash == "" {
		return registry.ReleaseInstallOperation{}, false, ErrRecordNotFound
	}
	prepared, err := registry.PrepareReleaseInstallOperation(req)
	if err != nil {
		return registry.ReleaseInstallOperation{}, false, err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return registry.ReleaseInstallOperation{}, false, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, releaseInstallSelect+` WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND kind=? ORDER BY created_at,execution_id`, owner.OwnerSessionHash, owner.OwnerUserHash, owner.OwnerEnvHash, owner.SessionChannelIDHash, execution.KindOperation)
	if err != nil {
		return registry.ReleaseInstallOperation{}, false, err
	}
	var existing []registry.ReleaseInstallOperation
	for rows.Next() {
		operation, err := scanReleaseInstallOperation(rows)
		if errors.Is(err, registry.ErrReleaseInstallOperationNotFound) {
			continue
		}
		if err != nil {
			_ = rows.Close()
			return registry.ReleaseInstallOperation{}, false, err
		}
		existing = append(existing, operation)
	}
	if err := rows.Close(); err != nil {
		return registry.ReleaseInstallOperation{}, false, err
	}
	for _, operation := range existing {
		if operation.RequestID == prepared.RequestID {
			if operation.RequestSHA256 != prepared.RequestSHA256 {
				return registry.ReleaseInstallOperation{}, false, registry.ErrReleaseInstallOperationConflict
			}
			return operation, false, nil
		}
		if operation.Execution.ID == prepared.Execution.ID {
			return registry.ReleaseInstallOperation{}, false, registry.ErrReleaseInstallOperationConflict
		}
		if operation.PluginInstanceID == prepared.PluginInstanceID && operation.Execution.Status == execution.StatusRunning {
			return operation, false, nil
		}
	}
	raw, err := encodeReleaseInstallOperation(prepared)
	if err != nil {
		return registry.ReleaseInstallOperation{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO execution(execution_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,kind,status,cursor,failure_code,cancelable,created_at,updated_at,cancel_requested_at,terminal_at,operation_json,stream_json) VALUES(?,?,?,?,?,?,?,?,0,'',0,?,?,NULL,NULL,?,'null')`, prepared.Execution.ID, prepared.PluginInstanceID, owner.OwnerSessionHash, owner.OwnerUserHash, owner.OwnerEnvHash, owner.SessionChannelIDHash, execution.KindOperation, execution.StatusRunning, prepared.Execution.CreatedAt.UnixNano(), prepared.Execution.UpdatedAt.UnixNano(), string(raw))
	if err != nil {
		return registry.ReleaseInstallOperation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return registry.ReleaseInstallOperation{}, false, err
	}
	return prepared, true, nil
}

func (v ExecutionView) GetReleaseInstall(ctx context.Context, ownerEnvHash, executionID string) (registry.ReleaseInstallOperation, error) {
	return scanReleaseInstallOperation(v.store.db.QueryRowContext(ctx, releaseInstallSelect+` WHERE owner_env_hash=? AND execution_id=? AND kind=?`, ownerEnvHash, executionID, execution.KindOperation))
}

func (v ExecutionView) GetReleaseInstallByRequest(ctx context.Context, ownerEnvHash, requestID string) (registry.ReleaseInstallOperation, error) {
	rows, err := v.store.db.QueryContext(ctx, releaseInstallSelect+` WHERE owner_env_hash=? AND kind=? ORDER BY created_at,execution_id`, ownerEnvHash, execution.KindOperation)
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	defer rows.Close()
	for rows.Next() {
		operation, err := scanReleaseInstallOperation(rows)
		if errors.Is(err, registry.ErrReleaseInstallOperationNotFound) {
			continue
		}
		if err != nil {
			return registry.ReleaseInstallOperation{}, err
		}
		if operation.RequestID == requestID {
			return operation, nil
		}
	}
	return registry.ReleaseInstallOperation{}, registry.ErrReleaseInstallOperationNotFound
}

func (v ExecutionView) ListReleaseInstalls(ctx context.Context, ownerEnvHash string) ([]registry.ReleaseInstallOperation, error) {
	rows, err := v.store.db.QueryContext(ctx, releaseInstallSelect+` WHERE owner_env_hash=? AND kind=? ORDER BY created_at,execution_id`, ownerEnvHash, execution.KindOperation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []registry.ReleaseInstallOperation
	for rows.Next() {
		operation, err := scanReleaseInstallOperation(rows)
		if errors.Is(err, registry.ErrReleaseInstallOperationNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, operation)
	}
	return result, rows.Err()
}

func (v ExecutionView) UpdateReleaseInstall(ctx context.Context, ownerEnvHash string, req registry.UpdateReleaseInstallOperationRequest) (registry.ReleaseInstallOperation, error) {
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	defer tx.Rollback()
	current, err := scanReleaseInstallOperation(tx.QueryRowContext(ctx, releaseInstallSelect+` WHERE owner_env_hash=? AND execution_id=? AND kind=?`, ownerEnvHash, req.ExecutionID, execution.KindOperation))
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	updated, err := registry.ApplyReleaseInstallOperationUpdate(current, req)
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	raw, err := encodeReleaseInstallOperation(updated)
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	status, failureCode := req.Status, ""
	if status == execution.StatusFailed {
		failureCode = updated.Failure.Code
	}
	installProgress := registry.ReleaseInstallProgressEvent{
		TaskID: updated.Execution.ID, RequestID: updated.RequestID,
		Stage: registry.ReleaseInstallStageForPhase(updated.Phase), Status: registry.ReleaseInstallStageRunning,
	}
	if updated.Progress.Kind != registry.ReleaseInstallProgressIndeterminate {
		completed, total := updated.Progress.Completed, updated.Progress.Total
		installProgress.Completed, installProgress.Total = &completed, &total
	}
	eventPayload := map[string]any{
		"phase": updated.Phase, "progress": updated.Progress, "install_progress": installProgress,
	}
	if status != execution.StatusRunning {
		eventPayload["status"] = status
	}
	if status == execution.StatusFailed {
		eventPayload["failure_phase"] = updated.Phase
		installProgress.Status = registry.ReleaseInstallStageFailed
		installProgress.FailureCode = updated.Failure.Code
		installProgress.FailureStage = installProgress.Stage
		eventPayload["install_progress"] = installProgress
	} else if status == execution.StatusCompleted {
		installProgress.Status = registry.ReleaseInstallStageCompleted
		eventPayload["install_progress"] = installProgress
	}
	payload, err := json.Marshal(eventPayload)
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	var terminalAt any
	if status != execution.StatusRunning {
		terminalAt = req.Now.UTC().UnixNano()
	}
	result, err := tx.ExecContext(ctx, `UPDATE execution SET status=?,cursor=cursor+1,failure_code=?,updated_at=?,terminal_at=?,operation_json=? WHERE owner_env_hash=? AND execution_id=? AND kind=? AND cursor=? AND status=?`, status, failureCode, req.Now.UTC().UnixNano(), terminalAt, string(raw), ownerEnvHash, req.ExecutionID, execution.KindOperation, req.ExpectedCursor, current.Execution.Status)
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return registry.ReleaseInstallOperation{}, registry.ErrReleaseInstallOperationConflict
	}
	var sequence uint64
	if err := tx.QueryRowContext(ctx, `SELECT cursor FROM execution WHERE execution_id=?`, req.ExecutionID).Scan(&sequence); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	kind := execution.EventProgress
	if status != execution.StatusRunning {
		kind = execution.EventTerminal
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO execution_events(execution_id,sequence,kind,payload_json,error_json) VALUES(?,?,?,?,?)`, req.ExecutionID, sequence, kind, string(payload), "null"); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	if err := tx.Commit(); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	return scanReleaseInstallOperation(v.store.db.QueryRowContext(ctx, releaseInstallSelect+` WHERE owner_env_hash=? AND execution_id=? AND kind=?`, ownerEnvHash, req.ExecutionID, execution.KindOperation))
}

const releaseInstallSelect = `SELECT execution_id,plugin_instance_id,kind,status,cursor,failure_code,cancelable,created_at,updated_at,cancel_requested_at,terminal_at,operation_json FROM execution`

func scanReleaseInstallOperation(row scanner) (registry.ReleaseInstallOperation, error) {
	var control execution.Execution
	var raw string
	var createdAt, updatedAt int64
	var cancelRequestedAt, terminalAt sql.NullInt64
	if err := row.Scan(&control.ID, &control.PluginInstanceID, &control.Kind, &control.Status, &control.Cursor, &control.FailureCode, &control.Cancelable, &createdAt, &updatedAt, &cancelRequestedAt, &terminalAt, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return registry.ReleaseInstallOperation{}, registry.ErrReleaseInstallOperationNotFound
		}
		return registry.ReleaseInstallOperation{}, err
	}
	operation, ok := decodeReleaseInstallOperation(raw)
	if !ok {
		return registry.ReleaseInstallOperation{}, registry.ErrReleaseInstallOperationNotFound
	}
	control.CreatedAt = time.Unix(0, createdAt).UTC()
	control.UpdatedAt = time.Unix(0, updatedAt).UTC()
	control.CancelRequestedAt = nullTimePointer(cancelRequestedAt)
	control.TerminalAt = nullTimePointer(terminalAt)
	if err := control.Validate(); err != nil {
		return registry.ReleaseInstallOperation{}, fmt.Errorf("%w: release install execution row: %v", ErrIncompatible, err)
	}
	if operation.PluginInstanceID != control.PluginInstanceID {
		return registry.ReleaseInstallOperation{}, fmt.Errorf("%w: release install payload identity mismatch", ErrIncompatible)
	}
	operation.Execution = control
	return operation, nil
}

func decodeReleaseInstallOperation(raw string) (registry.ReleaseInstallOperation, bool) {
	var payload releaseInstallPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil || payload.Kind != releaseInstallPayloadKind || payload.Operation.RequestID == "" {
		return registry.ReleaseInstallOperation{}, false
	}
	operation := payload.Operation
	operation.Release = payload.Release
	return operation, true
}

func (v ExecutionView) Get(ctx context.Context, id string) (execution.Execution, error) {
	if err := v.ready(); err != nil {
		return execution.Execution{}, err
	}
	return scanExecution(v.store.db.QueryRowContext(ctx, executionSelect+` WHERE execution_id=?`, id))
}

func (v ExecutionView) List(ctx context.Context, pluginInstanceID string) ([]execution.Execution, error) {
	if err := v.ready(); err != nil {
		return nil, err
	}
	query, args := executionSelect, []any{}
	if pluginInstanceID != "" {
		query += ` WHERE plugin_instance_id=?`
		args = append(args, pluginInstanceID)
	}
	query += ` ORDER BY created_at,execution_id`
	rows, err := v.store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []execution.Execution
	for rows.Next() {
		item, err := scanExecution(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (v ExecutionView) GetOwned(ctx context.Context, id string, owner ExecutionOwner) (execution.Execution, error) {
	if err := v.ready(); err != nil {
		return execution.Execution{}, err
	}
	if !owner.Valid() {
		return execution.Execution{}, ErrRecordNotFound
	}
	value, err := scanExecution(v.store.db.QueryRowContext(ctx, executionSelect+` WHERE execution_id=? AND owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=?`, id, owner.OwnerSessionHash, owner.OwnerUserHash, owner.OwnerEnvHash, owner.SessionChannelIDHash))
	if errors.Is(err, sql.ErrNoRows) {
		return execution.Execution{}, ErrRecordNotFound
	}
	return value, err
}

func (v ExecutionView) ListOwned(ctx context.Context, pluginInstanceID string, owner ExecutionOwner, cursor uint64, limit int) ([]execution.Execution, uint64, error) {
	if err := v.ready(); err != nil {
		return nil, 0, err
	}
	if !owner.Valid() {
		return nil, 0, ErrRecordNotFound
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := executionSelect + ` WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=?`
	args := []any{owner.OwnerSessionHash, owner.OwnerUserHash, owner.OwnerEnvHash, owner.SessionChannelIDHash}
	if pluginInstanceID != "" {
		query += ` AND plugin_instance_id=?`
		args = append(args, pluginInstanceID)
	}
	if cursor != 0 {
		query += ` AND rowid>?`
		args = append(args, cursor)
	}
	query += ` ORDER BY rowid LIMIT ?`
	args = append(args, limit+1)
	rows, err := v.store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := make([]execution.Execution, 0, limit+1)
	for rows.Next() {
		item, err := scanExecution(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var next uint64
	if len(result) > limit {
		result = result[:limit]
		// The public cursor is a stable ordinal for this owner-filtered ordered
		// result. Resolve the final rowid without exposing it in Execution.
		if err := v.store.db.QueryRowContext(ctx, `SELECT rowid FROM execution WHERE execution_id=?`, result[len(result)-1].ID).Scan(&next); err != nil {
			return nil, 0, err
		}
	}
	return result, next, nil
}

func (v ExecutionView) RequestCancelOwned(ctx context.Context, id string, owner ExecutionOwner, now time.Time) (execution.Execution, error) {
	current, err := v.GetOwned(ctx, id, owner)
	if err != nil {
		return execution.Execution{}, err
	}
	if current.Status == execution.StatusCancelRequested {
		return current, nil
	}
	if err := v.RequestCancel(ctx, id, now); err != nil {
		return execution.Execution{}, err
	}
	return v.GetOwned(ctx, id, owner)
}

func (v ExecutionView) EventsAfterOwned(ctx context.Context, id string, owner ExecutionOwner, cursor uint64, limit int) ([]execution.Event, error) {
	if _, err := v.GetOwned(ctx, id, owner); err != nil {
		return nil, err
	}
	return v.EventsAfter(ctx, id, cursor, limit)
}

func (v ExecutionView) Append(ctx context.Context, event execution.Event) error {
	if err := v.ready(); err != nil {
		return err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	value, err := scanExecution(tx.QueryRowContext(ctx, executionSelect+` WHERE execution_id=?`, event.ExecutionID))
	if err != nil {
		return err
	}
	validated, err := execution.NewEvent(value, event.Sequence, event.Kind, event.Payload)
	if err != nil {
		return err
	}
	validated.Error = event.Error
	if err := value.Append(validated); err != nil {
		return err
	}
	if err := insertEvent(ctx, tx, validated); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE execution SET cursor=?,updated_at=? WHERE execution_id=?`, value.Cursor, time.Now().UTC().UnixNano(), value.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (v ExecutionView) RequestCancel(ctx context.Context, id string, now time.Time) error {
	if err := v.ready(); err != nil {
		return err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	value, err := scanExecution(tx.QueryRowContext(ctx, executionSelect+` WHERE execution_id=?`, id))
	if err != nil {
		return err
	}
	if err := value.RequestCancel(now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE execution SET status=?,updated_at=?,cancel_requested_at=? WHERE execution_id=?`, value.Status, value.UpdatedAt.UnixNano(), value.CancelRequestedAt.UnixNano(), id); err != nil {
		return err
	}
	return tx.Commit()
}

func (v ExecutionView) Finish(ctx context.Context, id, status, failureCode string, event execution.Event, now time.Time) error {
	if err := v.ready(); err != nil {
		return err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	value, err := scanExecution(tx.QueryRowContext(ctx, executionSelect+` WHERE execution_id=?`, id))
	if err != nil {
		return err
	}
	validated, err := execution.NewEvent(value, event.Sequence, event.Kind, event.Payload)
	if err != nil {
		return err
	}
	validated.Error = event.Error
	if err := value.Finish(status, failureCode, validated, now); err != nil {
		return err
	}
	if err := insertEvent(ctx, tx, validated); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE execution SET status=?,cursor=?,failure_code=?,updated_at=?,terminal_at=? WHERE execution_id=?`, value.Status, value.Cursor, value.FailureCode, value.UpdatedAt.UnixNano(), value.TerminalAt.UnixNano(), id); err != nil {
		return err
	}
	return tx.Commit()
}

// ReconcileOrphans atomically terminates executions whose process-local owner
// cannot survive a Host restart. A pending cancellation converges to canceled;
// every other non-terminal execution converges to orphaned.
func (v ExecutionView) ReconcileOrphans(ctx context.Context, now time.Time) (ExecutionReconcileResult, error) {
	if err := v.ready(); err != nil {
		return ExecutionReconcileResult{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return ExecutionReconcileResult{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, executionSelect+` WHERE status IN (?,?) ORDER BY created_at,execution_id`, execution.StatusRunning, execution.StatusCancelRequested)
	if err != nil {
		return ExecutionReconcileResult{}, err
	}
	var pending []execution.Execution
	for rows.Next() {
		value, scanErr := scanExecution(rows)
		if scanErr != nil {
			rows.Close()
			return ExecutionReconcileResult{}, scanErr
		}
		pending = append(pending, value)
	}
	if err := rows.Close(); err != nil {
		return ExecutionReconcileResult{}, err
	}
	if err := rows.Err(); err != nil {
		return ExecutionReconcileResult{}, err
	}
	result := ExecutionReconcileResult{Records: make([]execution.Execution, 0, len(pending))}
	for _, value := range pending {
		status := execution.StatusOrphaned
		failureCode := "platform_failed"
		if value.Status == execution.StatusCancelRequested {
			status = execution.StatusCanceled
			failureCode = ""
			result.Canceled++
		} else {
			result.Orphaned++
		}
		event, err := execution.NewEvent(value, value.Cursor+1, execution.EventTerminal, map[string]any{"status": status})
		if err != nil {
			return ExecutionReconcileResult{}, err
		}
		if status == execution.StatusOrphaned {
			event.Error = &execution.PublicError{Code: failureCode, Message: "execution owner is unavailable after host restart"}
		}
		if err := value.Finish(status, failureCode, event, now); err != nil {
			return ExecutionReconcileResult{}, err
		}
		if err := insertEvent(ctx, tx, event); err != nil {
			return ExecutionReconcileResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE execution SET status=?,cursor=?,failure_code=?,updated_at=?,terminal_at=? WHERE execution_id=?`, value.Status, value.Cursor, value.FailureCode, value.UpdatedAt.UnixNano(), value.TerminalAt.UnixNano(), value.ID); err != nil {
			return ExecutionReconcileResult{}, err
		}
		result.Records = append(result.Records, value)
	}
	if err := tx.Commit(); err != nil {
		return ExecutionReconcileResult{}, err
	}
	return result, nil
}

// PruneTerminal atomically removes the oldest terminal executions selected by
// age or the per-owner plugin cap. execution_events follow through the schema's
// cascading foreign key.
func (v ExecutionView) PruneTerminal(ctx context.Context, req ExecutionPruneRequest) (ExecutionPruneResult, error) {
	if err := v.ready(); err != nil {
		return ExecutionPruneResult{}, err
	}
	if req.Before.IsZero() || req.Limit < 1 || req.Limit > 5000 || req.MaxTerminalRecordsPerPlugin < 1 || req.MaxTerminalRecordsPerPlugin > 100_000 {
		return ExecutionPruneResult{}, errors.New("execution prune request is invalid")
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return ExecutionPruneResult{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		SELECT execution_id FROM (
			SELECT execution_id,terminal_at,
				ROW_NUMBER() OVER (PARTITION BY owner_env_hash,plugin_instance_id ORDER BY terminal_at DESC,execution_id DESC) AS ordinal
			FROM execution
			WHERE terminal_at IS NOT NULL AND status IN (?,?,?,?)
		)
		WHERE terminal_at < ? OR ordinal > ?
		ORDER BY terminal_at,execution_id
		LIMIT ?`, execution.StatusCompleted, execution.StatusCanceled, execution.StatusFailed, execution.StatusOrphaned,
		req.Before.UTC().UnixNano(), req.MaxTerminalRecordsPerPlugin, req.Limit)
	if err != nil {
		return ExecutionPruneResult{}, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return ExecutionPruneResult{}, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return ExecutionPruneResult{}, err
	}
	if err := rows.Err(); err != nil {
		return ExecutionPruneResult{}, err
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `DELETE FROM execution WHERE execution_id=?`, id); err != nil {
			return ExecutionPruneResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ExecutionPruneResult{}, err
	}
	return ExecutionPruneResult{Deleted: len(ids)}, nil
}

func (v ExecutionView) EventsAfter(ctx context.Context, id string, cursor uint64, limit int) ([]execution.Event, error) {
	if err := v.ready(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := v.store.db.QueryContext(ctx, `SELECT execution_id,sequence,kind,payload_json,error_json FROM execution_events WHERE execution_id=? AND sequence>? ORDER BY sequence LIMIT ?`, id, cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []execution.Event
	for rows.Next() {
		var event execution.Event
		var payload, eventError string
		if err := rows.Scan(&event.ExecutionID, &event.Sequence, &event.Kind, &payload, &eventError); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(payload), &event.Payload); err != nil {
			return nil, err
		}
		if eventError != "null" {
			var publicError execution.PublicError
			if err := json.Unmarshal([]byte(eventError), &publicError); err != nil {
				return nil, err
			}
			event.Error = &publicError
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

const executionSelect = `SELECT execution_id,plugin_instance_id,kind,status,cursor,failure_code,cancelable,created_at,updated_at,cancel_requested_at,terminal_at FROM execution`

type scanner interface{ Scan(...any) error }

func scanExecution(row scanner) (execution.Execution, error) {
	var value execution.Execution
	var createdAt, updatedAt int64
	var cancelRequestedAt, terminalAt sql.NullInt64
	if err := row.Scan(&value.ID, &value.PluginInstanceID, &value.Kind, &value.Status, &value.Cursor, &value.FailureCode, &value.Cancelable, &createdAt, &updatedAt, &cancelRequestedAt, &terminalAt); err != nil {
		return execution.Execution{}, err
	}
	value.CreatedAt = time.Unix(0, createdAt).UTC()
	value.UpdatedAt = time.Unix(0, updatedAt).UTC()
	value.CancelRequestedAt = nullTimePointer(cancelRequestedAt)
	value.TerminalAt = nullTimePointer(terminalAt)
	if err := value.Validate(); err != nil {
		return execution.Execution{}, fmt.Errorf("%w: execution row: %v", ErrIncompatible, err)
	}
	return value, nil
}

func insertEvent(ctx context.Context, tx *sql.Tx, event execution.Event) error {
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return err
	}
	eventError := []byte("null")
	if event.Error != nil {
		eventError, err = json.Marshal(event.Error)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO execution_events(execution_id,sequence,kind,payload_json,error_json) VALUES(?,?,?,?,?)`, event.ExecutionID, event.Sequence, event.Kind, string(payload), string(eventError))
	return err
}

type Confirmation struct {
	ID                   string
	PluginInstanceID     string
	OwnerSessionHash     string
	OwnerUserHash        string
	OwnerEnvHash         string
	SessionChannelIDHash string
	Status               string
	ExpiresAt            int64
	RawJSON              json.RawMessage
}

type ConfirmationRevocation struct {
	SessionKey
	TeardownOperationID string
	RevokedCount        int
	RawJSON             json.RawMessage
}

func (v ConfirmationView) Put(ctx context.Context, value Confirmation) error {
	if err := v.ready(); err != nil {
		return err
	}
	if value.ID == "" || value.PluginInstanceID == "" || value.OwnerSessionHash == "" || value.OwnerUserHash == "" || value.OwnerEnvHash == "" || value.SessionChannelIDHash == "" || value.Status == "" || !validRawJSON(value.RawJSON) {
		return errors.New("confirmation is invalid")
	}
	_, err := v.store.db.ExecContext(ctx, `INSERT INTO confirmation_intents(confirmation_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,status,expires_at,confirmation_json) VALUES(?,?,?,?,?,?,?,?,?)`, value.ID, value.PluginInstanceID, value.OwnerSessionHash, value.OwnerUserHash, value.OwnerEnvHash, value.SessionChannelIDHash, value.Status, value.ExpiresAt, string(value.RawJSON))
	return err
}

func (v ConfirmationView) Get(ctx context.Context, id string) (Confirmation, error) {
	if err := v.ready(); err != nil {
		return Confirmation{}, err
	}
	var value Confirmation
	var raw string
	err := v.store.db.QueryRowContext(ctx, `SELECT confirmation_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,status,expires_at,confirmation_json FROM confirmation_intents WHERE confirmation_id=?`, id).Scan(&value.ID, &value.PluginInstanceID, &value.OwnerSessionHash, &value.OwnerUserHash, &value.OwnerEnvHash, &value.SessionChannelIDHash, &value.Status, &value.ExpiresAt, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Confirmation{}, ErrRecordNotFound
	}
	value.RawJSON = json.RawMessage(raw)
	return value, err
}

func (v ConfirmationView) Resolve(ctx context.Context, id, status string, now time.Time) (Confirmation, error) {
	if err := v.ready(); err != nil {
		return Confirmation{}, err
	}
	if status != "consumed" && status != "rejected" {
		return Confirmation{}, ErrStateConflict
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return Confirmation{}, err
	}
	defer tx.Rollback()
	var expiresAt int64
	if err := tx.QueryRowContext(ctx, `SELECT expires_at FROM confirmation_intents WHERE confirmation_id=? AND status='pending'`, id).Scan(&expiresAt); errors.Is(err, sql.ErrNoRows) {
		return Confirmation{}, ErrStateConflict
	} else if err != nil {
		return Confirmation{}, err
	}
	if normalizedUnixNano(now) >= expiresAt {
		return Confirmation{}, ErrStateConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE confirmation_intents SET status=? WHERE confirmation_id=? AND status='pending'`, status, id); err != nil {
		return Confirmation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Confirmation{}, err
	}
	return v.Get(ctx, id)
}

func (v ConfirmationView) RevokeSession(ctx context.Context, value ConfirmationRevocation) (int, error) {
	if err := v.ready(); err != nil {
		return 0, err
	}
	if !validSessionKey(value.SessionKey) || value.TeardownOperationID == "" || !validRawJSON(value.RawJSON) {
		return 0, errors.New("confirmation revocation is invalid")
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var previous int
	err = tx.QueryRowContext(ctx, `SELECT revoked_count FROM confirmation_session_revocations WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND teardown_operation_id=?`, value.OwnerSessionHash, value.OwnerUserHash, value.OwnerEnvHash, value.SessionChannelIDHash, value.TeardownOperationID).Scan(&previous)
	if err == nil {
		return previous, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE confirmation_intents SET status='revoked' WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND status='pending'`, value.OwnerSessionHash, value.OwnerUserHash, value.OwnerEnvHash, value.SessionChannelIDHash)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO confirmation_session_revocations(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,teardown_operation_id,revoked_count,revocation_json) VALUES(?,?,?,?,?,?,?)`, value.OwnerSessionHash, value.OwnerUserHash, value.OwnerEnvHash, value.SessionChannelIDHash, value.TeardownOperationID, count, string(value.RawJSON)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(count), nil
}

// PutConfirmationIntentRecord implements security's durable control-store
// boundary without opening or initializing a second SQLite owner.
func (v ConfirmationView) PutConfirmationIntentRecord(ctx context.Context, record security.ConfirmationIntentRecord, now time.Time, options security.ConfirmationIntentStoreOptions) error {
	if err := v.ready(); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM confirmation_intents WHERE status='pending' AND expires_at<=?`, now.UTC().UnixNano()); err != nil {
		return err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM confirmation_intents WHERE confirmation_id=?`, record.ConfirmationID).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		return security.ErrInvalidConfirmationIntent
	}
	counts := []struct {
		query string
		args  []any
		max   int
	}{
		{`SELECT COUNT(*) FROM confirmation_intents WHERE status='pending'`, nil, options.MaxTotal},
		{`SELECT COUNT(*) FROM confirmation_intents WHERE status='pending' AND owner_env_hash=? AND plugin_instance_id=?`, []any{record.Scope.OwnerEnvHash, record.PluginInstanceID}, options.MaxPerOwnerPlugin},
		{`SELECT COUNT(*) FROM confirmation_intents WHERE status='pending' AND owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=?`, []any{record.Scope.OwnerSessionHash, record.Scope.OwnerUserHash, record.Scope.OwnerEnvHash, record.Scope.SessionChannelIDHash}, options.MaxPerSession},
	}
	for _, item := range counts {
		var count int
		if err := tx.QueryRowContext(ctx, item.query, item.args...).Scan(&count); err != nil {
			return err
		}
		if count >= item.max {
			return security.ErrConfirmationIntentCapacity
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO confirmation_intents(confirmation_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,status,expires_at,confirmation_json) VALUES(?,?,?,?,?,?,'pending',?,?)`, record.ConfirmationID, record.PluginInstanceID, record.Scope.OwnerSessionHash, record.Scope.OwnerUserHash, record.Scope.OwnerEnvHash, record.Scope.SessionChannelIDHash, record.ExpiresAt.UTC().UnixNano(), string(raw)); err != nil {
		return err
	}
	return tx.Commit()
}

func (v ConfirmationView) ConsumeConfirmationIntentRecord(ctx context.Context, id string, scope sessionctx.SessionScope, now time.Time) (security.ConfirmationIntentRecord, error) {
	if err := v.ready(); err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	defer tx.Rollback()
	record, err := getConfirmationIntentRecord(ctx, tx, id)
	if errors.Is(err, ErrRecordNotFound) {
		return security.ConfirmationIntentRecord{}, security.ErrConfirmationIntentNotFound
	}
	if err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	if !confirmationRecordMatchesScope(record, scope) {
		return security.ConfirmationIntentRecord{}, security.ErrConfirmationIntentScopeMismatch
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM confirmation_intents WHERE confirmation_id=? AND status='pending'`, id); err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	if !record.ExpiresAt.After(now) {
		return security.ConfirmationIntentRecord{}, security.ErrConfirmationIntentExpired
	}
	return record, nil
}

func (v ConfirmationView) RejectConfirmationIntentRecord(ctx context.Context, req security.RejectConfirmationIntentRequest) (security.ConfirmationIntentRecord, error) {
	if err := v.ready(); err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	defer tx.Rollback()
	record, err := getConfirmationIntentRecord(ctx, tx, req.ConfirmationID)
	if errors.Is(err, ErrRecordNotFound) {
		return security.ConfirmationIntentRecord{}, security.ErrConfirmationIntentNotFound
	}
	if err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	if !record.ExpiresAt.After(req.Now) {
		if _, err := tx.ExecContext(ctx, `DELETE FROM confirmation_intents WHERE confirmation_id=? AND status='pending'`, req.ConfirmationID); err != nil {
			return security.ConfirmationIntentRecord{}, err
		}
		if err := tx.Commit(); err != nil {
			return security.ConfirmationIntentRecord{}, err
		}
		return security.ConfirmationIntentRecord{}, security.ErrConfirmationIntentExpired
	}
	if !confirmationRecordMatchesRejection(record, req) {
		return security.ConfirmationIntentRecord{}, security.ErrConfirmationIntentScopeMismatch
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM confirmation_intents WHERE confirmation_id=? AND status='pending'`, req.ConfirmationID); err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	return record, nil
}

func (v ConfirmationView) ListConfirmationIntentRecords(ctx context.Context, pluginInstanceID string) ([]security.ConfirmationIntentRecord, error) {
	if err := v.ready(); err != nil {
		return nil, err
	}
	query := `SELECT confirmation_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,expires_at,confirmation_json FROM confirmation_intents WHERE status='pending'`
	var args []any
	if pluginInstanceID != "" {
		query += ` AND plugin_instance_id=?`
		args = append(args, pluginInstanceID)
	}
	rows, err := v.store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []security.ConfirmationIntentRecord
	for rows.Next() {
		record, err := scanConfirmationIntentRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (v ConfirmationView) RevokePluginConfirmationIntentRecords(ctx context.Context, ownerEnvHash, pluginInstanceID string) (int, error) {
	if err := v.ready(); err != nil {
		return 0, err
	}
	result, err := v.store.db.ExecContext(ctx, `DELETE FROM confirmation_intents WHERE status='pending' AND owner_env_hash=? AND plugin_instance_id=?`, ownerEnvHash, pluginInstanceID)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	return int(count), err
}

func (v ConfirmationView) RevokeSessionConfirmationIntentRecords(ctx context.Context, scope sessionctx.SessionScope, operationID string, maxRevocations int) (int, error) {
	if err := v.ready(); err != nil {
		return 0, err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var previous int
	err = tx.QueryRowContext(ctx, `SELECT revoked_count FROM confirmation_session_revocations WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND teardown_operation_id=?`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, operationID).Scan(&previous)
	if err == nil {
		return previous, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	var revocations int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM confirmation_session_revocations`).Scan(&revocations); err != nil {
		return 0, err
	}
	if revocations >= maxRevocations {
		return 0, security.ErrConfirmationIntentCapacity
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM confirmation_intents WHERE status='pending' AND owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=?`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	raw, err := json.Marshal(map[string]any{"teardown_operation_id": operationID, "revoked_count": count})
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO confirmation_session_revocations(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,teardown_operation_id,revoked_count,revocation_json) VALUES(?,?,?,?,?,?,?)`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, operationID, count, string(raw)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(count), nil
}

func (v ConfirmationView) FinalizeSessionConfirmationIntentRevocation(ctx context.Context, scope sessionctx.SessionScope, operationID string) error {
	if err := v.ready(); err != nil {
		return err
	}
	_, err := v.store.db.ExecContext(ctx, `DELETE FROM confirmation_session_revocations WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND teardown_operation_id=?`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, operationID)
	return err
}

type confirmationIntentScanner interface{ Scan(...any) error }

func getConfirmationIntentRecord(ctx context.Context, tx *sql.Tx, id string) (security.ConfirmationIntentRecord, error) {
	return scanConfirmationIntentRecord(tx.QueryRowContext(ctx, `SELECT confirmation_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,expires_at,confirmation_json FROM confirmation_intents WHERE confirmation_id=? AND status='pending'`, id))
}

func scanConfirmationIntentRecord(row confirmationIntentScanner) (security.ConfirmationIntentRecord, error) {
	var id, pluginID, ownerSession, ownerUser, ownerEnv, channel, raw string
	var expiresAt int64
	if err := row.Scan(&id, &pluginID, &ownerSession, &ownerUser, &ownerEnv, &channel, &expiresAt, &raw); errors.Is(err, sql.ErrNoRows) {
		return security.ConfirmationIntentRecord{}, ErrRecordNotFound
	} else if err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	var record security.ConfirmationIntentRecord
	if err := jsonvalue.DecodeClosed([]byte(raw), &record); err != nil {
		return security.ConfirmationIntentRecord{}, fmt.Errorf("%w: invalid confirmation record", ErrStateConflict)
	}
	if record.Scope.OwnerSessionHash == "" && record.Scope.OwnerUserHash == "" && record.Scope.OwnerEnvHash == "" && record.Scope.SessionChannelIDHash == "" {
		record.Scope.OwnerSessionHash, record.Scope.OwnerUserHash = ownerSession, ownerUser
		record.Scope.OwnerEnvHash, record.Scope.SessionChannelIDHash = ownerEnv, channel
	}
	if record.ConfirmationID != id || record.PluginInstanceID != pluginID || record.Scope.OwnerSessionHash != ownerSession || record.Scope.OwnerUserHash != ownerUser || record.Scope.OwnerEnvHash != ownerEnv || record.Scope.SessionChannelIDHash != channel || record.ExpiresAt.UTC().UnixNano() != expiresAt {
		return security.ConfirmationIntentRecord{}, fmt.Errorf("%w: confirmation owner mismatch", ErrStateConflict)
	}
	return record, nil
}

func confirmationRecordMatchesScope(record security.ConfirmationIntentRecord, scope sessionctx.SessionScope) bool {
	return scope.Valid() && record.Scope.OwnerSessionHash == scope.OwnerSessionHash && record.Scope.OwnerUserHash == scope.OwnerUserHash && record.Scope.OwnerEnvHash == scope.OwnerEnvHash && record.Scope.SessionChannelIDHash == scope.SessionChannelIDHash
}

func confirmationRecordMatchesRejection(record security.ConfirmationIntentRecord, req security.RejectConfirmationIntentRequest) bool {
	return record.PluginInstanceID == req.PluginInstanceID && record.SurfaceInstanceID == req.SurfaceInstanceID && record.BridgeChannelID == req.BridgeChannelID && record.Scope.ActiveFingerprint == req.ActiveFingerprint && record.Scope.OwnerSessionHash == req.OwnerSessionHash && record.Scope.OwnerUserHash == req.OwnerUserHash && record.Scope.OwnerEnvHash == req.OwnerEnvHash && record.Scope.SessionChannelIDHash == req.SessionChannelIDHash && record.Scope.PolicyRevision == req.PolicyRevision && record.Scope.ManagementRevision == req.ManagementRevision && record.Scope.RevokeEpoch == req.RevokeEpoch
}

var _ security.ConfirmationIntentControlStore = ConfirmationView{}

type SessionKey struct {
	OwnerSessionHash     string
	OwnerUserHash        string
	OwnerEnvHash         string
	SessionChannelIDHash string
}

type SessionFence struct {
	SessionKey
	State       string
	ProofSHA256 []byte
	UpdatedAt   int64
	RawJSON     json.RawMessage
}

type SessionPhase struct {
	SessionKey
	Phase   string
	RawJSON json.RawMessage
}

const sessionIdentitySecretMetadataKey = "session_identity_secret_v1"

// DeriveSessionTeardownIdentity returns stable opaque material for one exact
// four-hash session scope. The only durable secret is Host-owned metadata;
// per-session lifecycle state remains solely in the session fence tables.
func (v SessionView) DeriveSessionTeardownIdentity(ctx context.Context, key SessionKey) (string, []byte, error) {
	if err := v.ready(); err != nil {
		return "", nil, err
	}
	if !validSessionKey(key) {
		return "", nil, errors.New("session key is invalid")
	}
	secret, err := v.sessionIdentitySecret(ctx)
	if err != nil {
		return "", nil, err
	}
	digest := hmac.New(sha256.New, secret)
	_, _ = digest.Write([]byte("redevplugin/session-teardown-identity/v1\x00"))
	for _, value := range []string{key.OwnerSessionHash, key.OwnerUserHash, key.OwnerEnvHash, key.SessionChannelIDHash} {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	proof := digest.Sum(nil)
	return "session-close-" + hex.EncodeToString(proof[:16]), proof, nil
}

func (v SessionView) sessionIdentitySecret(ctx context.Context) ([]byte, error) {
	secret := make([]byte, sha256.Size)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(hex.EncodeToString(secret))
	if err != nil {
		return nil, err
	}
	if _, err := v.store.db.ExecContext(ctx, `INSERT OR IGNORE INTO control_metadata(key,value_json) VALUES(?,?)`, sessionIdentitySecretMetadataKey, string(encoded)); err != nil {
		return nil, err
	}
	var raw string
	if err := v.store.db.QueryRowContext(ctx, `SELECT value_json FROM control_metadata WHERE key=?`, sessionIdentitySecretMetadataKey).Scan(&raw); err != nil {
		return nil, err
	}
	var stored string
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return nil, fmt.Errorf("%w: session identity secret", ErrStateConflict)
	}
	decoded, err := hex.DecodeString(stored)
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("%w: session identity secret", ErrStateConflict)
	}
	return decoded, nil
}

func (v SessionView) PutFence(ctx context.Context, value SessionFence) error {
	if err := v.ready(); err != nil {
		return err
	}
	if !validSessionKey(value.SessionKey) || value.State == "" || !validRawJSON(value.RawJSON) {
		return errors.New("session fence is invalid")
	}
	_, err := v.store.db.ExecContext(ctx, `INSERT INTO session_fences(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,state,fence_json,proof_sha256,updated_at) VALUES(?,?,?,?,?,?,?,?)`, value.OwnerSessionHash, value.OwnerUserHash, value.OwnerEnvHash, value.SessionChannelIDHash, value.State, string(value.RawJSON), value.ProofSHA256, value.UpdatedAt)
	return err
}

func (v SessionView) TransitionFence(ctx context.Context, value SessionFence, expectedState string) error {
	if err := v.ready(); err != nil {
		return err
	}
	if !validSessionKey(value.SessionKey) || expectedState == "" || value.State == "" || expectedState == value.State || !validRawJSON(value.RawJSON) {
		return errors.New("session transition is invalid")
	}
	result, err := v.store.db.ExecContext(ctx, `UPDATE session_fences SET state=?,fence_json=?,proof_sha256=?,updated_at=? WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND state=?`, value.State, string(value.RawJSON), value.ProofSHA256, value.UpdatedAt, value.OwnerSessionHash, value.OwnerUserHash, value.OwnerEnvHash, value.SessionChannelIDHash, expectedState)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrStateConflict
	}
	return nil
}

func (v SessionView) PutPhase(ctx context.Context, value SessionPhase) error {
	if err := v.ready(); err != nil {
		return err
	}
	if !validSessionKey(value.SessionKey) || value.Phase == "" || !validRawJSON(value.RawJSON) {
		return errors.New("session phase is invalid")
	}
	result, err := v.store.db.ExecContext(ctx, `INSERT INTO session_teardown_phases(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,phase,phase_json) VALUES(?,?,?,?,?,?) ON CONFLICT(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,phase) DO NOTHING`, value.OwnerSessionHash, value.OwnerUserHash, value.OwnerEnvHash, value.SessionChannelIDHash, value.Phase, string(value.RawJSON))
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 1 {
		return nil
	}
	var raw string
	if err := v.store.db.QueryRowContext(ctx, `SELECT phase_json FROM session_teardown_phases WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND phase=?`, value.OwnerSessionHash, value.OwnerUserHash, value.OwnerEnvHash, value.SessionChannelIDHash, value.Phase).Scan(&raw); err != nil {
		return err
	}
	if !jsonEqual([]byte(raw), value.RawJSON) {
		return ErrStateConflict
	}
	return nil
}

func (v SessionView) Get(ctx context.Context, key SessionKey) (SessionFence, []SessionPhase, error) {
	if err := v.ready(); err != nil {
		return SessionFence{}, nil, err
	}
	var fence SessionFence
	var raw string
	err := v.store.db.QueryRowContext(ctx, `SELECT state,fence_json,proof_sha256,updated_at FROM session_fences WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=?`, key.OwnerSessionHash, key.OwnerUserHash, key.OwnerEnvHash, key.SessionChannelIDHash).Scan(&fence.State, &raw, &fence.ProofSHA256, &fence.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionFence{}, nil, ErrRecordNotFound
	}
	if err != nil {
		return SessionFence{}, nil, err
	}
	fence.SessionKey, fence.RawJSON = key, json.RawMessage(raw)
	rows, err := v.store.db.QueryContext(ctx, `SELECT phase,phase_json FROM session_teardown_phases WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? ORDER BY phase`, key.OwnerSessionHash, key.OwnerUserHash, key.OwnerEnvHash, key.SessionChannelIDHash)
	if err != nil {
		return SessionFence{}, nil, err
	}
	defer rows.Close()
	var phases []SessionPhase
	for rows.Next() {
		var phase SessionPhase
		if err := rows.Scan(&phase.Phase, &raw); err != nil {
			return SessionFence{}, nil, err
		}
		phase.SessionKey, phase.RawJSON = key, json.RawMessage(raw)
		phases = append(phases, phase)
	}
	return fence, phases, rows.Err()
}

func (v SessionView) GetSessionControlRecord(ctx context.Context, scope sessionctx.SessionScope) (sessionscope.ControlRecord, error) {
	if err := v.ready(); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	record, err := getSessionControlRecord(ctx, v.store.db, scope)
	if errors.Is(err, ErrRecordNotFound) {
		return sessionscope.ControlRecord{}, sessionscope.ErrScopeNotFound
	}
	return record, err
}

func (v SessionView) ListSessionControlRecords(ctx context.Context) ([]sessionscope.ControlRecord, error) {
	if err := v.ready(); err != nil {
		return nil, err
	}
	rows, err := v.store.db.QueryContext(ctx, sessionControlSelect+` ORDER BY owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []sessionscope.ControlRecord
	for rows.Next() {
		record, err := scanSessionControlRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range records {
		phases, err := listSessionControlPhases(ctx, v.store.db, records[index].Scope)
		if err != nil {
			return nil, err
		}
		records[index].Phases = phases
	}
	return records, nil
}

func (v SessionView) BeginSessionControlTeardown(ctx context.Context, proposed sessionscope.ControlRecord, maxScopes int) (sessionscope.ControlRecord, error) {
	if err := v.ready(); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	defer tx.Rollback()
	current, err := getSessionControlRecord(ctx, tx, proposed.Scope)
	if errors.Is(err, ErrRecordNotFound) {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM session_fences`).Scan(&count); err != nil {
			return sessionscope.ControlRecord{}, err
		}
		if count >= maxScopes {
			return sessionscope.ControlRecord{}, sessionscope.ErrFenceCapacity
		}
		if err := insertSessionControlRecord(ctx, tx, proposed); err != nil {
			return sessionscope.ControlRecord{}, err
		}
		if err := tx.Commit(); err != nil {
			return sessionscope.ControlRecord{}, err
		}
		return proposed, nil
	}
	if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	if current.TeardownOperationID != proposed.TeardownOperationID || !bytes.Equal(current.ProofSHA256, proposed.ProofSHA256) {
		return sessionscope.ControlRecord{}, sessionscope.ErrTeardownIdentityMismatch
	}
	switch current.State {
	case sessionscope.StateDraining, sessionscope.StateIncomplete:
		current.State, current.UpdatedAt = sessionscope.StateDraining, proposed.UpdatedAt
		if err := updateSessionControlRecord(ctx, tx, current); err != nil {
			return sessionscope.ControlRecord{}, err
		}
	case sessionscope.StateComplete:
	default:
		return sessionscope.ControlRecord{}, sessionscope.ErrInvalidState
	}
	if err := tx.Commit(); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	return current, nil
}

func (v SessionView) AccumulateSessionControl(ctx context.Context, scope sessionctx.SessionScope, delta sessionscope.Counts, now time.Time) (sessionscope.ControlRecord, error) {
	return v.updateSessionControl(ctx, scope, now, func(current *sessionscope.ControlRecord) error {
		if current.State != sessionscope.StateDraining {
			return sessionscope.ErrInvalidState
		}
		counts, err := current.Counts.Add(delta)
		if err != nil {
			return err
		}
		current.Counts = counts
		return nil
	})
}

func (v SessionView) AccumulateSessionControlPhase(ctx context.Context, scope sessionctx.SessionScope, phase sessionscope.Phase, delta sessionscope.Counts, now time.Time) (sessionscope.ControlRecord, error) {
	if err := v.ready(); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	defer tx.Rollback()
	current, err := getSessionControlRecord(ctx, tx, scope)
	if errors.Is(err, ErrRecordNotFound) {
		return sessionscope.ControlRecord{}, sessionscope.ErrScopeNotFound
	}
	if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	if current.State != sessionscope.StateDraining {
		return sessionscope.ControlRecord{}, sessionscope.ErrInvalidState
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT phase_json FROM session_teardown_phases WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND phase=?`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, phase).Scan(&existing)
	if err == nil {
		if _, err := decodeSessionPhaseCounts(existing, phase); err != nil {
			return sessionscope.ControlRecord{}, err
		}
		return current, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return sessionscope.ControlRecord{}, err
	}
	counts, err := current.Counts.Add(delta)
	if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	current.Counts, current.UpdatedAt = counts, now.UTC()
	if err := updateSessionControlRecord(ctx, tx, current); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	raw, err := json.Marshal(delta)
	if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_teardown_phases(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,phase,phase_json) VALUES(?,?,?,?,?,?)`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, phase, string(raw)); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	if current.Phases == nil {
		current.Phases = map[sessionscope.Phase]sessionscope.Counts{}
	}
	current.Phases[phase] = delta
	return current, nil
}

func (v SessionView) TransitionSessionControl(ctx context.Context, scope sessionctx.SessionScope, expected, next sessionscope.State, now time.Time) (sessionscope.ControlRecord, error) {
	return v.updateSessionControl(ctx, scope, now, func(current *sessionscope.ControlRecord) error {
		if current.State == next && (next == sessionscope.StateIncomplete || next == sessionscope.StateComplete) {
			return nil
		}
		if current.State != expected {
			return sessionscope.ErrInvalidState
		}
		current.State = next
		return nil
	})
}

func (v SessionView) FinalizeSessionControl(ctx context.Context, scope sessionctx.SessionScope, operationID string, proof []byte) error {
	if err := v.ready(); err != nil {
		return err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := getSessionControlRecord(ctx, tx, scope)
	if err != nil || current.State != sessionscope.StateComplete || current.TeardownOperationID != operationID || !bytes.Equal(current.ProofSHA256, proof) {
		return sessionscope.ErrClosedSessionProofInvalid
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM session_teardown_phases WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=?`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM session_fences WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND state=? AND proof_sha256=?`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, sessionscope.StateComplete, proof)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sessionscope.ErrClosedSessionProofInvalid
	}
	return tx.Commit()
}

func (v SessionView) updateSessionControl(ctx context.Context, scope sessionctx.SessionScope, now time.Time, apply func(*sessionscope.ControlRecord) error) (sessionscope.ControlRecord, error) {
	if err := v.ready(); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	defer tx.Rollback()
	current, err := getSessionControlRecord(ctx, tx, scope)
	if errors.Is(err, ErrRecordNotFound) {
		return sessionscope.ControlRecord{}, sessionscope.ErrScopeNotFound
	}
	if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	if err := apply(&current); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	current.UpdatedAt = now.UTC()
	if err := updateSessionControlRecord(ctx, tx, current); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return sessionscope.ControlRecord{}, err
	}
	return current, nil
}

const sessionControlSelect = `SELECT owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,state,fence_json,proof_sha256,updated_at FROM session_fences`

type sessionControlQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type sessionControlScanner interface{ Scan(...any) error }

func getSessionControlRecord(ctx context.Context, query sessionControlQuerier, scope sessionctx.SessionScope) (sessionscope.ControlRecord, error) {
	record, err := scanSessionControlRecord(query.QueryRowContext(ctx, sessionControlSelect+` WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=?`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash))
	if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	phases, err := listSessionControlPhases(ctx, query, scope)
	if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	record.Phases = phases
	return record, nil
}

func scanSessionControlRecord(row sessionControlScanner) (sessionscope.ControlRecord, error) {
	var ownerSession, ownerUser, ownerEnv, channel, state, raw string
	var proof []byte
	var updatedAt int64
	if err := row.Scan(&ownerSession, &ownerUser, &ownerEnv, &channel, &state, &raw, &proof, &updatedAt); errors.Is(err, sql.ErrNoRows) {
		return sessionscope.ControlRecord{}, ErrRecordNotFound
	} else if err != nil {
		return sessionscope.ControlRecord{}, err
	}
	var record sessionscope.ControlRecord
	if err := jsonvalue.DecodeClosed([]byte(raw), &record); err != nil {
		return sessionscope.ControlRecord{}, sessionscope.ErrInvalidState
	}
	if record.State != sessionscope.State(state) || !bytes.Equal(record.ProofSHA256, proof) {
		return sessionscope.ControlRecord{}, sessionscope.ErrInvalidState
	}
	record.Scope = sessionctx.SessionScope{OwnerSessionHash: ownerSession, OwnerUserHash: ownerUser, OwnerEnvHash: ownerEnv, SessionChannelIDHash: channel}
	record.State, record.ProofSHA256 = sessionscope.State(state), append([]byte(nil), proof...)
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = time.Unix(0, updatedAt).UTC()
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = record.UpdatedAt
	}
	if record.Scope.Validate() != nil || !record.State.Valid() || !record.Counts.Valid() || record.TeardownOperationID == "" || len(record.ProofSHA256) != sha256.Size || record.UpdatedAt.UnixNano() != updatedAt {
		return sessionscope.ControlRecord{}, sessionscope.ErrInvalidState
	}
	return record, nil
}

func listSessionControlPhases(ctx context.Context, query interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, scope sessionctx.SessionScope) (map[sessionscope.Phase]sessionscope.Counts, error) {
	rows, err := query.QueryContext(ctx, `SELECT phase,phase_json FROM session_teardown_phases WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? ORDER BY phase`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	phases := map[sessionscope.Phase]sessionscope.Counts{}
	for rows.Next() {
		var phase sessionscope.Phase
		var raw string
		if err := rows.Scan(&phase, &raw); err != nil {
			return nil, err
		}
		counts, err := decodeSessionPhaseCounts(raw, phase)
		if err != nil || !phase.Valid() {
			return nil, sessionscope.ErrInvalidCounts
		}
		phases[phase] = counts
	}
	return phases, rows.Err()
}

func decodeSessionPhaseCounts(raw string, phase sessionscope.Phase) (sessionscope.Counts, error) {
	var counts sessionscope.Counts
	if err := jsonvalue.DecodeClosed([]byte(raw), &counts); err != nil || !counts.Valid() {
		return sessionscope.Counts{}, sessionscope.ErrInvalidCounts
	}
	return counts, nil
}

func insertSessionControlRecord(ctx context.Context, tx *sql.Tx, record sessionscope.ControlRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO session_fences(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,state,fence_json,proof_sha256,updated_at) VALUES(?,?,?,?,?,?,?,?)`, record.Scope.OwnerSessionHash, record.Scope.OwnerUserHash, record.Scope.OwnerEnvHash, record.Scope.SessionChannelIDHash, record.State, string(raw), record.ProofSHA256, record.UpdatedAt.UTC().UnixNano())
	return err
}

func updateSessionControlRecord(ctx context.Context, tx *sql.Tx, record sessionscope.ControlRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE session_fences SET state=?,fence_json=?,proof_sha256=?,updated_at=? WHERE owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=?`, record.State, string(raw), record.ProofSHA256, record.UpdatedAt.UTC().UnixNano(), record.Scope.OwnerSessionHash, record.Scope.OwnerUserHash, record.Scope.OwnerEnvHash, record.Scope.SessionChannelIDHash)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return sessionscope.ErrScopeNotFound
	}
	return nil
}

var _ sessionscope.ControlStore = SessionView{}

func (v RegistryView) ready() error     { return viewReady(v.store) }
func (v ExecutionView) ready() error    { return viewReady(v.store) }
func (v ConfirmationView) ready() error { return viewReady(v.store) }
func (v SessionView) ready() error      { return viewReady(v.store) }

func viewReady(store *Store) error {
	if store == nil {
		return ErrRequestsBlocked
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if !store.ready {
		return ErrRequestsBlocked
	}
	return nil
}

func validRawJSON(value json.RawMessage) bool { return len(value) > 0 && json.Valid(value) }
func validSessionKey(value SessionKey) bool {
	return value.OwnerSessionHash != "" && value.OwnerUserHash != "" && value.OwnerEnvHash != "" && value.SessionChannelIDHash != ""
}
func optionalInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}
func optionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().UnixNano()
}
func nullIntPointer(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}
func nullTimePointer(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	result := time.Unix(0, value.Int64).UTC()
	return &result
}

func normalizedUnixNano(value time.Time) int64 {
	if value.IsZero() {
		value = time.Now().UTC()
	}
	return value.UTC().UnixNano()
}

func jsonEqual(left, right []byte) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	leftCanonical, _ := json.Marshal(leftValue)
	rightCanonical, _ := json.Marshal(rightValue)
	return string(leftCanonical) == string(rightCanonical)
}
