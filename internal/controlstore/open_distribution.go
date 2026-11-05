package controlstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/floegence/redevplugin/v3/internal/canonicaljson"
)

// Schema seven removes retired admission metadata without changing package,
// manifest, grant, data-generation, execution, or owner identities. This is a
// one-time storage transition; current readers accept only the current record.
func migrateOpenDistribution(ctx context.Context, q dataHistoryMigrator) error {
	for _, table := range []string{"plugin_records", "plugin_data_history"} {
		rows, err := q.QueryContext(ctx, "SELECT rowid,record_json FROM "+table)
		if err != nil {
			return err
		}
		type update struct {
			id  int64
			raw string
		}
		var updates []update
		for rows.Next() {
			var id int64
			var raw string
			if err = rows.Scan(&id, &raw); err != nil {
				rows.Close()
				return err
			}
			normalized, e := normalizeReleasedPluginRecord([]byte(raw))
			if e != nil {
				rows.Close()
				return e
			}
			if _, e = decodeRegistryPluginRecord(normalized); e != nil {
				rows.Close()
				return e
			}
			if string(normalized) != raw {
				updates = append(updates, update{id, string(normalized)})
			}
		}
		err = errors.Join(rows.Err(), rows.Close())
		if err != nil {
			return err
		}
		for _, item := range updates {
			if _, err = q.ExecContext(ctx, "UPDATE "+table+" SET record_json=? WHERE rowid=?", item.raw, item.id); err != nil {
				return err
			}
		}
	}
	_, err := q.ExecContext(ctx, "UPDATE control_schema SET version=7 WHERE id=1 AND version=6")
	return err
}

func normalizeReleasedPluginRecord(raw []byte) ([]byte, error) {
	// Validate duplicate keys before dropping only the documented retired fields.
	if _, err := canonicaljson.CanonicalJSON(raw); err != nil {
		return nil, fmt.Errorf("%w: plugin record: %v", ErrIncompatible, err)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	if record == nil {
		return nil, ErrIncompatible
	}
	stripReleasedAdmissionFields(record)
	if history, ok := record["version_history"]; ok {
		var versions []map[string]json.RawMessage
		if err := json.Unmarshal(history, &versions); err != nil {
			return nil, err
		}
		for _, version := range versions {
			if version == nil {
				return nil, ErrIncompatible
			}
			stripReleasedAdmissionFields(version)
		}
		encoded, err := json.Marshal(versions)
		if err != nil {
			return nil, err
		}
		record["version_history"] = encoded
	}
	return json.Marshal(record)
}

func stripReleasedAdmissionFields(record map[string]json.RawMessage) {
	// Retired signer eligibility was not a user preference. Never inherit it.
	record["update_eligibility"] = json.RawMessage(`"manual_only"`)
	if _, present := record["automatic_updates"]; present {
		record["automatic_updates"] = json.RawMessage(`false`)
	}
	for _, key := range []string{"trust_state", "trust_assessment", "signature_assessment", "release_trust_binding", "local_import_provenance"} {
		delete(record, key)
	}
	var source map[string]json.RawMessage
	if json.Unmarshal(record["source_provenance"], &source) == nil && source != nil {
		var kind string
		if json.Unmarshal(source["kind"], &kind) == nil && (kind == "official_catalog" || kind == "approved_catalog" || kind == "local_generated") {
			// Old catalog records did not retain a retrievable package URL. Keep their
			// source reference for diagnostics and require explicit source selection.
			source["kind"] = json.RawMessage(`"local_package"`)
			record["source_provenance"], _ = json.Marshal(source)
			record["update_eligibility"] = json.RawMessage(`"manual_only"`)
		}
	}
}
