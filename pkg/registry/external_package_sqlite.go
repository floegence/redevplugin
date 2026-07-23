package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
)

func (s *SQLiteStore) CommitExternalPackage(ctx context.Context, req CommitExternalPackageRequest) (ExternalPackageCommitResult, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	if err := validateExternalPackageCommit(ownerEnvHash, req); err != nil {
		return ExternalPackageCommitResult{}, err
	}
	requestSHA256, err := externalPackageRequestSHA256(req)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	existingReceipt, exists, err := getSQLiteExternalPackageCommit(ctx, s.db, ownerEnvHash, req.InspectionID)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	if exists {
		if existingReceipt.RequestSHA256 != requestSHA256 {
			return ExternalPackageCommitResult{}, ErrExternalPackageCommitConflict
		}
		if existingReceipt.Result.Status == ExternalPackageCommitted || existingReceipt.Result.Status == ExternalPackageFailed {
			return cloneExternalPackageCommitResult(existingReceipt.Result)
		}
	} else {
		now := req.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return ExternalPackageCommitResult{}, err
		}
		defer rollbackUnlessCommitted(tx)
		var duplicateInspection string
		err = tx.QueryRowContext(ctx, `
SELECT inspection_id FROM external_package_commit_receipts
WHERE owner_env_hash = ? AND commit_id = ?`, ownerEnvHash, req.CommitID).Scan(&duplicateInspection)
		if err == nil {
			return ExternalPackageCommitResult{}, ErrExternalPackageCommitConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ExternalPackageCommitResult{}, err
		}
		current, currentExists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, req.Record.PluginInstanceID, true)
		if err != nil {
			return ExternalPackageCommitResult{}, err
		}
		if _, err := prepareExternalPackageRecord(ownerEnvHash, req, current, currentExists, now); err != nil {
			return ExternalPackageCommitResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO external_package_commit_receipts (
    owner_env_hash, inspection_id, commit_id, intent, confirmation_digest, request_sha256,
    expected_management_revision, intended_fingerprint, intended_package_sha256,
    plugin_instance_id, status, mutation_outcome, record_snapshot_json, failure_code,
    created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'null', '', ?, ?)`,
			ownerEnvHash, req.InspectionID, req.CommitID, string(req.Intent), req.ConfirmationDigest, requestSHA256,
			req.ExpectedManagementRevision, req.IntendedFingerprint, req.IntendedPackageSHA256,
			req.Record.PluginInstanceID, string(ExternalPackageCommitting), string(mutation.OutcomeUnknown),
			now.UnixNano(), now.UnixNano(),
		); err != nil {
			return ExternalPackageCommitResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return ExternalPackageCommitResult{}, mutation.Unknown(err)
		}
		existingReceipt = externalPackageCommitReceipt{
			OwnerEnvHash:  ownerEnvHash,
			RequestSHA256: requestSHA256,
			Request:       req,
			Result: ExternalPackageCommitResult{
				InspectionID: req.InspectionID, CommitID: req.CommitID, Intent: req.Intent,
				PluginInstanceID: req.Record.PluginInstanceID, ExpectedManagementRevision: req.ExpectedManagementRevision,
				IntendedFingerprint: req.IntendedFingerprint, IntendedPackageSHA256: req.IntendedPackageSHA256,
				Status: ExternalPackageCommitting, MutationOutcome: mutation.OutcomeUnknown,
				CreatedAt: now, UpdatedAt: now,
			},
		}
	}

	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	defer rollbackUnlessCommitted(tx)
	current, currentExists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, req.Record.PluginInstanceID, true)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	record, err := prepareExternalPackageRecord(ownerEnvHash, req, current, currentExists, now)
	if err != nil {
		return existingReceipt.Result, err
	}
	if err := upsertSQLitePlugin(ctx, tx, record); err != nil {
		return existingReceipt.Result, err
	}
	snapshotJSON, err := encodeRegistryJSON(record)
	if err != nil {
		return existingReceipt.Result, err
	}
	result := existingReceipt.Result
	result.Status = ExternalPackageCommitted
	result.MutationOutcome = mutation.OutcomeCommitted
	result.RecordSnapshot = &record
	result.UpdatedAt = now
	updateResult, err := tx.ExecContext(ctx, `
UPDATE external_package_commit_receipts
SET status = ?, mutation_outcome = ?, record_snapshot_json = ?, failure_code = '', updated_at = ?
WHERE owner_env_hash = ? AND inspection_id = ? AND commit_id = ? AND status = ?`,
		string(result.Status), string(result.MutationOutcome), snapshotJSON, now.UnixNano(),
		ownerEnvHash, req.InspectionID, req.CommitID, string(ExternalPackageCommitting),
	)
	if err != nil {
		return existingReceipt.Result, err
	}
	affected, err := updateResult.RowsAffected()
	if err != nil {
		return existingReceipt.Result, err
	}
	if affected != 1 {
		return ExternalPackageCommitResult{}, ErrExternalPackageCommitConflict
	}
	if err := s.commitTx(tx); err != nil {
		// The driver may report an error after crossing the durable commit point.
		// Callers reconcile through QueryExternalPackageCommit using the same IDs.
		result.Status = ExternalPackageCommitting
		result.MutationOutcome = mutation.OutcomeUnknown
		result.RecordSnapshot = nil
		return result, mutation.Unknown(err)
	}
	return cloneExternalPackageCommitResult(result)
}

func (s *SQLiteStore) QueryExternalPackageCommit(ctx context.Context, req QueryExternalPackageCommitRequest) (ExternalPackageCommitResult, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	if strings.TrimSpace(req.InspectionID) == "" {
		return ExternalPackageCommitResult{}, fmt.Errorf("%w: inspection_id is required", ErrInvalidExternalPackageCommit)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, exists, err := getSQLiteExternalPackageCommit(ctx, s.db, ownerEnvHash, req.InspectionID)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	if !exists || (req.CommitID != "" && req.CommitID != receipt.Request.CommitID) {
		return ExternalPackageCommitResult{}, ErrExternalPackageCommitNotFound
	}
	return cloneExternalPackageCommitResult(receipt.Result)
}

func getSQLiteExternalPackageCommit(ctx context.Context, q sqliteQuerier, ownerEnvHash, inspectionID string) (externalPackageCommitReceipt, bool, error) {
	var receipt externalPackageCommitReceipt
	var intent, status, outcome, snapshotJSON string
	var createdAt, updatedAt int64
	err := q.QueryRowContext(ctx, `
SELECT commit_id, intent, confirmation_digest, request_sha256, expected_management_revision,
       intended_fingerprint, intended_package_sha256, plugin_instance_id,
       status, mutation_outcome, record_snapshot_json, failure_code, created_at, updated_at
FROM external_package_commit_receipts
WHERE owner_env_hash = ? AND inspection_id = ?`, ownerEnvHash, inspectionID).Scan(
		&receipt.Request.CommitID, &intent, &receipt.Request.ConfirmationDigest, &receipt.RequestSHA256,
		&receipt.Request.ExpectedManagementRevision, &receipt.Request.IntendedFingerprint,
		&receipt.Request.IntendedPackageSHA256, &receipt.Request.Record.PluginInstanceID,
		&status, &outcome, &snapshotJSON, &receipt.Result.FailureCode, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return externalPackageCommitReceipt{}, false, nil
	}
	if err != nil {
		return externalPackageCommitReceipt{}, false, err
	}
	receipt.OwnerEnvHash = ownerEnvHash
	receipt.Request.InspectionID = inspectionID
	receipt.Request.Intent = ExternalPackageCommitIntent(intent)
	receipt.Result = ExternalPackageCommitResult{
		InspectionID: inspectionID, CommitID: receipt.Request.CommitID, Intent: receipt.Request.Intent,
		PluginInstanceID: receipt.Request.Record.PluginInstanceID, ExpectedManagementRevision: receipt.Request.ExpectedManagementRevision,
		IntendedFingerprint: receipt.Request.IntendedFingerprint, IntendedPackageSHA256: receipt.Request.IntendedPackageSHA256,
		Status: ExternalPackageCommitStatus(status), MutationOutcome: mutation.Outcome(outcome),
		FailureCode: receipt.Result.FailureCode, CreatedAt: unixToTime(createdAt), UpdatedAt: unixToTime(updatedAt),
	}
	switch receipt.Result.Status {
	case ExternalPackageCommitting, ExternalPackageFailed:
		if snapshotJSON != "null" {
			return externalPackageCommitReceipt{}, false, fmt.Errorf("external package receipt %q non-committed snapshot must be canonical null", inspectionID)
		}
	case ExternalPackageCommitted:
		if strings.TrimSpace(snapshotJSON) == "" || strings.TrimSpace(snapshotJSON) == "null" {
			return externalPackageCommitReceipt{}, false, fmt.Errorf("external package receipt %q committed snapshot must be an object", inspectionID)
		}
		var snapshot PluginRecord
		if err := decodeRegistryJSON(snapshotJSON, &snapshot); err != nil {
			return externalPackageCommitReceipt{}, false, err
		}
		snapshot.OwnerEnvHash = ownerEnvHash
		if err := validatePersistedPluginSecurityFacts(snapshot); err != nil {
			return externalPackageCommitReceipt{}, false, err
		}
		receipt.Result.RecordSnapshot = &snapshot
	}
	if err := validatePersistedExternalPackageReceipt(receipt); err != nil {
		return externalPackageCommitReceipt{}, false, err
	}
	return receipt, true, nil
}
