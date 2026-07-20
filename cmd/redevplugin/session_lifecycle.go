package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
)

const cliClosedSessionsSchemaVersion = "redevplugin.cli-closed-sessions.v1"

const cliClosedSessionsMaxBytes int64 = 128 << 20

type cliSessionLifecycleRecord struct {
	identity sessionscope.TeardownIdentity
	proof    []byte
	closed   bool
}

type cliSessionLifecycleAdapter struct {
	mu      sync.Mutex
	records map[sessionctx.SessionScope]cliSessionLifecycleRecord
	write   func([]byte) error
}

type cliClosedSessionsDocument struct {
	SchemaVersion string                   `json:"schema_version"`
	Records       []cliClosedSessionRecord `json:"records"`
}

type cliClosedSessionRecord struct {
	OwnerSessionHash     string `json:"owner_session_hash"`
	OwnerUserHash        string `json:"owner_user_hash"`
	OwnerEnvHash         string `json:"owner_env_hash"`
	SessionChannelIDHash string `json:"session_channel_id_hash"`
	OperationID          string `json:"operation_id"`
	ProofBase64          string `json:"proof_base64"`
	Closed               bool   `json:"closed"`
}

func newCLISessionLifecycleAdapter(path string) (*cliSessionLifecycleAdapter, error) {
	path = filepath.Clean(path)
	if path == "." || !filepath.IsAbs(path) {
		return nil, errors.New("CLI closed session path must be absolute")
	}
	adapter := &cliSessionLifecycleAdapter{records: make(map[sessionctx.SessionScope]cliSessionLifecycleRecord)}
	adapter.write = func(raw []byte) error {
		return writeCLIClosedSessionsState(path, raw, syncCLIClosedSessionsDirectory)
	}
	if err := validateCLIStateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return adapter, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("CLI closed session state must be a private regular file")
	}
	stateFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	openedInfo, err := stateFile.Stat()
	if err != nil {
		_ = stateFile.Close()
		return nil, err
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 {
		_ = stateFile.Close()
		return nil, errors.New("CLI closed session state changed during secure open")
	}
	if openedInfo.Size() > cliClosedSessionsMaxBytes {
		_ = stateFile.Close()
		return nil, errors.New("CLI closed session state exceeds the size limit")
	}
	raw, err := io.ReadAll(io.LimitReader(stateFile, cliClosedSessionsMaxBytes+1))
	if closeErr := stateFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > cliClosedSessionsMaxBytes {
		return nil, errors.New("CLI closed session state exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document cliClosedSessionsDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("CLI closed session document contains trailing JSON")
		}
		return nil, err
	}
	if document.SchemaVersion != cliClosedSessionsSchemaVersion {
		return nil, errors.New("CLI closed session schema version is unsupported")
	}
	if len(document.Records) > sessionscope.HardMaxScopes {
		return nil, errors.New("CLI closed session state exceeds the record limit")
	}
	for _, encoded := range document.Records {
		scope := sessionctx.SessionScope{
			OwnerSessionHash: encoded.OwnerSessionHash, OwnerUserHash: encoded.OwnerUserHash,
			OwnerEnvHash: encoded.OwnerEnvHash, SessionChannelIDHash: encoded.SessionChannelIDHash,
		}
		if err := scope.Validate(); err != nil {
			return nil, err
		}
		proofBytes, err := base64.RawStdEncoding.DecodeString(encoded.ProofBase64)
		if err != nil {
			return nil, sessionscope.ErrClosedSessionProofInvalid
		}
		proof, err := sessionscope.NewClosedSessionProof(proofBytes)
		if err != nil {
			return nil, err
		}
		identity, err := sessionscope.NewTeardownIdentity(encoded.OperationID, proof)
		if err != nil {
			return nil, err
		}
		if _, exists := adapter.records[scope]; exists {
			return nil, errors.New("duplicate CLI closed session scope")
		}
		adapter.records[scope] = cliSessionLifecycleRecord{identity: identity, proof: proofBytes, closed: encoded.Closed}
	}
	return adapter, nil
}

func (a *cliSessionLifecycleAdapter) ReconcileRetainedSessionScopes(ctx context.Context, req host.ReconcileRetainedSessionScopesRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	next := cloneCLISessionLifecycleRecords(a.records)
	changed := false
	for _, retained := range req.Scopes {
		if err := retained.SessionScope.Validate(); err != nil || !retained.Snapshot.State.Valid() ||
			retained.Snapshot.State == sessionscope.StateActive || !retained.Snapshot.Fenced {
			return errors.New("CLI retained session fence is invalid")
		}
		record, ok := a.records[retained.SessionScope]
		if !ok || !record.identity.Valid() || !retained.MatchesIdentity(record.identity) {
			return errors.New("CLI closed session identity is unavailable")
		}
		if !record.closed {
			record.closed = true
			next[retained.SessionScope] = record
			changed = true
		}
	}
	if changed {
		if err := a.persist(next); err != nil {
			return err
		}
		a.records = next
	}
	return nil
}

func (a *cliSessionLifecycleAdapter) PrepareSessionScopeClose(ctx context.Context, req host.PrepareSessionScopeCloseRequest) (sessionscope.TeardownIdentity, error) {
	if err := ctx.Err(); err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	scope, err := req.Session.SessionScope()
	if err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if record, ok := a.records[scope]; ok {
		return record.identity, nil
	}
	proof, err := sessionscope.GenerateClosedSessionProof()
	if err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	proofBytes, err := proof.BytesForDurableStorage()
	if err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	digest := sha256.Sum256([]byte(scope.OwnerSessionHash + "\x00" + scope.OwnerUserHash + "\x00" + scope.OwnerEnvHash + "\x00" + scope.SessionChannelIDHash))
	identity, err := sessionscope.NewTeardownIdentity("cli_session_teardown_"+hex.EncodeToString(digest[:8]), proof)
	if err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	next := cloneCLISessionLifecycleRecords(a.records)
	next[scope] = cliSessionLifecycleRecord{identity: identity, proof: proofBytes}
	if err := a.persist(next); err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	a.records = next
	return identity, nil
}

func (a *cliSessionLifecycleAdapter) CommitSessionScopeClose(ctx context.Context, req host.CommitSessionScopeCloseRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scope, err := req.Session.SessionScope()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	record, ok := a.records[scope]
	if !ok || !record.identity.Matches(req.Identity) {
		return errors.New("CLI closed session identity mismatch")
	}
	if record.closed {
		return nil
	}
	next := cloneCLISessionLifecycleRecords(a.records)
	record.closed = true
	next[scope] = record
	if err := a.persist(next); err != nil {
		return err
	}
	a.records = next
	return nil
}

func (a *cliSessionLifecycleAdapter) ValidateClosedSessionScope(ctx context.Context, req host.ValidateClosedSessionScopeRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scope, err := req.Session.SessionScope()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	record, ok := a.records[scope]
	if !ok || !record.closed || !record.identity.Matches(req.Identity) {
		return errors.New("CLI closed session identity mismatch")
	}
	return nil
}

func (a *cliSessionLifecycleAdapter) persist(records map[sessionctx.SessionScope]cliSessionLifecycleRecord) error {
	if len(records) > sessionscope.HardMaxScopes {
		return errors.New("CLI closed session state exceeds the record limit")
	}
	encoded := make([]cliClosedSessionRecord, 0, len(records))
	for scope, record := range records {
		encoded = append(encoded, cliClosedSessionRecord{
			OwnerSessionHash: scope.OwnerSessionHash, OwnerUserHash: scope.OwnerUserHash,
			OwnerEnvHash: scope.OwnerEnvHash, SessionChannelIDHash: scope.SessionChannelIDHash,
			OperationID: record.identity.OperationID, ProofBase64: base64.RawStdEncoding.EncodeToString(record.proof), Closed: record.closed,
		})
	}
	sort.Slice(encoded, func(i, j int) bool {
		left, right := encoded[i], encoded[j]
		return left.OwnerSessionHash+"\x00"+left.OwnerUserHash+"\x00"+left.OwnerEnvHash+"\x00"+left.SessionChannelIDHash <
			right.OwnerSessionHash+"\x00"+right.OwnerUserHash+"\x00"+right.OwnerEnvHash+"\x00"+right.SessionChannelIDHash
	})
	raw, err := json.MarshalIndent(cliClosedSessionsDocument{SchemaVersion: cliClosedSessionsSchemaVersion, Records: encoded}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if int64(len(raw)) > cliClosedSessionsMaxBytes {
		return errors.New("CLI closed session state exceeds the size limit")
	}
	return a.write(raw)
}

func writeCLIClosedSessionsState(path string, raw []byte, syncDirectory func(string) error) error {
	if syncDirectory == nil {
		return errors.New("CLI closed session directory sync is required")
	}
	directoryPath := filepath.Dir(path)
	if err := validateCLIStateDirectory(directoryPath); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directoryPath, ".closed-sessions-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directoryPath)
}

func syncCLIClosedSessionsDirectory(directoryPath string) error {
	directory, err := os.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("open CLI closed session state directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync CLI closed session state directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close CLI closed session state directory: %w", err)
	}
	return nil
}

func validateCLIStateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("CLI closed session state directory must be private (mode %o)", info.Mode().Perm())
	}
	return nil
}

func cloneCLISessionLifecycleRecords(source map[sessionctx.SessionScope]cliSessionLifecycleRecord) map[sessionctx.SessionScope]cliSessionLifecycleRecord {
	cloned := make(map[sessionctx.SessionScope]cliSessionLifecycleRecord, len(source)+1)
	for scope, record := range source {
		record.proof = append([]byte(nil), record.proof...)
		cloned[scope] = record
	}
	return cloned
}
