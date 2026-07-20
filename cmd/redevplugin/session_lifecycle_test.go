package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
)

func TestCLISessionLifecyclePersistsExactClosedIdentityAcrossRestart(t *testing.T) {
	path := privateCLISessionStatePath(t)
	adapter, err := newCLISessionLifecycleAdapter(path)
	if err != nil {
		t.Fatal(err)
	}
	session := sessionctx.Context{
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash",
		OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
	}
	identity, err := adapter.PrepareSessionScopeClose(context.Background(), host.PrepareSessionScopeCloseRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitSessionScopeClose(context.Background(), host.CommitSessionScopeCloseRequest{Session: session, Identity: identity}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("closed session state permissions = %o, want 600", info.Mode().Perm())
	}

	restarted, err := newCLISessionLifecycleAdapter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ValidateClosedSessionScope(context.Background(), host.ValidateClosedSessionScopeRequest{
		Session: session, Identity: identity,
	}); err != nil {
		t.Fatalf("ValidateClosedSessionScope(after restart) error = %v", err)
	}
	retained := retainedCLISessionScope(t, session, identity)
	if err := restarted.ReconcileRetainedSessionScopes(context.Background(), host.ReconcileRetainedSessionScopesRequest{
		Scopes: []sessionscope.RetainedScope{retained},
	}); err != nil {
		t.Fatalf("ReconcileRetainedSessionScopes(after restart) error = %v", err)
	}
	replayed, err := restarted.PrepareSessionScopeClose(context.Background(), host.PrepareSessionScopeCloseRequest{Session: session})
	if err != nil || !replayed.Matches(identity) {
		t.Fatalf("PrepareSessionScopeClose(replay) = %#v, %v", replayed, err)
	}
}

func TestCLISessionLifecycleReconcileCommitsPreparedIdentityAfterCrash(t *testing.T) {
	path := privateCLISessionStatePath(t)
	adapter, err := newCLISessionLifecycleAdapter(path)
	if err != nil {
		t.Fatal(err)
	}
	session := sessionctx.Context{
		OwnerSessionHash: "session_crash", OwnerUserHash: "user_crash",
		OwnerEnvHash: "env_crash", SessionChannelIDHash: "channel_crash",
	}
	identity, err := adapter.PrepareSessionScopeClose(context.Background(), host.PrepareSessionScopeCloseRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := newCLISessionLifecycleAdapter(path)
	if err != nil {
		t.Fatal(err)
	}
	wrongIdentity := mustCLITeardownIdentity(t, "cli_wrong_identity")
	wrongIdentityRetained := retainedCLISessionScope(t, session, wrongIdentity)
	if err := restarted.ReconcileRetainedSessionScopes(context.Background(), host.ReconcileRetainedSessionScopesRequest{
		Scopes: []sessionscope.RetainedScope{wrongIdentityRetained},
	}); err == nil {
		t.Fatal("ReconcileRetainedSessionScopes(wrong identity) succeeded")
	}
	if err := restarted.ValidateClosedSessionScope(context.Background(), host.ValidateClosedSessionScopeRequest{
		Session: session, Identity: identity,
	}); err == nil {
		t.Fatal("failed identity reconciliation committed closed state")
	}

	retained := retainedCLISessionScope(t, session, identity)
	if err := restarted.ReconcileRetainedSessionScopes(context.Background(), host.ReconcileRetainedSessionScopesRequest{
		Scopes: []sessionscope.RetainedScope{retained},
	}); err != nil {
		t.Fatalf("ReconcileRetainedSessionScopes() error = %v", err)
	}
	if err := restarted.ValidateClosedSessionScope(context.Background(), host.ValidateClosedSessionScopeRequest{
		Session: session, Identity: identity,
	}); err != nil {
		t.Fatalf("ValidateClosedSessionScope() error = %v", err)
	}

	restartedAgain, err := newCLISessionLifecycleAdapter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restartedAgain.ValidateClosedSessionScope(context.Background(), host.ValidateClosedSessionScopeRequest{
		Session: session, Identity: identity,
	}); err != nil {
		t.Fatalf("ValidateClosedSessionScope(after second restart) error = %v", err)
	}
	wrongSession := session
	wrongSession.SessionChannelIDHash = "channel_other"
	wrongRetained := retainedCLISessionScope(t, wrongSession, mustCLITeardownIdentity(t, "cli_wrong_scope"))
	if err := restartedAgain.ReconcileRetainedSessionScopes(context.Background(), host.ReconcileRetainedSessionScopesRequest{
		Scopes: []sessionscope.RetainedScope{wrongRetained},
	}); err == nil {
		t.Fatal("ReconcileRetainedSessionScopes(wrong scope) succeeded")
	}
	if err := restartedAgain.ValidateClosedSessionScope(context.Background(), host.ValidateClosedSessionScopeRequest{
		Session: session, Identity: wrongIdentity,
	}); err == nil {
		t.Fatal("ValidateClosedSessionScope(wrong identity) succeeded")
	}
}

func TestCLISessionLifecycleReconcilesPreparedIdentityFromReopenedSQLiteFence(t *testing.T) {
	ctx := context.Background()
	cliPath := privateCLISessionStatePath(t)
	adapter, err := newCLISessionLifecycleAdapter(cliPath)
	if err != nil {
		t.Fatal(err)
	}
	session := sessionctx.Context{
		OwnerSessionHash: "session_sqlite", OwnerUserHash: "user_sqlite",
		OwnerEnvHash: "env_sqlite", SessionChannelIDHash: "channel_sqlite",
	}
	identity, err := adapter.PrepareSessionScopeClose(ctx, host.PrepareSessionScopeCloseRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(t.TempDir(), "session-scopes.sqlite")
	store, err := sessionscope.NewSQLiteStore(ctx, databasePath, sessionscope.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := sessionscope.NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	teardown, _, err := coordinator.BeginTeardown(ctx, scope, identity, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	teardown.Release()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restartedAdapter, err := newCLISessionLifecycleAdapter(cliPath)
	if err != nil {
		t.Fatal(err)
	}
	reopenedStore, err := sessionscope.NewSQLiteStore(ctx, databasePath, sessionscope.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedStore.Close()
	reopenedCoordinator, err := sessionscope.NewCoordinator(reopenedStore)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := reopenedCoordinator.ListRetained(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || !retained[0].MatchesIdentity(identity) {
		t.Fatalf("reopened retained scope does not preserve exact identity binding: %#v", retained)
	}
	if err := restartedAdapter.ReconcileRetainedSessionScopes(ctx, host.ReconcileRetainedSessionScopesRequest{Scopes: retained}); err != nil {
		t.Fatalf("ReconcileRetainedSessionScopes() error = %v", err)
	}
	if err := restartedAdapter.ValidateClosedSessionScope(ctx, host.ValidateClosedSessionScopeRequest{
		Session: session, Identity: identity,
	}); err != nil {
		t.Fatalf("ValidateClosedSessionScope() error = %v", err)
	}
}

func TestCLISessionLifecycleRejectsTrailingJSONAndUnknownFields(t *testing.T) {
	for name, raw := range map[string][]byte{
		"trailing": []byte(`{"schema_version":"redevplugin.cli-closed-sessions.v1","records":[]} {}`),
		"unknown":  []byte(`{"schema_version":"redevplugin.cli-closed-sessions.v1","records":[],"extra":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			path := privateCLISessionStatePath(t)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := newCLISessionLifecycleAdapter(path); err == nil {
				t.Fatal("newCLISessionLifecycleAdapter() accepted invalid document")
			}
		})
	}
}

func TestCLISessionLifecycleRejectsInsecureStatePaths(t *testing.T) {
	validDocument := []byte("{\"schema_version\":\"redevplugin.cli-closed-sessions.v1\",\"records\":[]}\n")
	t.Run("public file", func(t *testing.T) {
		path := privateCLISessionStatePath(t)
		if err := os.WriteFile(path, validDocument, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := newCLISessionLifecycleAdapter(path); err == nil {
			t.Fatal("newCLISessionLifecycleAdapter() accepted a group/world-readable proof file")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		directory := filepath.Dir(privateCLISessionStatePath(t))
		target := filepath.Join(directory, "target.json")
		path := filepath.Join(directory, "closed-sessions.json")
		if err := os.WriteFile(target, validDocument, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := newCLISessionLifecycleAdapter(path); err == nil {
			t.Fatal("newCLISessionLifecycleAdapter() followed a proof-file symlink")
		}
	})
	t.Run("public directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "public")
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "closed-sessions.json")
		if _, err := newCLISessionLifecycleAdapter(path); err == nil {
			t.Fatal("newCLISessionLifecycleAdapter() accepted a group/world-accessible state directory")
		}
	})
	t.Run("missing directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "closed-sessions.json")
		if _, err := newCLISessionLifecycleAdapter(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("newCLISessionLifecycleAdapter() error = %v, want missing directory", err)
		}
	})
}

func TestCLISessionLifecycleDirectorySyncFailureDoesNotSwapMemoryState(t *testing.T) {
	path := privateCLISessionStatePath(t)
	adapter, err := newCLISessionLifecycleAdapter(path)
	if err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("injected directory sync failure")
	syncObserved := false
	adapter.write = func(raw []byte) error {
		return writeCLIClosedSessionsState(path, raw, func(directory string) error {
			syncObserved = true
			persisted, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(persisted) == 0 || directory != filepath.Dir(path) {
				t.Fatalf("directory sync ran before rename: directory=%q bytes=%d", directory, len(persisted))
			}
			return syncFailure
		})
	}
	session := sessionctx.Context{
		OwnerSessionHash: "session_sync", OwnerUserHash: "user_sync",
		OwnerEnvHash: "env_sync", SessionChannelIDHash: "channel_sync",
	}
	if _, err := adapter.PrepareSessionScopeClose(context.Background(), host.PrepareSessionScopeCloseRequest{Session: session}); !errors.Is(err, syncFailure) {
		t.Fatalf("PrepareSessionScopeClose() error = %v, want sync failure", err)
	}
	if !syncObserved || len(adapter.records) != 0 {
		t.Fatalf("sync observed=%v in-memory records=%d, want true and 0", syncObserved, len(adapter.records))
	}
}

func TestCLISessionLifecycleRejectsOversizedState(t *testing.T) {
	path := privateCLISessionStatePath(t)
	stateFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateFile.Truncate(cliClosedSessionsMaxBytes + 1); err != nil {
		_ = stateFile.Close()
		t.Fatal(err)
	}
	if err := stateFile.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := newCLISessionLifecycleAdapter(path); err == nil {
		t.Fatal("newCLISessionLifecycleAdapter() accepted oversized state")
	}
}

func TestCLISessionLifecycleRejectsTooManyRecords(t *testing.T) {
	path := privateCLISessionStatePath(t)
	raw := "{\"schema_version\":\"redevplugin.cli-closed-sessions.v1\",\"records\":[" +
		strings.Repeat("{},", sessionscope.HardMaxScopes) + "{}]}"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newCLISessionLifecycleAdapter(path); err == nil {
		t.Fatal("newCLISessionLifecycleAdapter() accepted too many records")
	}
}

func TestCLISessionLifecycleRefusesToPersistRecordOverflow(t *testing.T) {
	adapter, err := newCLISessionLifecycleAdapter(privateCLISessionStatePath(t))
	if err != nil {
		t.Fatal(err)
	}
	seedSession := sessionctx.Context{
		OwnerSessionHash: "session_seed", OwnerUserHash: "user_limit",
		OwnerEnvHash: "env_limit", SessionChannelIDHash: "channel_limit",
	}
	if _, err := adapter.PrepareSessionScopeClose(context.Background(), host.PrepareSessionScopeCloseRequest{Session: seedSession}); err != nil {
		t.Fatal(err)
	}
	seedScope, err := seedSession.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	seedRecord := adapter.records[seedScope]
	for index := 1; index < sessionscope.HardMaxScopes; index++ {
		scope := sessionctx.SessionScope{
			OwnerSessionHash: fmt.Sprintf("session_%d", index), OwnerUserHash: "user_limit",
			OwnerEnvHash: "env_limit", SessionChannelIDHash: fmt.Sprintf("channel_%d", index),
		}
		adapter.records[scope] = seedRecord
	}
	writeCalled := false
	adapter.write = func([]byte) error {
		writeCalled = true
		return nil
	}
	overflowSession := sessionctx.Context{
		OwnerSessionHash: "session_overflow", OwnerUserHash: "user_limit",
		OwnerEnvHash: "env_limit", SessionChannelIDHash: "channel_overflow",
	}
	if _, err := adapter.PrepareSessionScopeClose(context.Background(), host.PrepareSessionScopeCloseRequest{Session: overflowSession}); err == nil {
		t.Fatal("PrepareSessionScopeClose() persisted more records than the durable format accepts")
	}
	if writeCalled || len(adapter.records) != sessionscope.HardMaxScopes {
		t.Fatalf("write called=%v records=%d, want false and %d", writeCalled, len(adapter.records), sessionscope.HardMaxScopes)
	}
}

func mustCLITeardownIdentity(t *testing.T, operationID string) sessionscope.TeardownIdentity {
	t.Helper()
	proof, err := sessionscope.GenerateClosedSessionProof()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sessionscope.NewTeardownIdentity(operationID, proof)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func privateCLISessionStatePath(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "closed-sessions.json")
}

func retainedCLISessionScope(t *testing.T, session sessionctx.Context, identity sessionscope.TeardownIdentity) sessionscope.RetainedScope {
	t.Helper()
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	store, err := sessionscope.NewMemoryStore(sessionscope.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := sessionscope.NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	teardown, _, err := coordinator.BeginTeardown(context.Background(), scope, identity, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	teardown.Release()
	retained, err := coordinator.ListRetained(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 {
		t.Fatalf("retained session scopes = %d, want 1", len(retained))
	}
	return retained[0]
}
