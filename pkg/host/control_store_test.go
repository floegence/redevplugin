package host

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestOpenOwnsControlStoreLifecycle(t *testing.T) {
	config := modularTestConfig(t)
	config.StateRoot = filepath.Join(t.TempDir(), "state")

	host, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	controlPath := filepath.Join(config.StateRoot, "control.sqlite")
	if _, err := os.Stat(controlPath); err != nil {
		t.Fatalf("control DB was not created below state root: %v", err)
	}
	if host.controlStore == nil || host.controlStore.Generation() != 1 {
		t.Fatalf("Host did not retain the opened control store: %#v", host.controlStore)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := host.controlStore.Executions().List(context.Background(), ""); !errors.Is(err, controlstore.ErrRequestsBlocked) {
		t.Fatalf("control view after Host.Close() error = %v, want ErrRequestsBlocked", err)
	}
}

func TestOpenDoesNotCreateLegacyPlatformStateTables(t *testing.T) {
	config := modularTestConfig(t)
	config.StateRoot = filepath.Join(t.TempDir(), "state")
	config.Core.internalStateOwners.confirmationIntents = nil
	config.Core.internalStateOwners.sessionScopes = nil

	host, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	db, err := sql.Open("sqlite", filepath.Join(config.StateRoot, "control.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'plugin_confirmation_%' OR name LIKE 'plugin_session_scope_%') ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var legacy []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		legacy = append(legacy, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(legacy) != 0 {
		t.Fatalf("Host Open created legacy platform state tables: %v", legacy)
	}
}

func TestHostConfirmationAuthorityPersistsInControlStore(t *testing.T) {
	config := modularTestConfig(t)
	config.StateRoot = filepath.Join(t.TempDir(), "state")
	config.Core.internalStateOwners.confirmationIntents = nil
	ctx := hostTestContext()
	session, ok := sessionctx.FromContext(ctx)
	if !ok {
		t.Fatal("host test context has no session")
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	req := security.PutConfirmationIntentRequest{
		ConfirmationID: "confirmation_control", ConfirmationTokenID: "token_control",
		PluginID: "com.example.control", PluginInstanceID: "instance_control",
		SurfaceInstanceID: "surface_control", BridgeChannelID: "bridge_control",
		Method: "documents.write", RequestHash: "sha256:request", PlanHash: "sha256:plan",
		Scope: security.ConfirmationScope{
			ActiveFingerprint: "sha256:fingerprint", OwnerSessionHash: session.OwnerSessionHash,
			OwnerUserHash: session.OwnerUserHash, OwnerEnvHash: session.OwnerEnvHash,
			SessionChannelIDHash: session.SessionChannelIDHash, PolicyRevision: 1,
			ManagementRevision: 1, RevokeEpoch: 0, TargetDescriptorSHA256: "sha256:target",
		},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), Now: now,
	}

	host, err := Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.adapters.ConfirmationIntents.PutConfirmationIntent(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}

	config.Core.internalStateOwners.confirmationIntents = nil
	reopened, err := Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	wrong := scope
	wrong.SessionChannelIDHash = "sha256:wrong-channel"
	if _, err := reopened.adapters.ConfirmationIntents.ConsumeConfirmationIntent(ctx, security.ConsumeConfirmationIntentRequest{ConfirmationID: req.ConfirmationID, SessionScope: wrong, Now: now.Add(time.Minute)}); !errors.Is(err, security.ErrConfirmationIntentScopeMismatch) {
		t.Fatalf("wrong-scope consume error = %v", err)
	}
	consumed, err := reopened.adapters.ConfirmationIntents.ConsumeConfirmationIntent(ctx, security.ConsumeConfirmationIntentRequest{ConfirmationID: req.ConfirmationID, SessionScope: scope, Now: now.Add(time.Minute)})
	if err != nil || consumed.PlanHash != req.PlanHash {
		t.Fatalf("ConsumeConfirmationIntent() = %#v, %v", consumed, err)
	}
	if _, err := reopened.adapters.ConfirmationIntents.ConsumeConfirmationIntent(ctx, security.ConsumeConfirmationIntentRequest{ConfirmationID: req.ConfirmationID, SessionScope: scope, Now: now.Add(time.Minute)}); !errors.Is(err, security.ErrConfirmationIntentNotFound) {
		t.Fatalf("replayed consume error = %v", err)
	}
}

func TestExecutionFacadeUsesControlStoreAndSessionOwner(t *testing.T) {
	config := modularTestConfig(t)
	config.StateRoot = filepath.Join(t.TempDir(), "state")
	host, err := Open(hostTestContext(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	owner := executionOwnerScope(hostTestContext())
	other := executionOwnerScope(hostTestContextWith("session_other", "user_other", "env_other", "channel_other"))
	now := time.Now().UTC()
	for _, fixture := range []struct {
		value execution.Execution
		owner controlstore.ExecutionOwner
	}{
		{execution.Execution{ID: "exec_1", PluginInstanceID: "plugin_1", Kind: execution.KindOperation, Cancelable: true, CreatedAt: now}, owner},
		{execution.Execution{ID: "exec_other", PluginInstanceID: "plugin_1", Kind: execution.KindOperation, Cancelable: true, CreatedAt: now.Add(time.Second)}, other},
	} {
		if err := host.controlStore.Executions().CreateOwned(hostTestContext(), fixture.value, fixture.owner); err != nil {
			t.Fatal(err)
		}
	}
	releaseIdentity := registry.ReleaseInstallIdentity{
		SourceID: "official", Channel: "stable", ReleaseMetadataRef: "release.json",
		ReleaseMetadataSHA256: strings.Repeat("a", 64), PublisherID: "publisher", PluginID: "plugin", Version: "1.0.0",
		PackageSHA256: "sha256:" + strings.Repeat("b", 64), ManifestSHA256: "sha256:" + strings.Repeat("c", 64), EntriesSHA256: "sha256:" + strings.Repeat("d", 64),
	}
	if _, _, err := host.controlStore.Executions().StartReleaseInstall(hostTestContext(), owner, registry.StartReleaseInstallOperationRequest{
		RequestID: "request_release_install", ExecutionID: "release_install_1", PluginInstanceID: "plugin_1",
		ReleaseIdentityDigest: mustReleaseIdentityDigestForRegistryTest(t, releaseIdentity),
		ManifestSHA256:        releaseIdentity.ManifestSHA256, ContractSetSHA256: "sha256:" + strings.Repeat("e", 64), SummarySHA256: "sha256:" + strings.Repeat("f", 64),
		Release: releaseIdentity, Now: now.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := host.controlStore.Executions().StartReleaseInstall(hostTestContext(), owner, registry.StartReleaseInstallOperationRequest{
		RequestID: "request_release_install_2", ExecutionID: "release_install_2", PluginInstanceID: "plugin_2",
		ReleaseIdentityDigest: mustReleaseIdentityDigestForRegistryTest(t, releaseIdentity),
		ManifestSHA256:        releaseIdentity.ManifestSHA256, ContractSetSHA256: "sha256:" + strings.Repeat("e", 64), SummarySHA256: "sha256:" + strings.Repeat("f", 64),
		Release: releaseIdentity, Now: now.Add(3 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.controlStore.Executions().Append(hostTestContext(), execution.Event{ExecutionID: "exec_1", Sequence: 1, Kind: execution.EventProgress, Payload: map[string]any{"step": 1}}); err != nil {
		t.Fatal(err)
	}

	listed, next, err := host.ListExecutions(hostTestContext(), "plugin_1", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].ID != "exec_1" || listed[1].ID != "release_install_1" || next != 0 {
		t.Fatalf("ListExecutions() = %#v, next=%d", listed, next)
	}
	releaseInstalls, next, err := host.ListExecutionsWithOptions(hostTestContext(), ListExecutionsOptions{
		PluginInstanceID: "plugin_1", OperationScope: ExecutionOperationScopeReleaseInstall, Limit: 10,
	})
	if err != nil || len(releaseInstalls) != 1 || releaseInstalls[0].ID != "release_install_1" || next != 0 {
		t.Fatalf("ListExecutionsWithOptions(release install) = %#v, next=%d, err=%v", releaseInstalls, next, err)
	}
	firstPage, next, err := host.ListExecutionsWithOptions(hostTestContext(), ListExecutionsOptions{
		OperationScope: ExecutionOperationScopeReleaseInstall, Limit: 1,
	})
	if err != nil || len(firstPage) != 1 || firstPage[0].ID != "release_install_1" || next == 0 {
		t.Fatalf("release install first page = %#v, next=%d, err=%v", firstPage, next, err)
	}
	secondPage, terminalCursor, err := host.ListExecutionsWithOptions(hostTestContext(), ListExecutionsOptions{
		OperationScope: ExecutionOperationScopeReleaseInstall, Cursor: next, Limit: 1,
	})
	if err != nil || len(secondPage) != 1 || secondPage[0].ID != "release_install_2" || terminalCursor != 0 {
		t.Fatalf("release install second page = %#v, next=%d, err=%v", secondPage, terminalCursor, err)
	}
	if _, err := host.GetExecution(hostTestContext(), "exec_other"); !errors.Is(err, controlstore.ErrRecordNotFound) {
		t.Fatalf("cross-owner GetExecution() error = %v", err)
	}
	events, err := host.EventsAfter(hostTestContext(), "exec_1", 0, 10)
	if err != nil || len(events) != 1 || events[0].Sequence != 1 {
		t.Fatalf("EventsAfter() = %#v, err=%v", events, err)
	}
	canceled, err := host.CancelExecution(hostTestContext(), "exec_1", "user requested")
	if err != nil || canceled.Status != execution.StatusCancelRequested {
		t.Fatalf("CancelExecution() = %#v, err=%v", canceled, err)
	}
	again, err := host.CancelExecution(hostTestContext(), "exec_1", "duplicate")
	if err != nil || again.Status != execution.StatusCancelRequested {
		t.Fatalf("idempotent CancelExecution() = %#v, err=%v", again, err)
	}
}

func executionOwnerScope(ctx context.Context) controlstore.ExecutionOwner {
	session, _ := sessionctx.FromContext(ctx)
	return controlstore.ExecutionOwner{
		OwnerSessionHash: session.OwnerSessionHash, OwnerUserHash: session.OwnerUserHash,
		OwnerEnvHash: session.OwnerEnvHash, SessionChannelIDHash: session.SessionChannelIDHash,
	}
}

func TestOpenDoesNotDiscoverLegacySiblingDatabases(t *testing.T) {
	stateRoot := t.TempDir()
	legacyPaths := []string{
		filepath.Join(stateRoot, "registry.sqlite"),
		filepath.Join(stateRoot, "operations.sqlite"),
		filepath.Join(stateRoot, "db", "registry.sqlite"),
	}
	if err := os.MkdirAll(filepath.Join(stateRoot, "db"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := make(map[string][]byte, len(legacyPaths))
	for index, path := range legacyPaths {
		payload := []byte{byte(index + 1), 0x52, 0x50, 0x32}
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		before[path] = payload
	}

	config := modularTestConfig(t)
	config.StateRoot = stateRoot
	host, err := Open(hostTestContext(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	records, err := host.ListPlugins(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("fresh v3 control store imported legacy plugins: %#v", records)
	}
	for _, path := range legacyPaths {
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before[path]) {
			t.Fatalf("legacy sibling changed: %s", path)
		}
	}
}
