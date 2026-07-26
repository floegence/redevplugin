package host

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestGetSurfaceOperationProjectsBoundSnapshotAndHidesAudienceMismatch(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationObservationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := GetSurfaceOperationRequest{
		OperationID: started.OperationID, SurfaceInstanceID: "surface_rpc", BridgeChannelID: "bridge_rpc",
		Now: time.Date(2026, 7, 26, 1, 0, 0, 0, time.UTC),
	}
	snapshot, err := h.GetSurfaceOperation(hostTestContext(), base)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OperationID != started.OperationID || snapshot.Status != operation.StatusRunning ||
		snapshot.TerminalAt != nil || snapshot.FailureCode != nil ||
		snapshot.RetryAfterMS != SurfaceOperationSnapshotRetryMinMS {
		t.Fatalf("running snapshot = %#v", snapshot)
	}

	tests := []struct {
		name   string
		mutate func(*GetSurfaceOperationRequest)
	}{
		{name: "surface", mutate: func(req *GetSurfaceOperationRequest) { req.SurfaceInstanceID = "surface_other" }},
		{name: "bridge channel", mutate: func(req *GetSurfaceOperationRequest) { req.BridgeChannelID = "bridge_other" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			req.Now = req.Now.Add(time.Second)
			tc.mutate(&req)
			if _, err := h.GetSurfaceOperation(hostTestContext(), req); !errors.Is(err, operation.ErrNotFound) {
				t.Fatalf("GetSurfaceOperation() error = %v, want %v", err, operation.ErrNotFound)
			}
		})
	}
	for name, ctx := range map[string]func() context.Context{
		"owner session": func() context.Context {
			return hostTestContextWith("session_other", "user_hash", "env_hash", "channel_hash")
		},
		"owner user": func() context.Context {
			return hostTestContextWith("session_hash", "user_other", "env_hash", "channel_hash")
		},
		"owner env": func() context.Context {
			return hostTestContextWith("session_hash", "user_hash", "env_other", "channel_hash")
		},
		"channel": func() context.Context {
			return hostTestContextWith("session_hash", "user_hash", "env_hash", "channel_other")
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := base
			req.Now = req.Now.Add(2 * time.Second)
			if _, err := h.GetSurfaceOperation(ctx(), req); !errors.Is(err, operation.ErrNotFound) {
				t.Fatalf("GetSurfaceOperation() error = %v, want %v", err, operation.ErrNotFound)
			}
		})
	}
	unknown := base
	unknown.OperationID = "operation_unknown"
	unknown.Now = unknown.Now.Add(3 * time.Second)
	if _, err := h.GetSurfaceOperation(hostTestContext(), unknown); !errors.Is(err, operation.ErrNotFound) {
		t.Fatalf("unknown GetSurfaceOperation() error = %v, want %v", err, operation.ErrNotFound)
	}
	for index := 0; index < 10_000; index++ {
		mismatched := base
		mismatched.SurfaceInstanceID = fmt.Sprintf("surface_unbound_%d", index)
		if _, err := h.GetSurfaceOperation(hostTestContext(), mismatched); !errors.Is(err, operation.ErrNotFound) {
			t.Fatalf("unbound surface %d error = %v, want %v", index, err, operation.ErrNotFound)
		}
	}
	h.operationObservers.mu.Lock()
	retainedSurfaces := len(h.operationObservers.surfaces)
	retainedOperations := h.operationObservers.operationCount
	h.operationObservers.mu.Unlock()
	if retainedSurfaces != 1 || retainedOperations != 2 {
		t.Fatalf("unbound surface flood retained surfaces=%d operations=%d", retainedSurfaces, retainedOperations)
	}
}

func TestProjectPluginOperationSnapshotClosedUnion(t *testing.T) {
	createdAt := time.Date(2026, 7, 26, 2, 0, 0, 0, time.UTC)
	terminalAt := createdAt.Add(time.Second)
	for _, tc := range []struct {
		status      operation.Status
		failureCode capability.ExecutionFailureCode
		terminal    bool
	}{
		{status: operation.StatusRunning},
		{status: operation.StatusCancelRequested},
		{status: operation.StatusCompleted, terminal: true},
		{status: operation.StatusCanceled, terminal: true},
		{status: operation.StatusOrphanedAfterDisable, terminal: true},
		{status: operation.StatusOrphanedAfterUninstall, terminal: true},
		{status: operation.StatusFailed, terminal: true, failureCode: capability.ExecutionFailureAdapterFailed},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			record := operation.Record{
				OperationID: "operation_1", Status: tc.status, Cancelable: true,
				CreatedAt: createdAt, UpdatedAt: terminalAt, FailureCode: tc.failureCode,
			}
			if tc.terminal {
				record.TerminalAt = &terminalAt
			}
			snapshot, err := projectPluginOperationSnapshot(record)
			if err != nil {
				t.Fatal(err)
			}
			if (snapshot.TerminalAt != nil) != tc.terminal {
				t.Fatalf("TerminalAt = %v, terminal = %v", snapshot.TerminalAt, tc.terminal)
			}
			if tc.status == operation.StatusFailed {
				if snapshot.FailureCode == nil || *snapshot.FailureCode != tc.failureCode {
					t.Fatalf("FailureCode = %v", snapshot.FailureCode)
				}
			} else if snapshot.FailureCode != nil {
				t.Fatalf("non-failed snapshot leaked failure code %v", *snapshot.FailureCode)
			}
		})
	}
	malformed := operation.Record{OperationID: "operation_bad", Status: operation.StatusFailed, TerminalAt: &terminalAt}
	if _, err := projectPluginOperationSnapshot(malformed); !errors.Is(err, operation.ErrInvalidOperation) {
		t.Fatalf("malformed snapshot error = %v", err)
	}
}

func TestSurfaceOperationObservationRegistryEnforcesBudgetsAndDispose(t *testing.T) {
	registry := newSurfaceOperationObservationRegistry()
	key := surfaceOperationObservationKey{owner: operation.OwnerScope{
		OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel",
	}, surfaceInstanceID: "surface"}
	now := time.Date(2026, 7, 26, 3, 0, 0, 0, time.UTC)
	release, err := registry.acquire(key, "operation_1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.acquire(key, "operation_1", now); err == nil {
		t.Fatal("concurrent operation observation was accepted")
	} else {
		var limited *SurfaceOperationRateLimitError
		if !errors.As(err, &limited) || limited.RetryAfterMS != SurfaceOperationSnapshotRetryMinMS {
			t.Fatalf("concurrent limit error = %#v", err)
		}
	}
	release()
	release, err = registry.acquire(key, "operation_1", now)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := registry.acquire(key, "operation_1", now); err == nil {
		t.Fatal("per-operation token budget was not enforced")
	}
	registry.dispose(key)
	release, err = registry.acquire(key, "operation_1", now)
	if err != nil {
		t.Fatalf("observation after dispose cleanup = %v", err)
	}
	release()

	for index := 0; index < SurfaceOperationSnapshotPerSurfaceBurst; index++ {
		operationID := fmt.Sprintf("operation_surface_%d", index)
		release, err := registry.acquire(key, operationID, now.Add(time.Second))
		if err != nil {
			t.Fatalf("surface request %d = %v", index, err)
		}
		release()
	}
	if _, err := registry.acquire(key, "operation_surface_over", now.Add(time.Second)); err == nil {
		t.Fatal("per-surface token budget was not enforced")
	}
	for index := 0; index < 10_000; index++ {
		_, _ = registry.acquire(key, fmt.Sprintf("operation_flood_%d", index), now.Add(time.Second))
	}
	registry.mu.Lock()
	retained := len(registry.surfaces[key].operations)
	registry.mu.Unlock()
	if retained != SurfaceOperationSnapshotPerSurfaceBurst+1 {
		t.Fatalf("unique operation flood retained %d states, want %d", retained, SurfaceOperationSnapshotPerSurfaceBurst+1)
	}
}

func TestSurfaceOperationObservationRegistryHardBoundsHighFrequencyNewSurfaces(t *testing.T) {
	registry := newSurfaceOperationObservationRegistry()
	now := time.Date(2026, 7, 26, 4, 0, 0, 0, time.UTC)
	owner := operation.OwnerScope{
		OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel",
	}
	for index := 0; index < surfaceOperationObservationMaxSurfacesPerOwner+1_000; index++ {
		key := surfaceOperationObservationKey{owner: owner, surfaceInstanceID: fmt.Sprintf("surface_%d", index)}
		release, err := registry.acquire(key, fmt.Sprintf("operation_%d", index), now)
		if index < surfaceOperationObservationMaxSurfacesPerOwner {
			if err != nil {
				t.Fatalf("bounded surface %d = %v", index, err)
			}
			release()
		} else if err == nil {
			t.Fatalf("surface %d exceeded hard bound", index)
		}
	}
	registry.mu.Lock()
	retainedSurfaces := len(registry.surfaces)
	retainedOperations := registry.operationCount
	nextPrune := registry.nextPrune
	registry.mu.Unlock()
	if retainedSurfaces != surfaceOperationObservationMaxSurfacesPerOwner || retainedOperations != surfaceOperationObservationMaxSurfacesPerOwner {
		t.Fatalf("hard bound retained surfaces=%d operations=%d", retainedSurfaces, retainedOperations)
	}
	if !nextPrune.Equal(now.Add(surfaceOperationObservationPruneInterval)) {
		t.Fatalf("high-frequency capacity rejection rescanned prune state: next=%s", nextPrune)
	}
	secondOwner := operation.OwnerScope{
		OwnerSessionHash: "session_two", OwnerUserHash: "user_two", OwnerEnvHash: "env_two", SessionChannelIDHash: "channel_two",
	}
	release, err := registry.acquire(
		surfaceOperationObservationKey{owner: secondOwner, surfaceInstanceID: "surface_second_owner"},
		"operation_second_owner", now,
	)
	if err != nil {
		t.Fatalf("second owner was coupled to first owner capacity: %v", err)
	}
	release()
}

func TestReconcileSurfaceRevocationAndSessionDisposeClearObservationState(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}},
	})
	installed := installAndEnablePlugin(t, h, buildOperationObservationRPCFixturePackage(t))
	grantDeclaredPermissions(t, h, installed)
	bootstrap, gateway := openSurfaceAndMintGatewayForAudience(t, h, installed.PluginInstanceID, "operation.view", "surface_cleanup", "bridge_cleanup")
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_cleanup",
		BridgeChannelID: "bridge_cleanup", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.GetSurfaceOperation(hostTestContext(), GetSurfaceOperationRequest{
		OperationID: started.OperationID, SurfaceInstanceID: "surface_cleanup", BridgeChannelID: "bridge_cleanup",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReconcileSurfaceRevocation(hostTestContext(), DisposeSurfaceRequest{
		SurfaceInstanceID: "surface_cleanup", BridgeNonce: bootstrap.BridgeNonce,
	}); err != nil {
		t.Fatal(err)
	}
	h.operationObservers.mu.Lock()
	retainedAfterReconcile := len(h.operationObservers.surfaces)
	h.operationObservers.mu.Unlock()
	if retainedAfterReconcile != 0 {
		t.Fatalf("reconciled surface retained %d observation states", retainedAfterReconcile)
	}

	registry := newSurfaceOperationObservationRegistry()
	session := sessionctx.Context{
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
	}
	key := surfaceOperationObservationKey{owner: operationOwnerScope(session), surfaceInstanceID: "surface_session_cleanup"}
	release, err := registry.acquire(key, "operation_session_cleanup", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	release()
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	registry.disposeSession(scope)
	if len(registry.surfaces) != 0 || registry.operationCount != 0 {
		t.Fatalf("session cleanup retained surfaces=%d operations=%d", len(registry.surfaces), registry.operationCount)
	}
}
