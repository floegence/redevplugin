package host

import (
	"context"
	"io"
	"slices"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

type WebPrivateFileRequest struct {
	WebSurfaceRequest
	StoreID string
	Path    string
}

// TransferWebPrivateFile streams one private file. Uploads replace the complete
// file atomically; cancellation before commit leaves the prior file intact.
// Blocking stream implementations must honor cancellation by closing their I/O.
func (h *Host) TransferWebPrivateFile(ctx context.Context, req WebPrivateFileRequest, source io.Reader, destination io.Writer) (size int64, retErr error) {
	done, err := h.ensureOpen()
	if err != nil {
		return 0, err
	}
	defer done()
	if (source == nil) == (destination == nil) {
		return 0, errRuntimeIOInvalidRequest
	}
	binding, ctx, err := h.webSurface(ctx, req.WebSurfaceRequest)
	if err != nil {
		return 0, err
	}
	if !binding.gatewayReady {
		return 0, bridge.ErrAssetSessionRequired
	}
	operation := "read"
	if source != nil {
		operation = "write"
	}
	allowed := false
	for _, access := range binding.surface.Web.Storage {
		if access.StoreID == req.StoreID && slices.Contains(access.Operations, operation) {
			allowed = true
		}
	}
	if !allowed || source != nil && !binding.owner.CanWrite || source == nil && !binding.owner.CanRead {
		return 0, permissions.ErrPermissionDenied
	}
	record, err := h.getPluginRecord(ctx, binding.pluginInstanceID)
	if err != nil {
		return 0, err
	}
	if err = h.canRun(ctx, record); err != nil {
		return 0, err
	}
	namespace, found, err := storageNamespaceByStoreID(record, req.StoreID)
	if err != nil {
		return 0, err
	}
	if !found || namespace.Kind != storage.StoreFiles {
		return 0, permissions.ErrPermissionDenied
	}
	scope, err := binding.owner.ResourceScope(sessionctx.ScopeKind(namespace.Scope))
	if err != nil {
		return 0, err
	}
	ctx, _, release, err := h.resourceAction(ctx, ManagementActionMintStorageHandleGrant, scopedAuthorizationTarget(ResourceStore, req.StoreID, scope.Kind), scopedAuthorizationTarget(ResourcePlugin, record.PluginInstanceID, sessionctx.ScopeEnvironment))
	if err != nil {
		return 0, err
	}
	defer release()
	ctx, cancel := context.WithDeadline(ctx, binding.expiresAt)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 5*time.Minute)
	defer timeout()
	stop := context.AfterFunc(binding.ctx, cancel)
	defer stop()
	for _, stream := range []any{source, destination} {
		if closer, ok := stream.(io.Closer); ok {
			stopIO := context.AfterFunc(ctx, func() { _ = closer.Close() })
			defer stopIO()
		}
	}

	releaseResource, err := h.reserveWebResource(req.WebSurfaceRequest, binding.ctx)
	if err != nil {
		return 0, err
	}
	defer releaseResource()
	broker, ok := h.runtimeIO.storageFiles.(storage.FilesStreamBroker)
	if !ok {
		return 0, errRuntimeIOStorageDenied
	}
	if source == nil {
		result, err := broker.ReadFileStream(ctx, storage.FileReadRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: scope, StoreID: req.StoreID, Path: req.Path, MaxBytes: namespace.QuotaBytes}, destination)
		return result.SizeBytes, err
	}
	audit, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.storage.updated", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return 0, err
	}
	defer func() { retErr = audit.complete(context.WithoutCancel(ctx), retErr) }()
	fence := func(ctx context.Context) (func(), error) {
		h.webSurfaces.fileMu.RLock()
		h.webSurfaces.mu.Lock()
		current := h.webSurfaces.byOrigin[req.Origin]
		valid := current != nil && current.ctx == binding.ctx && current.resourceToken == req.Token && ctx.Err() == nil
		h.webSurfaces.mu.Unlock()
		if !valid {
			h.webSurfaces.fileMu.RUnlock()
			return nil, bridge.ErrTokenRevoked
		}
		return h.webSurfaces.fileMu.RUnlock, nil
	}
	result, err := broker.WriteFileStream(ctx, storage.FileStreamWriteRequest{FileWriteRequest: storage.FileWriteRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: scope, StoreID: req.StoreID, Path: req.Path}, MaxBytes: namespace.QuotaBytes, BeforeCommit: fence}, source)
	return result.SizeBytes, err
}
