package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

// WebResourceRequest carries no author-supplied owner, plugin identity or grant.
// The dedicated origin session must have completed its source-bound handshake.
type WebResourceRequest struct {
	WebSurfaceRequest
	Resource  string
	Arguments json.RawMessage
}

func (h *Host) WebResource(ctx context.Context, req WebResourceRequest) (result any, retErr error) {
	done, err := h.ensureOpen()
	if err != nil {
		return nil, err
	}
	defer done()
	if len(req.Arguments) > 96<<10 || validateRuntimeIOJSON(req.Arguments) != nil {
		return nil, errRuntimeIOInvalidRequest
	}
	binding, ctx, err := h.webSurface(ctx, req.WebSurfaceRequest)
	if err != nil {
		return nil, err
	}
	if !binding.gatewayReady || binding.ctx == nil {
		return nil, bridge.ErrAssetSessionRequired
	}
	record, err := h.getPluginRecord(ctx, binding.pluginInstanceID)
	if err != nil {
		return nil, err
	}
	if record.EnableState != registry.EnableEnabled {
		return nil, permissions.ErrPermissionDenied
	}
	if err := h.canRun(ctx, record); err != nil {
		return nil, err
	}
	if req.Resource == "describe" {
		var args struct{}
		if err := decodeRuntimeIOJSON(req.Arguments, &args); err != nil {
			return nil, err
		}
		stores := []map[string]any{}
		for _, access := range binding.surface.Web.Storage {
			namespace, found, err := storageNamespaceByStoreID(record, access.StoreID)
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, permissions.ErrPermissionDenied
			}
			stores = append(stores, map[string]any{"store_id": access.StoreID, "kind": namespace.Kind, "scope": namespace.Scope, "operations": access.Operations})
		}
		return map[string]any{"can_read": binding.owner.CanRead, "can_write": binding.owner.CanWrite, "storage": stores, "settings": binding.surface.Web.Settings, "limits": map[string]any{"control_bytes": 96 << 10, "value_bytes": 64 << 10, "page_entries": 100, "transaction_statements": 64, "operation_timeout_ms": 5000, "watch_timeout_ms": 25000, "stream_timeout_ms": 300000, "concurrency_per_surface": 16, "concurrency_per_host": 256, "websocket_message_bytes": 1 << 20}}, nil
	}
	var selector struct {
		Operation string               `json:"operation"`
		StoreID   string               `json:"store_id"`
		Scope     sessionctx.ScopeKind `json:"scope"`
	}
	if err := json.Unmarshal(req.Arguments, &selector); err != nil {
		return nil, errRuntimeIOInvalidRequest
	}
	if selector.Operation == "watch" {
		return h.watchWebResource(ctx, req, binding)
	}
	action := ManagementActionMintStorageHandleGrant
	scope := selector.Scope
	target := scopedAuthorizationTarget(ResourceSettings, record.PluginInstanceID, scope)
	var access manifest.StorageBrokerAccessSpec
	var kind string
	if req.Resource == "settings" {
		if !slices.Contains(binding.surface.Web.Settings, selector.Operation) {
			return nil, permissions.ErrPermissionDenied
		}
		if selector.Operation == "get" {
			action = ManagementActionGetPluginSettings
		} else {
			action = ManagementActionPatchPluginSettings
		}
	} else {
		namespace, found, err := storageNamespaceByStoreID(record, selector.StoreID)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, permissions.ErrPermissionDenied
		}
		kind = string(namespace.Kind)
		scope = sessionctx.ScopeKind(namespace.Scope)
		if req.Resource != "storage."+kind {
			return nil, errRuntimeIOInvalidRequest
		}
		for _, item := range binding.surface.Web.Storage {
			if item.StoreID == selector.StoreID {
				access = item
				break
			}
		}
		if selector.Operation == "batch" && kind == "kv" {
			if !slices.Contains(access.Operations, "put") || !slices.Contains(access.Operations, "delete") {
				return nil, permissions.ErrPermissionDenied
			}
		} else if !slices.Contains(access.Operations, selector.Operation) {
			return nil, permissions.ErrPermissionDenied
		}
		target = scopedAuthorizationTarget(ResourceStore, namespace.StoreID, scope)
	}
	resourceScope, err := binding.owner.ResourceScope(scope)
	if err != nil {
		return nil, err
	}
	writes := selector.Operation != "get"
	if req.Resource != "settings" {
		writes = runtimeStorageOperationWrites(kind, selector.Operation)
	}
	if (!writes && !binding.owner.CanRead) || (writes && !binding.owner.CanWrite) {
		return nil, permissions.ErrPermissionDenied
	}
	ctx, _, release, err := h.resourceAction(ctx, action, target, scopedAuthorizationTarget(ResourcePlugin, record.PluginInstanceID, sessionctx.ScopeEnvironment))
	if err != nil {
		return nil, err
	}
	defer release()
	// Serialize finite operations against surface revocation; asynchronous streams
	// use lifetime cancellation instead of holding this fence.
	current, _, err := h.webSurface(ctx, req.WebSurfaceRequest)
	if err != nil {
		return nil, err
	}
	if !current.gatewayReady || current.ctx.Err() != nil {
		return nil, bridge.ErrAssetSessionRequired
	}
	h.webSurfaces.fileMu.RLock()
	defer h.webSurfaces.fileMu.RUnlock()
	h.webSurfaces.mu.Lock()
	live := h.webSurfaces.byOrigin[req.Origin]
	valid := live != nil && live.resourceToken == req.Token && live.ctx == current.ctx
	h.webSurfaces.mu.Unlock()
	if !valid {
		return nil, bridge.ErrTokenRevoked
	}
	ctx, cancel := context.WithDeadline(ctx, current.expiresAt)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, 5*time.Second)
	defer deadline()
	stop := context.AfterFunc(current.ctx, cancel)
	defer stop()
	if req.Resource == "settings" {
		if selector.Operation == "get" {
			var args struct {
				Operation string               `json:"operation"`
				Scope     sessionctx.ScopeKind `json:"scope"`
			}
			if err := decodeRuntimeIOJSON(req.Arguments, &args); err != nil {
				return nil, err
			}
			return h.GetPluginSettings(ctx, GetSettingsRequest{PluginInstanceID: record.PluginInstanceID, Scope: scope})
		}
		var args struct {
			Operation              string               `json:"operation"`
			Scope                  sessionctx.ScopeKind `json:"scope"`
			ExpectedValuesRevision uint64               `json:"expected_values_revision"`
			Set                    map[string]any       `json:"set"`
			Remove                 []string             `json:"remove,omitempty"`
		}
		if err := decodeRuntimeIOJSON(req.Arguments, &args); err != nil {
			return nil, err
		}
		return h.PatchPluginSettings(ctx, PatchSettingsRequest{PluginInstanceID: record.PluginInstanceID, Scope: scope, ExpectedValuesRevision: args.ExpectedValuesRevision, Set: args.Set, Remove: args.Remove})
	}
	session, err := binding.owner.SessionScope()
	if err != nil {
		return nil, err
	}
	ops := map[string]struct{}{}
	for _, op := range access.Operations {
		ops[op] = struct{}{}
	}
	invocation := hostRuntimeIORegistration{surfaceResource: true, resource: resourceio.Invocation{Owner: resourceio.Owner{PluginInstanceID: record.PluginInstanceID, ActiveFingerprint: record.ActiveFingerprint, Scope: resourceScope, Session: session}, CanRead: binding.owner.CanRead, CanWrite: binding.owner.CanWrite}, storage: map[string]hostRuntimeIOStorageAccess{access.StoreID: {kind: kind, scope: resourceScope, operations: ops}}}
	if writes {
		audit, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.storage.updated", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
		if err != nil {
			return nil, err
		}
		defer func() { retErr = audit.complete(context.WithoutCancel(ctx), retErr) }()
	}
	if kind == "kv" && selector.Operation == "batch" {
		var args struct {
			Operation string `json:"operation"`
			StoreID   string `json:"store_id"`
			Mutations []struct {
				Key          string  `json:"key"`
				Value        *string `json:"value_base64,omitempty"`
				Delete       bool    `json:"delete,omitempty"`
				ExpectedETag *string `json:"expected_etag,omitempty"`
			} `json:"mutations"`
		}
		if err := decodeRuntimeIOJSON(req.Arguments, &args); err != nil {
			return nil, err
		}
		broker, ok := h.runtimeIO.storageKV.(storage.KVBatchBroker)
		if !ok {
			return nil, errRuntimeIOStorageDenied
		}
		items := make([]storage.KVMutation, len(args.Mutations))
		for i, item := range args.Mutations {
			if item.Delete == (item.Value != nil) {
				return nil, errRuntimeIOInvalidRequest
			}
			var value []byte
			if item.Value != nil {
				var err error
				value, err = base64.StdEncoding.Strict().DecodeString(*item.Value)
				if err != nil {
					return nil, errRuntimeIOInvalidRequest
				}
			}
			items[i] = storage.KVMutation{Key: item.Key, Value: value, Delete: item.Delete, ExpectedETag: item.ExpectedETag}
		}
		return broker.BatchKV(ctx, storage.KVBatchRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: resourceScope, StoreID: selector.StoreID, Mutations: items})
	}
	args := map[string]json.RawMessage{}
	if err := json.Unmarshal(req.Arguments, &args); err != nil {
		return nil, errRuntimeIOInvalidRequest
	}
	// Resource control calls remain bounded even when callers bypass the SDK.
	for name, limit := range map[string]uint64{"max_bytes": 64 << 10, "max_entries": 100, "max_rows": 100, "max_response_bytes": 64 << 10, "timeout_ms": 5000} {
		applicable := (name == "max_bytes" && (selector.Operation == "get" || selector.Operation == "read")) || (name == "max_entries" && selector.Operation == "list") || ((name == "max_rows" || name == "max_response_bytes") && selector.Operation == "query") || (name == "timeout_ms" && kind == "sqlite")
		if !applicable {
			continue
		}
		value := limit
		if raw, ok := args[name]; ok {
			if json.Unmarshal(raw, &value) != nil || value == 0 || value > limit {
				return nil, resourceio.ErrResourceLimit
			}
		}
		args[name], _ = json.Marshal(value)
	}
	req.Arguments, _ = json.Marshal(args)
	return h.runtimeIO.dispatchStorage(ctx, invocation, runtimeIOControlRequest{Operation: "storage." + strings.TrimPrefix(req.Resource, "storage."), Arguments: req.Arguments})
}

// watchWebResource emits full snapshots and coalesces intermediate changes. It
// stores no second execution log and never holds the revocation fence while idle.
func (h *Host) watchWebResource(ctx context.Context, req WebResourceRequest, binding *webSurfaceBinding) (any, error) {
	var args struct {
		Operation string               `json:"operation"`
		StoreID   string               `json:"store_id,omitempty"`
		Key       string               `json:"key,omitempty"`
		Scope     sessionctx.ScopeKind `json:"scope,omitempty"`
		Cursor    *string              `json:"cursor,omitempty"`
	}
	if err := decodeRuntimeIOJSON(req.Arguments, &args); err != nil {
		return nil, err
	}
	if req.Resource != "storage.kv" && req.Resource != "settings" {
		return nil, errRuntimeIOInvalidRequest
	}
	if args.Cursor != nil && len(*args.Cursor) > 128 {
		return nil, errRuntimeIOInvalidRequest
	}
	releaseResource, err := h.reserveWebResource(req.WebSurfaceRequest, binding.ctx)
	if err != nil {
		return nil, err
	}
	defer releaseResource()
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	stop := context.AfterFunc(binding.ctx, cancel)
	defer stop()
	request := map[string]any{"operation": "get"}
	if req.Resource == "storage.kv" {
		request["store_id"] = args.StoreID
		request["key"] = args.Key
	} else {
		request["scope"] = args.Scope
	}
	raw, _ := json.Marshal(request)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		snapshot, err := h.WebResource(ctx, WebResourceRequest{WebSurfaceRequest: req.WebSurfaceRequest, Resource: req.Resource, Arguments: raw})
		found, cursor := true, ""
		if errors.Is(err, storage.ErrKVKeyNotFound) {
			found = false
			err = nil
		}
		if err != nil {
			return nil, err
		}
		if found {
			if req.Resource == "settings" {
				cursor = strconv.FormatUint(snapshot.(SettingsResult).ValuesRevision, 10)
			} else {
				cursor = snapshot.(map[string]any)["etag"].(string)
			}
		}
		if args.Cursor == nil || cursor != *args.Cursor {
			return map[string]any{"changed": true, "found": found, "cursor": cursor, "snapshot": snapshot}, nil
		}
		select {
		case <-ctx.Done():
			if binding.ctx.Err() != nil {
				return nil, bridge.ErrTokenRevoked
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return map[string]any{"changed": false, "cursor": cursor}, nil
			}
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// WebResourceError exposes stable broker errors without private paths or SQL.
func WebResourceError(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	if errors.Is(err, permissions.ErrPermissionDenied) {
		return "PERMISSION_DENIED", false
	}
	if errors.Is(err, bridge.ErrTokenRevoked) || errors.Is(err, bridge.ErrAssetSessionRequired) || errors.Is(err, context.Canceled) {
		return "RESOURCE_CLOSED", false
	}
	if errors.Is(err, storage.ErrRevisionConflict) || errors.Is(err, plugindata.ErrRevisionConflict) {
		return "CONFLICT", false
	}
	if errors.Is(err, resourceio.ErrResourceLimit) {
		return "RESOURCE_LIMIT", false
	}
	return runtimeIOStorageError(err)
}
