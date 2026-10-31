package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/floegence/redevplugin/v3/internal/dataupgradecontract"
	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/settings"
)

type pluginDataUpgradeContextKey struct{}

// Admission uses the existing execution registry lock so a concurrent start is
// either included in revocation or rejected before the data snapshot begins.
type pluginDataUpgradeAdmission struct{ pluginInstanceID string }

func (r *executionLeaseRegistry) beginDataUpgrade(pluginInstanceID string) (*pluginDataUpgradeAdmission, func(), error) {
	release := r.lockPlugin(pluginInstanceID, true)
	defer release()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dataUpgrades[pluginInstanceID] != nil {
		return nil, nil, capability.ErrExecutionRevoked
	}
	admission := &pluginDataUpgradeAdmission{pluginInstanceID: pluginInstanceID}
	r.dataUpgrades[pluginInstanceID] = admission
	return admission, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.dataUpgrades[pluginInstanceID] == admission {
			delete(r.dataUpgrades, pluginInstanceID)
		}
	}, nil
}

// This capability exists only inside the lifecycle write lock. It binds the
// verified target method to the still-current predecessor and isolated workspace.
type pluginDataUpgradeExecution struct {
	host           *Host
	previous, next registry.PluginRecord
	method         manifest.MethodSpec
	workspace      *plugindata.UpgradeWorkspace
	scope          sessionctx.ResourceScope
	session        sessionctx.Context
	runtime        runtimeclient.RuntimeBinding
	admission      *pluginDataUpgradeAdmission
	active         atomic.Bool
}

func dataUpgradeExecution(ctx context.Context) *pluginDataUpgradeExecution {
	value, _ := ctx.Value(pluginDataUpgradeContextKey{}).(*pluginDataUpgradeExecution)
	return value
}

func (u *pluginDataUpgradeExecution) validate(ctx context.Context, h *Host, fingerprint, method string) error {
	if !u.active.Load() || u.host != h || fingerprint != u.next.ActiveFingerprint || method != u.method.Method {
		return capability.ErrExecutionRevoked
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	session, err := sessionctx.Require(ctx)
	if err != nil || session != u.session {
		return capability.ErrExecutionRevoked
	}
	current, err := h.getPluginRecord(ctx, u.previous.PluginInstanceID)
	if err != nil || current.ActiveFingerprint != u.previous.ActiveFingerprint || current.Version != u.previous.Version || current.EnableState != u.previous.EnableState || registry.AuthorizationRevisionsFromRecord(current) != registry.AuthorizationRevisionsFromRecord(u.previous) {
		return capability.ErrExecutionRevoked
	}
	if _, err := h.checkRunnable(ctx, u.next); err != nil {
		return err
	}
	return nil
}

func pluginDataUpgradeRequired(current, next manifest.Manifest) (bool, error) {
	oldShape, err := plugindata.ShapeFromManifest(current)
	if err != nil {
		return false, err
	}
	newShape, err := plugindata.ShapeFromManifest(next)
	if err != nil {
		return false, err
	}
	oldHash, err := plugindata.HashShape(oldShape)
	if err != nil {
		return false, err
	}
	newHash, err := plugindata.HashShape(newShape)
	if err != nil {
		return false, err
	}
	if next.DataUpgrade != nil {
		for _, previous := range next.DataUpgrade.From {
			if previous.Version == current.Version() && previous.ShapeSHA256 == oldHash {
				return true, nil
			}
		}
	}
	if oldHash != newHash {
		return false, fmt.Errorf("%w: target package must declare this exact predecessor version and data shape", ErrPluginDataContractChanged)
	}
	return false, nil
}

func (h *Host) commitPluginDataUpgrade(ctx context.Context, current, next registry.PluginRecord, now time.Time, external bool) (result registry.PluginRecord, retErr error) {
	commitStarted := false
	defer func() {
		if retErr != nil && !commitStarted {
			retErr = &mutation.Error{Outcome: mutation.OutcomeNotCommitted, Err: retErr}
		}
	}()
	if h.controlStore == nil {
		return registry.PluginRecord{}, ErrControlStoreRequired
	}
	store := h.adapters.PluginData
	now = lifecycleNow(now)
	if needed, err := pluginDataUpgradeRequired(current.Manifest, next.Manifest); err != nil || !needed {
		if err == nil {
			err = ErrPluginDataContractChanged
		}
		return registry.PluginRecord{}, err
	}
	spec := next.Manifest.DataUpgrade
	ctx, cancel := context.WithTimeout(ctx, time.Duration(spec.MaxRuntimeMS)*time.Millisecond)
	defer cancel()
	next.OwnerEnvHash = current.OwnerEnvHash
	// Conversion leases retain the predecessor's revision until the one durable
	// package/data transaction increments it. They never authorize normal calls.
	next.PolicyRevision, next.ManagementRevision, next.RevokeEpoch = current.PolicyRevision, current.ManagementRevision, current.RevokeEpoch
	method, ok := manifestMethod(next.Manifest, spec.Method)
	if !ok {
		return registry.PluginRecord{}, ErrMethodRequestContract
	}
	if _, err := h.checkRunnable(ctx, next); err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.ensureWorkerRuntimeReady(ctx, next); err != nil {
		return registry.PluginRecord{}, err
	}
	binding, err := h.bindCompatibleWorkerRuntime(ctx, next)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.prewarmWorkerModules(ctx, next); err != nil {
		return registry.PluginRecord{}, err
	}
	admission, resumeAdmission, err := h.executions.beginDataUpgrade(current.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer resumeAdmission()
	// Fence new execution leases before revoking existing leases. The data
	// store write lock also drains broker accesses before taking the snapshot.
	if err := h.revokePluginRuntimeCapabilities(ctx, current, now); err != nil {
		return registry.PluginRecord{}, err
	}
	previous, found, err := h.controlStore.GetBinding(ctx, current.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if !found {
		return registry.PluginRecord{}, plugindata.ErrBindingNotFound
	}
	shape, err := plugindata.ShapeFromManifest(next.Manifest)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	var stored registry.PluginRecord
	_, err = store.Upgrade(ctx, plugindata.UpgradeRequest{Expected: previous, TargetShape: shape, MaxBytes: spec.MaxBytes}, func(ctx context.Context, workspace *plugindata.UpgradeWorkspace) error {
		for _, scope := range workspace.Scopes() {
			session, err := sessionctx.Require(ctx)
			if err != nil {
				return err
			}
			if scope.Kind == sessionctx.ScopeUser {
				session.OwnerUserHash = scope.OwnerUserHash
			}
			// The management action authorizes conversion of this instance's data;
			// per-scope Worker invocations cannot cross into another user's scope.
			session.CanRead, session.CanWrite = true, true
			invocationCtx := sessionctx.WithContext(ctx, session)
			u := &pluginDataUpgradeExecution{host: h, previous: current, next: next, method: method, workspace: workspace, scope: scope, session: session, runtime: binding, admission: admission}
			u.active.Store(true)
			invocationCtx = context.WithValue(invocationCtx, pluginDataUpgradeContextKey{}, u)
			_, err = h.dispatchMethod(invocationCtx, next, method, CallMethodRequest{PluginInstanceID: current.PluginInstanceID, Method: method.Method, Params: map[string]any{"from_version": current.Version, "to_version": next.Version, "scope": string(scope.Kind)}, session: session, Now: now})
			u.active.Store(false)
			if err != nil {
				return err
			}
		}
		return nil
	}, func(ctx context.Context, previous, active plugindata.Binding) error {
		commitStarted = true
		var err error
		stored, err = h.controlStore.CommitPluginDataUpgrade(ctx, current, next, previous, active, now, external)
		return err
	})
	return stored, err
}

// The upgrade API wraps the existing storage operations. It exposes neither
// filesystem paths nor ordinary runtime resources, grants, or network handles.
func (broker *hostRuntimeIOBroker) dispatchUpgrade(ctx context.Context, invocation hostRuntimeIORegistration, request runtimeIOControlRequest) (any, error) {
	u := invocation.upgrade
	if u == nil || !u.active.Load() {
		return nil, errRuntimeIOStorageDenied
	}
	if err := u.validate(sessionctx.WithContext(ctx, u.session), u.host, invocation.resource.Owner.ActiveFingerprint, u.method.Method); err != nil {
		return nil, err
	}
	if request.Operation != "data.upgrade" {
		return nil, errRuntimeIOStorageDenied
	}
	var args struct {
		Dataset string          `json:"dataset"`
		Kind    string          `json:"kind"`
		Request json.RawMessage `json:"request"`
	}
	if err := decodeRuntimeIOJSON(request.Arguments, &args); err != nil || args.Dataset != "input" && args.Dataset != "output" {
		return nil, errRuntimeIOInvalidRequest
	}
	output := args.Dataset == "output"
	var operation struct{ Operation string }
	if err := json.Unmarshal(args.Request, &operation); err != nil {
		return nil, errRuntimeIOInvalidRequest
	}
	if !output && (args.Kind == "settings" && operation.Operation == "write" || args.Kind != "settings" && runtimeStorageOperationWrites(args.Kind, operation.Operation)) {
		return nil, errRuntimeIOStorageDenied
	}
	raw, err := json.Marshal(request)
	if err != nil || dataupgradecontract.Validate(raw) != nil {
		return nil, errRuntimeIOInvalidRequest
	}
	if args.Kind == "settings" {
		var value struct {
			Operation string                     `json:"operation"`
			Values    map[string]json.RawMessage `json:"values,omitempty"`
		}
		if err := decodeRuntimeIOJSON(args.Request, &value); err != nil {
			return nil, errRuntimeIOInvalidRequest
		}
		if value.Operation == "read" && value.Values == nil {
			return u.workspace.ReadSettings(ctx, output, u.scope)
		}
		if value.Operation == "write" && output && value.Values != nil {
			if err := u.workspace.WriteSettings(ctx, u.scope, value.Values); err != nil {
				if errors.Is(err, settings.ErrInvalidSetting) {
					return nil, errRuntimeIOInvalidRequest
				}
				return nil, err
			}
			return map[string]bool{"ok": true}, nil
		}
		return nil, errRuntimeIOStorageDenied
	}
	var selector struct {
		Operation string `json:"operation"`
		StoreID   string `json:"store_id"`
	}
	if err := json.Unmarshal(args.Request, &selector); err != nil || strings.TrimSpace(selector.StoreID) == "" || !validRuntimeStorageOperation(args.Kind, selector.Operation) || !output && runtimeStorageOperationWrites(args.Kind, selector.Operation) {
		return nil, errRuntimeIOStorageDenied
	}
	if output {
		ctx, err = u.workspace.OutputContext(ctx, u.scope)
	} else {
		ctx, err = u.workspace.InputContext(ctx, u.scope)
	}
	if err != nil {
		return nil, err
	}
	switch args.Kind {
	case "files":
		return broker.dispatchStorageFiles(ctx, u.next.PluginInstanceID, u.scope, selector.Operation, args.Request)
	case "kv":
		return broker.dispatchStorageKV(ctx, u.next.PluginInstanceID, u.scope, selector.Operation, args.Request)
	case "sqlite":
		return broker.dispatchStorageSQLite(ctx, u.next.PluginInstanceID, u.scope, selector.Operation, args.Request)
	default:
		return nil, errRuntimeIOStorageDenied
	}
}
