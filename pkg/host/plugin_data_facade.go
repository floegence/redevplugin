package host

import (
	"context"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

type InspectPluginDataRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type PluginDataObjectInspection struct {
	Scope  sessionctx.ScopeKind `json:"scope"`
	Object plugindata.Object    `json:"object"`
}

type PluginDataInspection struct {
	Bindings        []plugindata.Binding         `json:"bindings"`
	Objects         []PluginDataObjectInspection `json:"objects"`
	Namespaces      []storage.NamespaceRecord    `json:"namespaces"`
	TotalUsageBytes int64                        `json:"total_usage_bytes"`
	TotalUsageFiles int64                        `json:"total_usage_files"`
}

type ReadPluginDataFileRequest struct {
	PluginInstanceID string               `json:"plugin_instance_id"`
	Scope            sessionctx.ScopeKind `json:"scope"`
	StoreID          string               `json:"store_id"`
	Path             string               `json:"path"`
	MaxBytes         int64                `json:"max_bytes,omitempty"`
}

type WritePluginDataFileRequest struct {
	PluginInstanceID string               `json:"plugin_instance_id"`
	Scope            sessionctx.ScopeKind `json:"scope"`
	StoreID          string               `json:"store_id"`
	Path             string               `json:"path"`
	Data             []byte               `json:"-"`
}

func (h *Host) InspectPluginData(ctx context.Context, req InspectPluginDataRequest) (PluginDataInspection, error) {
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	_, err := h.authorizeManagement(ctx, ManagementActionInspectPluginData,
		scopedAuthorizationTargetOrCollection(ResourcePluginData, req.PluginInstanceID, sessionctx.ScopeEnvironment),
	)
	if err != nil {
		return PluginDataInspection{}, err
	}
	bindings, err := h.inspectPluginDataBindings(ctx, req.PluginInstanceID)
	if err != nil {
		return PluginDataInspection{}, err
	}
	result := PluginDataInspection{
		Bindings:   bindings,
		Objects:    []PluginDataObjectInspection{},
		Namespaces: []storage.NamespaceRecord{},
	}
	for _, binding := range bindings {
		for _, scopeKind := range []sessionctx.ScopeKind{sessionctx.ScopeUser, sessionctx.ScopeEnvironment} {
			objects, err := h.inspectPluginDataObjects(ctx, binding.PluginInstanceID, scopeKind)
			if err != nil {
				return PluginDataInspection{}, err
			}
			for _, object := range objects {
				result.Objects = append(result.Objects, PluginDataObjectInspection{Scope: scopeKind, Object: object})
			}
		}
		namespaces, err := h.adapters.PluginData.ListNamespaces(ctx, binding.PluginInstanceID)
		if err != nil {
			return PluginDataInspection{}, err
		}
		for index := range namespaces {
			usage, err := h.adapters.PluginData.Usage(ctx, binding.PluginInstanceID, namespaces[index].StoreID)
			if err != nil {
				return PluginDataInspection{}, err
			}
			namespaces[index].UsageBytes = usage.UsageBytes
			namespaces[index].UsageFiles = usage.UsageFiles
			namespaces[index].QuotaBytes = usage.QuotaBytes
			namespaces[index].QuotaFiles = usage.QuotaFiles
			result.TotalUsageBytes += usage.UsageBytes
			result.TotalUsageFiles += usage.UsageFiles
		}
		result.Namespaces = append(result.Namespaces, namespaces...)
	}
	return result, nil
}

func (h *Host) inspectPluginDataBindings(ctx context.Context, pluginInstanceID string) ([]plugindata.Binding, error) {
	result := []plugindata.Binding{}
	for cursor := ""; ; {
		page, next, err := h.controlStore.ListBindings(ctx, cursor, 256)
		if err != nil {
			return nil, err
		}
		for _, binding := range page {
			if pluginInstanceID == "" || binding.PluginInstanceID == pluginInstanceID {
				result = append(result, binding)
			}
		}
		if next == "" {
			return result, nil
		}
		cursor = next
	}
}

func (h *Host) inspectPluginDataObjects(ctx context.Context, pluginInstanceID string, scope sessionctx.ScopeKind) ([]plugindata.Object, error) {
	result := []plugindata.Object{}
	for cursor := ""; ; {
		page, next, err := h.controlStore.ListObjects(ctx, scope, pluginInstanceID, cursor, 256)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if next == "" {
			return result, nil
		}
		cursor = next
	}
}

func (h *Host) ReadPluginDataFile(ctx context.Context, req ReadPluginDataFileRequest) (storage.FileReadResult, error) {
	scope, err := h.authorizedPluginDataFileScope(ctx, ManagementActionReadPluginDataFile, req.PluginInstanceID, req.Scope)
	if err != nil {
		return storage.FileReadResult{}, err
	}
	return h.adapters.PluginData.ReadFile(ctx, storage.FileReadRequest{
		PluginInstanceID: strings.TrimSpace(req.PluginInstanceID), ResourceScope: scope,
		StoreID: strings.TrimSpace(req.StoreID), Path: req.Path, MaxBytes: req.MaxBytes,
	})
}

func (h *Host) WritePluginDataFile(ctx context.Context, req WritePluginDataFileRequest) (storage.FileWriteResult, error) {
	scope, err := h.authorizedPluginDataFileScope(ctx, ManagementActionWritePluginDataFile, req.PluginInstanceID, req.Scope)
	if err != nil {
		return storage.FileWriteResult{}, err
	}
	return h.adapters.PluginData.WriteFile(ctx, storage.FileWriteRequest{
		PluginInstanceID: strings.TrimSpace(req.PluginInstanceID), ResourceScope: scope,
		StoreID: strings.TrimSpace(req.StoreID), Path: req.Path, Data: append([]byte(nil), req.Data...),
	})
}

func (h *Host) authorizedPluginDataFileScope(ctx context.Context, action ManagementAction, pluginInstanceID string, scopeKind sessionctx.ScopeKind) (sessionctx.ResourceScope, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	authorization, err := h.authorizeManagement(ctx, action,
		scopedAuthorizationTarget(ResourcePluginData, pluginInstanceID, scopeKind),
		scopedAuthorizationTarget(ResourcePlugin, pluginInstanceID, sessionctx.ScopeEnvironment),
	)
	if err != nil {
		return sessionctx.ResourceScope{}, err
	}
	return authorization.session.ResourceScope(scopeKind)
}
