package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

func DecodeModel(r io.Reader) (Model, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if err != nil {
		return Model{}, err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return Model{}, fmt.Errorf("manifest exceeds 1 MiB")
	}
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return Model{}, err
	}
	switch header.SchemaVersion {
	case SchemaVersionV8:
		legacy, err := decodeV8(bytes.NewReader(raw))
		if err != nil {
			return Model{}, err
		}
		return normalizeV8(legacy)
	case SchemaVersionV9:
		return decodeV9(raw)
	default:
		return Model{}, ValidationError{Field: "schema_version", Message: "unsupported manifest schema"}
	}
}

func canonicalManifestJSON(raw []byte) ([]byte, error) {
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, err
	}
	if header.SchemaVersion == SchemaVersionV9 {
		return releasecontract.CanonicalJSON(raw)
	}
	legacy, err := decodeV8(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	// v8's published hash input is the typed encoding and must never be
	// replaced by the lossless v9 canonicalizer.
	return json.Marshal(legacy)
}

// CanonicalJSON returns the exact hash input for either the frozen v8 typed
// manifest or the forward-compatible v9 lossless document.
func CanonicalJSON(raw []byte) ([]byte, error) { return canonicalManifestJSON(raw) }

func normalizeV8(legacy Manifest) (Model, error) {
	model := Model{Manifest: legacy, SchemaSource: SchemaVersionV8}
	surface, worker := uint16(1), uint16(1)
	model.API.Surface = &surface
	model.API.Worker = &worker
	features := map[FeatureID]struct{}{}
	if legacy.NetworkAccess != nil {
		for _, connector := range legacy.NetworkAccess.Connectors {
			switch connector.Transport {
			case "http":
				features[FeatureNetHTTP] = struct{}{}
			case "websocket":
				features[FeatureNetWebSocket] = struct{}{}
			case "tcp":
				features[FeatureNetTCP] = struct{}{}
			case "udp":
				features[FeatureNetUDP] = struct{}{}
			}
		}
	}
	for feature := range features {
		model.API.RequiredFeatures = append(model.API.RequiredFeatures, feature)
	}
	sort.Slice(model.API.RequiredFeatures, func(i, j int) bool { return model.API.RequiredFeatures[i] < model.API.RequiredFeatures[j] })
	if legacy.NetworkAccess != nil && len(legacy.NetworkAccess.Connectors) > 0 {
		model.Permissions = []PermissionID{PermissionNetworkClient}
	}
	return model, nil
}

// Normalize converts a previously decoded manifest into the current behavior
// model. It is used by durable-record migration and legacy callers.
func Normalize(legacy Manifest) (Model, error) { return normalizeV8(legacy) }

// RestoreModel rebuilds the normalized behavior projection persisted by the
// registry. The manifest payload remains the legacy-compatible typed form;
// source and public API fields carry the author schema facts not represented
// in that payload.
func RestoreModel(legacy Manifest, source string, api PublicAPIRequirement, permissions []PermissionID) (Model, error) {
	if source == "" || source == SchemaVersionV8 {
		return normalizeV8(legacy)
	}
	if source != SchemaVersionV9 {
		return Model{}, ValidationError{Field: "manifest_schema_source", Message: "unsupported manifest source"}
	}
	normalizedAPI, err := normalizePublicAPI(api)
	if err != nil {
		return Model{}, err
	}
	normalizedPermissions, err := normalizePermissions(permissions)
	if err != nil {
		return Model{}, err
	}
	if legacy.SchemaVersion != SchemaVersionV8 {
		return Model{}, ValidationError{Field: "manifest.schema_version", Message: "persisted normalized manifest must use v8 payload"}
	}
	if err := Validate(legacy); err != nil {
		return Model{}, err
	}
	return Model{Manifest: legacy, SchemaSource: SchemaVersionV9, API: normalizedAPI, Permissions: normalizedPermissions}, nil
}

type v9Document struct {
	SchemaVersion string               `json:"schema_version"`
	Publisher     Publisher            `json:"publisher"`
	Plugin        v9Plugin             `json:"plugin"`
	API           PublicAPIRequirement `json:"api"`
	Permissions   []PermissionID       `json:"permissions"`
	Presentation  v9Presentation       `json:"presentation"`
	Surfaces      []SurfaceSpec        `json:"surfaces"`
	Workers       []v9Worker           `json:"workers"`
	Methods       []v9Method           `json:"methods"`
	Storage       *StorageSpec         `json:"storage,omitempty"`
	Settings      *SettingsSpec        `json:"settings,omitempty"`
}

type v9Plugin struct {
	PluginID    string `json:"plugin_id"`
	DisplayName string `json:"display_name"`
	Version     string `json:"version"`
}

type v9Presentation struct {
	Icon    *PresentationIconSpec `json:"icon,omitempty"`
	Locales struct {
		Default string `json:"default"`
	} `json:"locales"`
}

type v9Worker struct {
	WorkerID         string     `json:"worker_id"`
	Artifact         string     `json:"artifact"`
	Mode             WorkerMode `json:"mode"`
	Scope            string     `json:"scope"`
	MemoryLimitBytes int64      `json:"memory_limit_bytes"`
}

type v9Method struct {
	Method         string              `json:"method"`
	WorkerID       string              `json:"worker_id"`
	Effect         MethodEffect        `json:"effect"`
	Execution      MethodExecutionMode `json:"execution"`
	RequestSchema  map[string]any      `json:"request_schema"`
	ResponseSchema map[string]any      `json:"response_schema"`
}

func decodeV9(raw []byte) (Model, error) {
	canonical, err := canonicalManifestJSON(raw)
	if err != nil {
		return Model{}, err
	}
	_ = canonical // package hashing retains these bytes; Model only owns behavior.
	var document v9Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&document); err != nil {
		return Model{}, err
	}
	if document.SchemaVersion != SchemaVersionV9 {
		return Model{}, ValidationError{Field: "schema_version", Message: "must be redevplugin.manifest.v9"}
	}
	normalizedAPI, err := normalizePublicAPI(document.API)
	if err != nil {
		return Model{}, err
	}
	permissions, err := normalizePermissions(document.Permissions)
	if err != nil {
		return Model{}, err
	}
	legacy := Manifest{
		SchemaVersion: SchemaVersionV8,
		Publisher:     document.Publisher,
		Plugin:        Plugin{PluginID: document.Plugin.PluginID, DisplayName: document.Plugin.DisplayName, Version: document.Plugin.Version, APIVersion: "plugin-v1", MinRuntimeVersion: "0.0.0", UIProtocolVersion: "plugin-ui-v7"},
		Presentation:  PresentationSpec{DefaultLocale: document.Presentation.Locales.Default, Summary: document.Plugin.DisplayName, Description: []string{document.Plugin.DisplayName}, Highlights: []string{}, Keywords: []string{document.Plugin.DisplayName}, Localizations: []PresentationLocalizationSpec{}, Icon: document.Presentation.Icon},
		Surfaces:      document.Surfaces,
		Storage:       document.Storage,
		Settings:      document.Settings,
	}
	for _, worker := range document.Workers {
		legacy.Workers = append(legacy.Workers, WorkerSpec{WorkerID: worker.WorkerID, Artifact: worker.Artifact, ABI: "redevplugin-wasm-worker-v2", Mode: worker.Mode, Scope: worker.Scope, MemoryLimitBytes: worker.MemoryLimitBytes})
	}
	for _, method := range document.Methods {
		legacy.Methods = append(legacy.Methods, MethodSpec{Method: method.Method, Effect: method.Effect, Execution: method.Execution, Route: MethodRouteSpec{Kind: MethodRouteWorker, WorkerID: method.WorkerID}, RequestSchema: method.RequestSchema, ResponseSchema: method.ResponseSchema})
	}
	if err := Validate(legacy); err != nil {
		return Model{}, err
	}
	return Model{Manifest: legacy, SchemaSource: SchemaVersionV9, API: normalizedAPI, Permissions: permissions}, nil
}

func normalizePublicAPI(api PublicAPIRequirement) (PublicAPIRequirement, error) {
	if api.Surface == nil || *api.Surface != 1 {
		return PublicAPIRequirement{}, ValidationError{Field: "api.surface", Message: "must be 1"}
	}
	if api.Worker == nil || *api.Worker != 1 {
		return PublicAPIRequirement{}, ValidationError{Field: "api.worker", Message: "must be 1"}
	}
	normalized := PublicAPIRequirement{Surface: api.Surface, Worker: api.Worker}
	seen := map[FeatureID]string{}
	for _, feature := range api.RequiredFeatures {
		if !knownFeature(feature) {
			return PublicAPIRequirement{}, fmt.Errorf("%w: %s", ErrUnsupportedFeature, feature)
		}
		if prior := seen[feature]; prior != "" {
			return PublicAPIRequirement{}, ValidationError{Field: "api.required_features", Message: "must not contain duplicates"}
		}
		seen[feature] = "required"
		normalized.RequiredFeatures = append(normalized.RequiredFeatures, feature)
	}
	for _, feature := range api.OptionalFeatures {
		if !knownFeature(feature) {
			continue
		}
		if prior := seen[feature]; prior != "" {
			return PublicAPIRequirement{}, ValidationError{Field: "api.optional_features", Message: "must not duplicate required or optional features"}
		}
		seen[feature] = "optional"
		normalized.OptionalFeatures = append(normalized.OptionalFeatures, feature)
	}
	sort.Slice(normalized.RequiredFeatures, func(i, j int) bool { return normalized.RequiredFeatures[i] < normalized.RequiredFeatures[j] })
	sort.Slice(normalized.OptionalFeatures, func(i, j int) bool { return normalized.OptionalFeatures[i] < normalized.OptionalFeatures[j] })
	return normalized, nil
}

func knownFeature(feature FeatureID) bool {
	switch feature {
	case FeatureIOStream, FeatureFSWorkspace, FeatureFSHome, FeatureFSEnvironment, FeatureFSWatch, FeatureNetHTTP, FeatureNetWebSocket, FeatureNetTCP, FeatureNetUDP:
		return true
	default:
		return false
	}
}

func normalizePermissions(values []PermissionID) ([]PermissionID, error) {
	seen := map[PermissionID]struct{}{}
	result := make([]PermissionID, 0, len(values))
	for _, value := range values {
		if !knownPermission(value) {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedPermission, value)
		}
		if _, ok := seen[value]; ok {
			return nil, ValidationError{Field: "permissions", Message: "must not contain duplicates"}
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func knownPermission(value PermissionID) bool {
	switch value {
	case PermissionFSWorkspaceRead, PermissionFSWorkspaceWrite, PermissionFSHomeRead, PermissionFSHomeWrite, PermissionFSEnvironmentRead, PermissionFSEnvironmentWrite, PermissionNetworkClient, PermissionNetworkListen:
		return true
	default:
		return false
	}
}

func decodeV8(r io.Reader) (Manifest, error) {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	var m Manifest
	if err := decoder.Decode(&m); err != nil {
		return Manifest{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return Manifest{}, err
		}
		return Manifest{}, fmt.Errorf("manifest contains trailing JSON values")
	}
	return m, Validate(m)
}

func (m Model) String() string { return strings.TrimSpace(m.PluginID()) }
