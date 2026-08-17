package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
)

func decodeCurrent(r io.Reader) (Manifest, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if err != nil {
		return Manifest{}, err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return Manifest{}, fmt.Errorf("manifest exceeds 1 MiB")
	}
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return Manifest{}, err
	}
	switch header.SchemaVersion {
	case SchemaVersionV9:
		return decodeV9(raw)
	default:
		return Manifest{}, ValidationError{Field: "schema_version", Message: "unsupported manifest schema"}
	}
}

func canonicalManifestJSON(raw []byte) ([]byte, error) {
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, err
	}
	if header.SchemaVersion != SchemaVersionV9 {
		return nil, ValidationError{Field: "schema_version", Message: "unsupported manifest schema"}
	}
	return releasecontract.CanonicalJSON(raw)
}

// CanonicalJSON returns the exact hash input for the current manifest.
func CanonicalJSON(raw []byte) ([]byte, error) { return canonicalManifestJSON(raw) }

// MarshalCanonical returns the current manifest wire representation. Package
// installation should retain the original canonical bytes; this encoder is for
// current in-memory records and deterministic tests only.
func MarshalCanonical(current Manifest) ([]byte, error) {
	if err := Validate(current); err != nil {
		return nil, err
	}
	document := v9Document{
		SchemaVersion:      current.SchemaVersion,
		Publisher:          current.Publisher,
		Plugin:             v9Plugin{PluginID: current.Plugin.PluginID, DisplayName: current.Plugin.DisplayName, Version: current.Plugin.Version},
		API:                current.API,
		Permissions:        append([]PermissionID{}, current.Permissions...),
		Surfaces:           append([]SurfaceSpec{}, current.Surfaces...),
		CapabilityBindings: append([]CapabilityBinding(nil), current.CapabilityBindings...),
		Workers:            []v9Worker{},
		Methods:            append([]MethodSpec{}, current.Methods...),
		Storage:            current.Storage,
		NetworkAccess:      current.NetworkAccess,
		Settings:           current.Settings,
		Intents:            append([]IntentSpec(nil), current.Intents...),
	}
	document.Presentation.Icon = current.Presentation.Icon
	document.Presentation.Locales.Default = current.Presentation.DefaultLocale
	for _, worker := range current.Workers {
		document.Workers = append(document.Workers, v9Worker{WorkerID: worker.WorkerID, Artifact: worker.Artifact, Mode: worker.Mode, Scope: worker.Scope, MemoryLimitBytes: worker.MemoryLimitBytes})
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return canonicalManifestJSON(raw)
}

type v9Document struct {
	SchemaVersion      string               `json:"schema_version"`
	Publisher          Publisher            `json:"publisher"`
	Plugin             v9Plugin             `json:"plugin"`
	API                PublicAPIRequirement `json:"api"`
	Permissions        []PermissionID       `json:"permissions"`
	Presentation       v9Presentation       `json:"presentation"`
	Surfaces           []SurfaceSpec        `json:"surfaces"`
	CapabilityBindings []CapabilityBinding  `json:"capability_bindings,omitempty"`
	Workers            []v9Worker           `json:"workers"`
	Methods            []MethodSpec         `json:"methods"`
	Storage            *StorageSpec         `json:"storage,omitempty"`
	NetworkAccess      *NetworkAccessSpec   `json:"network_access,omitempty"`
	Settings           *SettingsSpec        `json:"settings,omitempty"`
	Intents            []IntentSpec         `json:"intents,omitempty"`
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

func decodeV9(raw []byte) (Manifest, error) {
	canonical, err := canonicalManifestJSON(raw)
	if err != nil {
		return Manifest{}, err
	}
	_ = canonical // pluginpkg retains these bytes as the signing and hash authority.
	var document v9Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Manifest{}, err
	}
	if document.SchemaVersion != SchemaVersionV9 {
		return Manifest{}, ValidationError{Field: "schema_version", Message: "must be redevplugin.manifest.v9"}
	}
	for _, required := range []struct {
		field   string
		present bool
	}{
		{field: "permissions", present: document.Permissions != nil},
		{field: "surfaces", present: document.Surfaces != nil},
		{field: "workers", present: document.Workers != nil},
		{field: "methods", present: document.Methods != nil},
	} {
		if !required.present {
			return Manifest{}, ValidationError{Field: required.field, Message: "is required"}
		}
	}
	normalizedAPI, err := normalizePublicAPI(document.API)
	if err != nil {
		return Manifest{}, err
	}
	permissions, err := normalizePermissions(document.Permissions)
	if err != nil {
		return Manifest{}, err
	}
	current := Manifest{
		SchemaVersion:      SchemaVersionV9,
		Publisher:          document.Publisher,
		Plugin:             Plugin{PluginID: document.Plugin.PluginID, DisplayName: document.Plugin.DisplayName, Version: document.Plugin.Version},
		API:                normalizedAPI,
		Permissions:        permissions,
		Presentation:       PresentationSpec{DefaultLocale: document.Presentation.Locales.Default, Summary: document.Plugin.DisplayName, Description: []string{document.Plugin.DisplayName}, Highlights: []string{}, Keywords: []string{document.Plugin.DisplayName}, Localizations: []PresentationLocalizationSpec{}, Icon: document.Presentation.Icon},
		Surfaces:           document.Surfaces,
		CapabilityBindings: document.CapabilityBindings,
		Methods:            document.Methods,
		Storage:            document.Storage,
		NetworkAccess:      document.NetworkAccess,
		Settings:           document.Settings,
		Intents:            document.Intents,
	}
	for _, worker := range document.Workers {
		current.Workers = append(current.Workers, WorkerSpec{WorkerID: worker.WorkerID, Artifact: worker.Artifact, Mode: worker.Mode, Scope: worker.Scope, MemoryLimitBytes: worker.MemoryLimitBytes})
	}
	if err := Validate(current); err != nil {
		return Manifest{}, err
	}
	return current, nil
}

func normalizePublicAPI(api PublicAPIRequirement) (PublicAPIRequirement, error) {
	if api.Major != PluginAPIMajor {
		return PublicAPIRequirement{}, ValidationError{Field: "api.major", Message: "must be 1"}
	}
	normalized := PublicAPIRequirement{Major: api.Major}
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
