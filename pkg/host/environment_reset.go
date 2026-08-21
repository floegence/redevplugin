package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
)

const EnvironmentResetOwnershipManifestSchemaV1 = "redevplugin.environment_reset_ownership.v1"

var (
	ErrEnvironmentResetRequest = errors.New("invalid ReDevPlugin environment reset request")
	ErrEnvironmentResetBlocked = errors.New("ReDevPlugin environment reset is blocked")
)

type EnvironmentResetDataKind string

const (
	EnvironmentResetHostControl        EnvironmentResetDataKind = "host_control"
	EnvironmentResetPluginData         EnvironmentResetDataKind = "plugin_data"
	EnvironmentResetExternalInspection EnvironmentResetDataKind = "external_inspections"
	EnvironmentResetAssets             EnvironmentResetDataKind = "assets"
	EnvironmentResetObservability      EnvironmentResetDataKind = "observability"
	EnvironmentResetSecrets            EnvironmentResetDataKind = "secrets"
	EnvironmentResetRuntimeExecution   EnvironmentResetDataKind = "runtime_execution"
	EnvironmentResetReleaseArtifacts   EnvironmentResetDataKind = "release_artifacts"
	EnvironmentResetTrust              EnvironmentResetDataKind = "trust"
)

type EnvironmentResetOwnershipEntry struct {
	Kind         EnvironmentResetDataKind `json:"kind"`
	RelativePath string                   `json:"relative_path"`
}

type EnvironmentResetOwnershipManifest struct {
	SchemaVersion string                           `json:"schema_version"`
	EnvironmentID string                           `json:"environment_id"`
	Entries       []EnvironmentResetOwnershipEntry `json:"entries"`
	SHA256        string                           `json:"sha256"`
}

type EnvironmentResetRequest struct {
	StateRoot         string                            `json:"state_root"`
	OperationID       string                            `json:"operation_id"`
	OwnershipManifest EnvironmentResetOwnershipManifest `json:"ownership_manifest"`
}

type EnvironmentResetPreflight struct {
	EnvironmentID           string                           `json:"environment_id"`
	OperationID             string                           `json:"operation_id"`
	OwnershipManifestSHA256 string                           `json:"ownership_manifest_sha256"`
	DeleteEntries           []EnvironmentResetOwnershipEntry `json:"delete_entries"`
}

type EnvironmentResetResult struct {
	EnvironmentID           string                           `json:"environment_id"`
	OperationID             string                           `json:"operation_id"`
	OwnershipManifestSHA256 string                           `json:"ownership_manifest_sha256"`
	ResetEntries            []EnvironmentResetOwnershipEntry `json:"reset_entries"`
}

var environmentResetPaths = map[EnvironmentResetDataKind]string{
	EnvironmentResetHostControl:        "control.sqlite",
	EnvironmentResetPluginData:         "plugin-data",
	EnvironmentResetExternalInspection: "external-inspections",
	EnvironmentResetAssets:             "assets",
	EnvironmentResetObservability:      "observability.sqlite",
	EnvironmentResetSecrets:            "secrets.sqlite",
	EnvironmentResetRuntimeExecution:   "runtime-exec",
	EnvironmentResetReleaseArtifacts:   "release-artifacts",
	EnvironmentResetTrust:              "trust",
}

// NewEnvironmentResetOwnershipManifest returns the canonical manifest for the
// selected platform-owned data categories. Hosts should persist this manifest
// next to their target ownership metadata before a reset is ever needed.
func NewEnvironmentResetOwnershipManifest(environmentID string, kinds ...EnvironmentResetDataKind) (EnvironmentResetOwnershipManifest, error) {
	environmentID = strings.TrimSpace(environmentID)
	if environmentID == "" || len(environmentID) > 256 {
		return EnvironmentResetOwnershipManifest{}, fmt.Errorf("%w: environment_id is required", ErrEnvironmentResetRequest)
	}
	unique := make(map[EnvironmentResetDataKind]struct{}, len(kinds))
	entries := make([]EnvironmentResetOwnershipEntry, 0, len(kinds))
	for _, kind := range kinds {
		path, ok := environmentResetPaths[kind]
		if !ok {
			return EnvironmentResetOwnershipManifest{}, fmt.Errorf("%w: unknown data kind %q", ErrEnvironmentResetRequest, kind)
		}
		if _, exists := unique[kind]; exists {
			return EnvironmentResetOwnershipManifest{}, fmt.Errorf("%w: duplicate data kind %q", ErrEnvironmentResetRequest, kind)
		}
		unique[kind] = struct{}{}
		entries = append(entries, EnvironmentResetOwnershipEntry{Kind: kind, RelativePath: path})
	}
	if len(entries) == 0 {
		return EnvironmentResetOwnershipManifest{}, fmt.Errorf("%w: at least one owned data kind is required", ErrEnvironmentResetRequest)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Kind < entries[right].Kind })
	manifest := EnvironmentResetOwnershipManifest{
		SchemaVersion: EnvironmentResetOwnershipManifestSchemaV1,
		EnvironmentID: environmentID,
		Entries:       entries,
	}
	digest, err := environmentResetManifestDigest(manifest)
	if err != nil {
		return EnvironmentResetOwnershipManifest{}, err
	}
	manifest.SHA256 = digest
	return manifest, nil
}

func PreflightEnvironmentReset(ctx context.Context, request EnvironmentResetRequest) (EnvironmentResetPreflight, error) {
	normalized, err := normalizeEnvironmentResetRequest(ctx, request)
	if err != nil {
		return EnvironmentResetPreflight{}, err
	}
	lock, err := acquireEnvironmentRootLock(normalized.StateRoot, false)
	if err != nil {
		return EnvironmentResetPreflight{}, err
	}
	defer lock.Close()
	if err := validateEnvironmentResetEntries(normalized.StateRoot, normalized.OwnershipManifest.Entries); err != nil {
		return EnvironmentResetPreflight{}, err
	}
	return EnvironmentResetPreflight{
		EnvironmentID:           normalized.OwnershipManifest.EnvironmentID,
		OperationID:             normalized.OperationID,
		OwnershipManifestSHA256: normalized.OwnershipManifest.SHA256,
		DeleteEntries:           append([]EnvironmentResetOwnershipEntry(nil), normalized.OwnershipManifest.Entries...),
	}, nil
}

// ResetEnvironment removes only manifest-declared ReDevPlugin-owned data and
// initializes fresh Host control and plugin-data stores when selected. It must
// run after the owning Host and plugin runtime have stopped.
func ResetEnvironment(ctx context.Context, request EnvironmentResetRequest) (EnvironmentResetResult, error) {
	normalized, err := normalizeEnvironmentResetRequest(ctx, request)
	if err != nil {
		return EnvironmentResetResult{}, err
	}
	lock, err := acquireEnvironmentRootLock(normalized.StateRoot, false)
	if err != nil {
		return EnvironmentResetResult{}, err
	}
	defer lock.Close()
	if err := validateEnvironmentResetEntries(normalized.StateRoot, normalized.OwnershipManifest.Entries); err != nil {
		return EnvironmentResetResult{}, err
	}
	for _, entry := range normalized.OwnershipManifest.Entries {
		if err := removeEnvironmentResetEntry(normalized.StateRoot, entry); err != nil {
			return EnvironmentResetResult{}, err
		}
	}
	if err := initializeResetEnvironmentCore(ctx, normalized.StateRoot, normalized.OwnershipManifest.Entries); err != nil {
		return EnvironmentResetResult{}, err
	}
	return EnvironmentResetResult{
		EnvironmentID:           normalized.OwnershipManifest.EnvironmentID,
		OperationID:             normalized.OperationID,
		OwnershipManifestSHA256: normalized.OwnershipManifest.SHA256,
		ResetEntries:            append([]EnvironmentResetOwnershipEntry(nil), normalized.OwnershipManifest.Entries...),
	}, nil
}

func normalizeEnvironmentResetRequest(ctx context.Context, request EnvironmentResetRequest) (EnvironmentResetRequest, error) {
	if ctx == nil {
		return EnvironmentResetRequest{}, fmt.Errorf("%w: context is required", ErrEnvironmentResetRequest)
	}
	if err := ctx.Err(); err != nil {
		return EnvironmentResetRequest{}, err
	}
	request.OperationID = strings.TrimSpace(request.OperationID)
	if request.OperationID == "" || len(request.OperationID) > 256 {
		return EnvironmentResetRequest{}, fmt.Errorf("%w: operation_id is required", ErrEnvironmentResetRequest)
	}
	root, err := validatedEnvironmentResetRoot(request.StateRoot, false)
	if err != nil {
		return EnvironmentResetRequest{}, err
	}
	request.StateRoot = root
	canonical, err := NewEnvironmentResetOwnershipManifest(request.OwnershipManifest.EnvironmentID, manifestKinds(request.OwnershipManifest.Entries)...)
	if err != nil {
		return EnvironmentResetRequest{}, err
	}
	if request.OwnershipManifest.SchemaVersion != canonical.SchemaVersion ||
		request.OwnershipManifest.SHA256 != canonical.SHA256 ||
		!equalEnvironmentResetEntries(request.OwnershipManifest.Entries, canonical.Entries) {
		return EnvironmentResetRequest{}, fmt.Errorf("%w: ownership manifest does not match canonical platform paths", ErrEnvironmentResetRequest)
	}
	request.OwnershipManifest = canonical
	return request, nil
}

func manifestKinds(entries []EnvironmentResetOwnershipEntry) []EnvironmentResetDataKind {
	kinds := make([]EnvironmentResetDataKind, len(entries))
	for index := range entries {
		kinds[index] = entries[index].Kind
	}
	return kinds
}

func equalEnvironmentResetEntries(left, right []EnvironmentResetOwnershipEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func environmentResetManifestDigest(manifest EnvironmentResetOwnershipManifest) (string, error) {
	payload := struct {
		SchemaVersion string                           `json:"schema_version"`
		EnvironmentID string                           `json:"environment_id"`
		Entries       []EnvironmentResetOwnershipEntry `json:"entries"`
	}{manifest.SchemaVersion, manifest.EnvironmentID, manifest.Entries}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateEnvironmentResetEntries(root string, entries []EnvironmentResetOwnershipEntry) error {
	for _, entry := range entries {
		expected, ok := environmentResetPaths[entry.Kind]
		if !ok || entry.RelativePath != expected {
			return fmt.Errorf("%w: unrecognized owned path", ErrEnvironmentResetBlocked)
		}
		target := filepath.Join(root, expected)
		info, err := os.Lstat(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: owned path %q is a symlink", ErrEnvironmentResetBlocked, expected)
		}
	}
	return nil
}

func removeEnvironmentResetEntry(root string, entry EnvironmentResetOwnershipEntry) error {
	target := filepath.Join(root, entry.RelativePath)
	if err := os.RemoveAll(target); err != nil {
		return err
	}
	if entry.Kind == EnvironmentResetHostControl || entry.Kind == EnvironmentResetObservability || entry.Kind == EnvironmentResetSecrets {
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			if err := os.Remove(target + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func initializeResetEnvironmentCore(ctx context.Context, root string, entries []EnvironmentResetOwnershipEntry) error {
	selected := make(map[EnvironmentResetDataKind]bool, len(entries))
	for _, entry := range entries {
		selected[entry.Kind] = true
	}
	if !selected[EnvironmentResetHostControl] && !selected[EnvironmentResetPluginData] {
		return nil
	}
	control, err := controlstore.Open(ctx, controlstore.Config{Path: filepath.Join(root, "control.sqlite")})
	if err != nil {
		return fmt.Errorf("initialize reset control store: %w", err)
	}
	if selected[EnvironmentResetPluginData] {
		data, dataErr := plugindata.Open(ctx, filepath.Join(root, "plugin-data"), control)
		if dataErr != nil {
			_ = control.Close()
			return fmt.Errorf("initialize reset plugin data: %w", dataErr)
		}
		if closeErr := data.Close(); closeErr != nil {
			_ = control.Close()
			return closeErr
		}
	}
	return control.Close()
}
