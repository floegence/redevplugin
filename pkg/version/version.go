package version

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

const (
	modulePath = "github.com/floegence/redevplugin"
	devVersion = "0.0.0-dev"
)

var (
	GoModuleVersion  = devVersion
	UIPackageVersion = devVersion
	RuntimeVersion   = devVersion

	buildInfoModuleVersion = detectBuildInfoModuleVersion
)

const (
	PluginHostProtocolVersion      = "plugin-host-v1"
	RustIPCVersion                 = "rust-ipc-v1"
	WASMABIVersion                 = "redevplugin-wasm-worker-v1"
	ManifestSchemaVersion          = "manifest-v1"
	PackageSignatureSchemaVersion  = "package-signature-v1"
	ReleaseMetadataSchemaVersion   = "release-metadata-v1"
	SourcePolicySchemaVersion      = "source-policy-v1"
	SourceRevocationsSchemaVersion = "source-revocations-v1"
	TokenTicketSchemaVersion       = "token-ticket-v1"
	BridgeSchemaVersion            = "bridge-v1"
	TargetClassifierVersion        = "target-classifier-v1"
	NetworkGrantSchemaVersion      = "network-grant-v1"
	PluginPlatformOpenAPIVersion   = "plugin-platform-v1"
	CompatibilityManifestVersion   = "redevplugin.compatibility.v1"
	CompatibilitySchemaVersion     = "compatibility-manifest-v1"
	ReleaseManifestSchemaVersion   = "release-manifest-v1"
	WorkerInvocationSchemaVersion  = "worker-invocation-v1"
	ErrorCodesSchemaVersion        = "error-codes-v1"
)

type Matrix struct {
	GoModuleVersion                string `json:"redevplugin_go_version"`
	UIPackageVersion               string `json:"redevplugin_ui_version"`
	RuntimeVersion                 string `json:"redevplugin_runtime_version"`
	PluginHostProtocolVersion      string `json:"plugin_host_protocol_version"`
	RustIPCVersion                 string `json:"rust_ipc_version"`
	WASMABIVersion                 string `json:"wasm_abi_version"`
	ManifestSchemaVersion          string `json:"manifest_schema_version"`
	PackageSignatureSchemaVersion  string `json:"package_signature_schema_version"`
	ReleaseMetadataSchemaVersion   string `json:"release_metadata_schema_version"`
	SourcePolicySchemaVersion      string `json:"source_policy_schema_version"`
	SourceRevocationsSchemaVersion string `json:"source_revocations_schema_version"`
	TokenTicketSchemaVersion       string `json:"token_ticket_schema_version"`
	BridgeSchemaVersion            string `json:"bridge_schema_version"`
	TargetClassifierVersion        string `json:"target_classifier_version"`
	NetworkGrantSchemaVersion      string `json:"network_grant_schema_version"`
	PluginPlatformOpenAPIVersion   string `json:"plugin_platform_openapi_version"`
	CompatibilitySchemaVersion     string `json:"compatibility_schema_version"`
	WorkerInvocationSchemaVersion  string `json:"worker_invocation_schema_version"`
	ErrorCodesSchemaVersion        string `json:"error_codes_schema_version"`
}

type ContractArtifact struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type CompatibilityManifest struct {
	SchemaVersion string             `json:"schema_version"`
	Matrix        Matrix             `json:"matrix"`
	Contracts     []ContractArtifact `json:"contracts"`
}

var (
	ErrCompatibilitySchemaVersion = errors.New("compatibility manifest schema version mismatch")
	ErrCompatibilityMatrix        = errors.New("compatibility manifest version matrix mismatch")
	ErrCompatibilityContract      = errors.New("compatibility manifest contract mismatch")
	ErrCompatibilityPath          = errors.New("compatibility manifest contract path is invalid")
)

func CurrentMatrix() Matrix {
	return Matrix{
		GoModuleVersion:                resolvedReleaseVersion(GoModuleVersion),
		UIPackageVersion:               resolvedReleaseVersion(UIPackageVersion),
		RuntimeVersion:                 resolvedReleaseVersion(RuntimeVersion),
		PluginHostProtocolVersion:      PluginHostProtocolVersion,
		RustIPCVersion:                 RustIPCVersion,
		WASMABIVersion:                 WASMABIVersion,
		ManifestSchemaVersion:          ManifestSchemaVersion,
		PackageSignatureSchemaVersion:  PackageSignatureSchemaVersion,
		ReleaseMetadataSchemaVersion:   ReleaseMetadataSchemaVersion,
		SourcePolicySchemaVersion:      SourcePolicySchemaVersion,
		SourceRevocationsSchemaVersion: SourceRevocationsSchemaVersion,
		TokenTicketSchemaVersion:       TokenTicketSchemaVersion,
		BridgeSchemaVersion:            BridgeSchemaVersion,
		TargetClassifierVersion:        TargetClassifierVersion,
		NetworkGrantSchemaVersion:      NetworkGrantSchemaVersion,
		PluginPlatformOpenAPIVersion:   PluginPlatformOpenAPIVersion,
		CompatibilitySchemaVersion:     CompatibilitySchemaVersion,
		WorkerInvocationSchemaVersion:  WorkerInvocationSchemaVersion,
		ErrorCodesSchemaVersion:        ErrorCodesSchemaVersion,
	}
}

func resolvedReleaseVersion(configured string) string {
	if configured != "" && configured != devVersion {
		return configured
	}
	if detected := buildInfoModuleVersion(); detected != "" {
		return detected
	}
	if configured == "" {
		return devVersion
	}
	return configured
}

func detectBuildInfoModuleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	if info.Main.Path == modulePath {
		if version := normalizeModuleVersion(info.Main.Version); version != "" {
			return version
		}
	}
	for _, dep := range info.Deps {
		if dep.Path != modulePath {
			continue
		}
		if version := normalizeModuleVersion(dep.Version); version != "" {
			return version
		}
	}
	return ""
}

func normalizeModuleVersion(version string) string {
	if version == "" || version == "(devel)" {
		return ""
	}
	return strings.TrimPrefix(version, "v")
}

func CurrentCompatibilityManifest() CompatibilityManifest {
	return CompatibilityManifest{
		SchemaVersion: CompatibilityManifestVersion,
		Matrix:        CurrentMatrix(),
		Contracts: []ContractArtifact{
			{
				ID:      "plugin-platform-openapi",
				Path:    "spec/openapi/plugin-platform-v1.yaml",
				Version: PluginPlatformOpenAPIVersion,
				SHA256:  "a0e251c07b0ce50e4129c6468f949065e24d88081cafdee1cd4382627930bcad",
			},
			{
				ID:      "manifest-schema",
				Path:    "spec/plugin/manifest-v1.schema.json",
				Version: ManifestSchemaVersion,
				SHA256:  "8751e06d5d2fe6f2c5de1ebb06109cc9c267125f5cc8973045b630a7aa0b2cbf",
			},
			{
				ID:      "package-signature-schema",
				Path:    "spec/plugin/package-signature-v1.schema.json",
				Version: PackageSignatureSchemaVersion,
				SHA256:  "13951c0f6831ba28647774368c76a817868aeb7984628e2cf3dc4ad1b54f8284",
			},
			{
				ID:      "release-metadata-schema",
				Path:    "spec/plugin/release-metadata-v1.schema.json",
				Version: ReleaseMetadataSchemaVersion,
				SHA256:  "c0e5bb660cec514bddf4039adbab7b870340fe671a208117a766691bf71f0048",
			},
			{
				ID:      "source-policy-schema",
				Path:    "spec/plugin/source-policy-v1.schema.json",
				Version: SourcePolicySchemaVersion,
				SHA256:  "b5f3094402bdbfdda1671b46e5f64a69ad7dc2ba9501030439fafa87acd2923e",
			},
			{
				ID:      "source-revocations-schema",
				Path:    "spec/plugin/source-revocations-v1.schema.json",
				Version: SourceRevocationsSchemaVersion,
				SHA256:  "4c4132879a51b31e99775c979ca3ab43c2ee4c5c885f3ff1e7b43cd5ce8bc83d",
			},
			{
				ID:      "token-ticket-schema",
				Path:    "spec/plugin/token-ticket-v1.schema.json",
				Version: TokenTicketSchemaVersion,
				SHA256:  "b2abad67cc4637a4978b48a446372fdc0da339fe8b19268c8db7f697e7aa1106",
			},
			{
				ID:      "iframe-bridge-schema",
				Path:    "spec/plugin/bridge-v1.schema.json",
				Version: BridgeSchemaVersion,
				SHA256:  "23cfda963ca04cbc149dc41a4311a34fb6a9775bf1fa08a9cbd3d9559689044e",
			},
			{
				ID:      "compatibility-manifest-schema",
				Path:    "spec/plugin/compatibility-manifest-v1.schema.json",
				Version: CompatibilitySchemaVersion,
				SHA256:  "49fa1bbafb1ac46804ce35ffa9b3cf896644e17a596b03cfba503b80691c5d96",
			},
			{
				ID:      "release-manifest-schema",
				Path:    "spec/plugin/release-manifest-v1.schema.json",
				Version: ReleaseManifestSchemaVersion,
				SHA256:  "19b02f226322c21db8e891c5d4a0a18b7e5375cb0b22f3469a96c0baa0cf94fd",
			},
			{
				ID:      "worker-invocation-schema",
				Path:    "spec/plugin/worker-invocation-v1.schema.json",
				Version: WorkerInvocationSchemaVersion,
				SHA256:  "cbbef78febae6d13d914bf382d22f2d9785d0bac158eb92d18a2815d5c70dbe6",
			},
			{
				ID:      "error-codes-schema",
				Path:    "spec/plugin/error-codes-v1.schema.json",
				Version: ErrorCodesSchemaVersion,
				SHA256:  "8dddba605e5bb0c01f05a5265815314843ef154a3d1e4c5350d301effefbd572",
			},
			{
				ID:      "rust-ipc-schema",
				Path:    "spec/plugin/ipc-v1.schema.json",
				Version: RustIPCVersion,
				SHA256:  "4e3a9556392b06b805f36fe80c5690408d702a72d71ac6f6e3edcb31f2fd0e91",
			},
			{
				ID:      "wasm-worker-schema",
				Path:    "spec/plugin/wasm-worker-v1.schema.json",
				Version: WASMABIVersion,
				SHA256:  "ff0a37ea972db7d8be89b529e03d890af00aab3f2d9461c2db3a3d58c664b775",
			},
			{
				ID:      "network-grant-schema",
				Path:    "spec/plugin/network-grant-v1.schema.json",
				Version: NetworkGrantSchemaVersion,
				SHA256:  "e3ba8e7aa42267596b5570c1de60994a0912b125ea78427776db8092c2b3ea7b",
			},
			{
				ID:      "target-classifier-fixture",
				Path:    "spec/plugin/target-classifier-v1.json",
				Version: TargetClassifierVersion,
				SHA256:  "7e9367d624c22d575ae5c118063c1cb0f0de6b5b0081eabcfc51c0357e4d14d7",
			},
		},
	}
}

func DecodeCompatibilityManifest(raw []byte) (CompatibilityManifest, error) {
	var manifest CompatibilityManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return CompatibilityManifest{}, err
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		return CompatibilityManifest{}, errors.New("compatibility manifest must contain exactly one JSON document")
	} else if !errors.Is(err, io.EOF) {
		return CompatibilityManifest{}, err
	}
	return manifest, nil
}

func VerifyCompatibilityManifestFile(filename string, artifactRoot string) error {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	manifest, err := DecodeCompatibilityManifest(raw)
	if err != nil {
		return err
	}
	return VerifyCompatibilityManifest(manifest, artifactRoot)
}

func VerifyCompatibilityManifest(manifest CompatibilityManifest, artifactRoot string) error {
	expected := CurrentCompatibilityManifest()
	if manifest.SchemaVersion != expected.SchemaVersion {
		return fmt.Errorf("%w: got %q want %q", ErrCompatibilitySchemaVersion, manifest.SchemaVersion, expected.SchemaVersion)
	}
	if !matrixEqual(manifest.Matrix, expected.Matrix) {
		return fmt.Errorf("%w: got %#v want %#v", ErrCompatibilityMatrix, manifest.Matrix, expected.Matrix)
	}

	expectedContracts := map[string]ContractArtifact{}
	for _, contract := range expected.Contracts {
		expectedContracts[contract.ID] = contract
	}
	seen := map[string]bool{}
	for _, contract := range manifest.Contracts {
		if seen[contract.ID] {
			return fmt.Errorf("%w: duplicate contract id %q", ErrCompatibilityContract, contract.ID)
		}
		seen[contract.ID] = true
		expectedContract, ok := expectedContracts[contract.ID]
		if !ok {
			return fmt.Errorf("%w: unexpected contract id %q", ErrCompatibilityContract, contract.ID)
		}
		if contract.Path != expectedContract.Path || contract.Version != expectedContract.Version || contract.SHA256 != expectedContract.SHA256 {
			return fmt.Errorf("%w: contract %q metadata mismatch", ErrCompatibilityContract, contract.ID)
		}
		if err := verifyContractArtifactHash(artifactRoot, contract); err != nil {
			return err
		}
	}
	for id := range expectedContracts {
		if !seen[id] {
			return fmt.Errorf("%w: missing contract id %q", ErrCompatibilityContract, id)
		}
	}
	return nil
}

func verifyContractArtifactHash(root string, contract ContractArtifact) error {
	if err := validateContractPath(contract.Path); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(contract.Path)))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != contract.SHA256 {
		return fmt.Errorf("%w: %s sha256 got %s want %s", ErrCompatibilityContract, contract.Path, got, contract.SHA256)
	}
	return nil
}

func validateContractPath(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") {
		return fmt.Errorf("%w: %q", ErrCompatibilityPath, path)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean != path || strings.HasPrefix(clean, "../") || clean == ".." {
		return fmt.Errorf("%w: %q", ErrCompatibilityPath, path)
	}
	if !strings.HasPrefix(path, "spec/openapi/") && !strings.HasPrefix(path, "spec/plugin/") {
		return fmt.Errorf("%w: %q", ErrCompatibilityPath, path)
	}
	return nil
}

func matrixEqual(a Matrix, b Matrix) bool {
	return a == b
}
