package version

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	PluginHostProtocolVersion     = "plugin-host-v1"
	RustIPCVersion                = "rust-ipc-v1"
	WASMABIVersion                = "redevplugin-wasm-worker-v1"
	ManifestSchemaVersion         = "manifest-v1"
	PackageSignatureSchemaVersion = "package-signature-v1"
	TokenTicketSchemaVersion      = "token-ticket-v1"
	BridgeSchemaVersion           = "bridge-v1"
	TargetClassifierVersion       = "target-classifier-v1"
	NetworkGrantSchemaVersion     = "network-grant-v1"
	PluginPlatformOpenAPIVersion  = "plugin-platform-v1"
	CompatibilityManifestVersion  = "redevplugin.compatibility.v1"
	CompatibilitySchemaVersion    = "compatibility-manifest-v1"
	ReleaseManifestSchemaVersion  = "release-manifest-v1"
	WorkerInvocationSchemaVersion = "worker-invocation-v1"
	ErrorCodesSchemaVersion       = "error-codes-v1"
)

type Matrix struct {
	GoModuleVersion               string `json:"redevplugin_go_version"`
	UIPackageVersion              string `json:"redevplugin_ui_version"`
	RuntimeVersion                string `json:"redevplugin_runtime_version"`
	PluginHostProtocolVersion     string `json:"plugin_host_protocol_version"`
	RustIPCVersion                string `json:"rust_ipc_version"`
	WASMABIVersion                string `json:"wasm_abi_version"`
	ManifestSchemaVersion         string `json:"manifest_schema_version"`
	PackageSignatureSchemaVersion string `json:"package_signature_schema_version"`
	TokenTicketSchemaVersion      string `json:"token_ticket_schema_version"`
	BridgeSchemaVersion           string `json:"bridge_schema_version"`
	TargetClassifierVersion       string `json:"target_classifier_version"`
	NetworkGrantSchemaVersion     string `json:"network_grant_schema_version"`
	PluginPlatformOpenAPIVersion  string `json:"plugin_platform_openapi_version"`
	CompatibilitySchemaVersion    string `json:"compatibility_schema_version"`
	WorkerInvocationSchemaVersion string `json:"worker_invocation_schema_version"`
	ErrorCodesSchemaVersion       string `json:"error_codes_schema_version"`
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
		GoModuleVersion:               resolvedReleaseVersion(GoModuleVersion),
		UIPackageVersion:              resolvedReleaseVersion(UIPackageVersion),
		RuntimeVersion:                resolvedReleaseVersion(RuntimeVersion),
		PluginHostProtocolVersion:     PluginHostProtocolVersion,
		RustIPCVersion:                RustIPCVersion,
		WASMABIVersion:                WASMABIVersion,
		ManifestSchemaVersion:         ManifestSchemaVersion,
		PackageSignatureSchemaVersion: PackageSignatureSchemaVersion,
		TokenTicketSchemaVersion:      TokenTicketSchemaVersion,
		BridgeSchemaVersion:           BridgeSchemaVersion,
		TargetClassifierVersion:       TargetClassifierVersion,
		NetworkGrantSchemaVersion:     NetworkGrantSchemaVersion,
		PluginPlatformOpenAPIVersion:  PluginPlatformOpenAPIVersion,
		CompatibilitySchemaVersion:    CompatibilitySchemaVersion,
		WorkerInvocationSchemaVersion: WorkerInvocationSchemaVersion,
		ErrorCodesSchemaVersion:       ErrorCodesSchemaVersion,
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
				SHA256:  "040d92575a4acf1f9dfa91fc946b2e5180a954cf8da7167bb87ba74c74d3b202",
			},
			{
				ID:      "manifest-schema",
				Path:    "spec/plugin/manifest-v1.schema.json",
				Version: ManifestSchemaVersion,
				SHA256:  "65a36285af0ac3f4442388a37b8e45fca56b6b3037eb918757ceec59bc946aca",
			},
			{
				ID:      "package-signature-schema",
				Path:    "spec/plugin/package-signature-v1.schema.json",
				Version: PackageSignatureSchemaVersion,
				SHA256:  "13951c0f6831ba28647774368c76a817868aeb7984628e2cf3dc4ad1b54f8284",
			},
			{
				ID:      "token-ticket-schema",
				Path:    "spec/plugin/token-ticket-v1.schema.json",
				Version: TokenTicketSchemaVersion,
				SHA256:  "d83a698319262daa4d4bdaf9930b4b930717147376192f7160688910aaa9a2b0",
			},
			{
				ID:      "iframe-bridge-schema",
				Path:    "spec/plugin/bridge-v1.schema.json",
				Version: BridgeSchemaVersion,
				SHA256:  "b524192ce4cdcb956159d8226452bcfdb90c0ce4218328d6440dcf255ac67c0d",
			},
			{
				ID:      "compatibility-manifest-schema",
				Path:    "spec/plugin/compatibility-manifest-v1.schema.json",
				Version: CompatibilitySchemaVersion,
				SHA256:  "db9907e927238cc0710054e7fafb6c9f816d90723c266472510a70e5b3e94e76",
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
				SHA256:  "913e7fbdc87ed59f0f1b7f9b16b87e88c9441cc1c26a5547a22d03f0f1c4fc03",
			},
			{
				ID:      "error-codes-schema",
				Path:    "spec/plugin/error-codes-v1.schema.json",
				Version: ErrorCodesSchemaVersion,
				SHA256:  "c32997d25f3330519665e693c3dd98e1aac01e192b55a9015e460165a086427f",
			},
			{
				ID:      "rust-ipc-schema",
				Path:    "spec/plugin/ipc-v1.schema.json",
				Version: RustIPCVersion,
				SHA256:  "53812b5e3235ad52cac6cdb7ec7cfaa09bd3c33d951dcae7d278495b9e142f6b",
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
				SHA256:  "cf5b02acaf59ccd578df7c8281c392b2721ee594d908d85f1aac39ccf9ebd079",
			},
		},
	}
}

func DecodeCompatibilityManifest(raw []byte) (CompatibilityManifest, error) {
	var manifest CompatibilityManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
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
