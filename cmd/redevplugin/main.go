package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/installstage"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/secrets"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/trust"
	"github.com/floegence/redevplugin/pkg/version"
)

type validateSummary struct {
	OK            bool           `json:"ok"`
	Kind          string         `json:"kind"`
	PluginID      string         `json:"plugin_id"`
	Version       string         `json:"version"`
	PackageHash   string         `json:"package_hash,omitempty"`
	ManifestHash  string         `json:"manifest_hash,omitempty"`
	EntriesHash   string         `json:"entries_hash,omitempty"`
	Signed        bool           `json:"signed,omitempty"`
	SignatureKey  string         `json:"signature_key,omitempty"`
	SignatureAlgo string         `json:"signature_algorithm,omitempty"`
	VersionMatrix version.Matrix `json:"version_matrix"`
}

type lifecycleSummary struct {
	OK                 bool                 `json:"ok"`
	Action             string               `json:"action"`
	PluginInstanceID   string               `json:"plugin_instance_id"`
	PluginID           string               `json:"plugin_id"`
	Version            string               `json:"version"`
	TrustState         registry.TrustState  `json:"trust_state"`
	EnableState        registry.EnableState `json:"enable_state"`
	PolicyRevision     uint64               `json:"policy_revision"`
	ManagementRevision uint64               `json:"management_revision"`
	RevokeEpoch        uint64               `json:"revoke_epoch"`
}

type keygenSummary struct {
	OK         bool   `json:"ok"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	PrivateKey string `json:"private_key_file"`
	PublicKey  string `json:"public_key_file"`
	CreatedAt  string `json:"created_at"`
}

type scaffoldSummary struct {
	OK          bool           `json:"ok"`
	Kind        string         `json:"kind"`
	PluginID    string         `json:"plugin_id"`
	Version     string         `json:"version"`
	OutputDir   string         `json:"output_dir"`
	Files       []string       `json:"files"`
	VersionInfo version.Matrix `json:"version_matrix"`
}

//go:embed scaffold_assets/plugin-worker.js
var scaffoldPluginWorkerJS []byte

//go:embed scaffold_assets/plugin-worker.ts
var scaffoldPluginWorkerTS []byte

//go:embed scaffold_assets/backend.wasm
var scaffoldWorkerWASM []byte

//go:embed scaffold_assets/worker-lib.rs
var scaffoldWorkerRust []byte

type compatibilityVerifySummary struct {
	OK            bool   `json:"ok"`
	SchemaVersion string `json:"schema_version"`
	Contracts     int    `json:"contracts"`
}

type dataInspectSummary struct {
	OK               bool                      `json:"ok"`
	StateRoot        string                    `json:"state_root"`
	PluginDataRoot   string                    `json:"plugin_data_root"`
	PluginInstanceID string                    `json:"plugin_instance_id,omitempty"`
	BindingCount     int                       `json:"binding_count"`
	ObjectCount      int                       `json:"object_count"`
	NamespaceCount   int                       `json:"namespace_count"`
	TotalUsageBytes  int64                     `json:"total_usage_bytes"`
	TotalUsageFiles  int64                     `json:"total_usage_files"`
	Bindings         []plugindata.Binding      `json:"bindings"`
	Objects          []plugindata.Object       `json:"objects"`
	Namespaces       []storage.NamespaceRecord `json:"namespaces"`
	VersionMatrix    version.Matrix            `json:"version_matrix"`
}

type signingPrivateKeyFile struct {
	SchemaVersion string `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PublisherID   string `json:"publisher_id,omitempty"`
	PluginID      string `json:"plugin_id,omitempty"`
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
}

type signingPublicKeyFile struct {
	SchemaVersion string `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PublisherID   string `json:"publisher_id,omitempty"`
	PluginID      string `json:"plugin_id,omitempty"`
	PublicKey     string `json:"public_key"`
	CreatedAt     string `json:"created_at,omitempty"`
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "redevplugin: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	ctx = cliContext(ctx)
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "validate":
		if len(args) != 2 {
			return usage()
		}
		return validate(ctx, args[1])
	case "package":
		if len(args) != 3 {
			return usage()
		}
		return buildPackage(ctx, args[1], args[2])
	case "scaffold":
		if len(args) != 4 {
			return usage()
		}
		return scaffoldPlugin(args[1], args[2], args[3])
	case "keygen":
		if len(args) != 4 {
			return usage()
		}
		return keygen(args[1], args[2], args[3])
	case "sign":
		if len(args) != 4 {
			return usage()
		}
		return signPackage(ctx, args[1], args[2], args[3])
	case "version":
		return writeJSON(version.CurrentCompatibilityManifest())
	case "verify-compatibility":
		if len(args) != 3 {
			return usage()
		}
		return verifyCompatibility(args[1], args[2])
	case "host-capability":
		return runHostCapability(ctx, args[1:])
	case "inspect-data":
		if len(args) != 2 && len(args) != 3 {
			return usage()
		}
		pluginInstanceID := ""
		if len(args) == 3 {
			pluginInstanceID = args[2]
		}
		return inspectData(ctx, args[1], pluginInstanceID)
	case "install-local":
		if len(args) != 2 {
			return usage()
		}
		return lifecycleHarness(ctx, "install-local", args[1])
	case "install-verified":
		if len(args) != 3 {
			return usage()
		}
		return installVerifiedHarness(ctx, args[1], args[2])
	case "dev-install":
		if len(args) < 3 {
			return usage()
		}
		capabilities, err := parseDevCapabilityArgs(args[3:])
		if err != nil {
			return err
		}
		return devInstall(ctx, args[1], args[2], capabilities)
	case "dev-enable":
		if len(args) != 2 {
			return usage()
		}
		return devEnable(ctx, args[1])
	case "dev-open":
		if len(args) != 3 {
			return usage()
		}
		return devOpen(ctx, args[1], args[2])
	case "dev-secret-bind":
		if len(args) != 3 && len(args) != 4 {
			return usage()
		}
		return devSecretBind(ctx, args[1], args[2], optionalSecretScope(args))
	case "dev-secret-test":
		if len(args) != 3 && len(args) != 4 {
			return usage()
		}
		return devSecretTest(ctx, args[1], args[2], optionalSecretScope(args))
	case "dev-secret-delete":
		if len(args) != 3 && len(args) != 4 {
			return usage()
		}
		return devSecretDelete(ctx, args[1], args[2], optionalSecretScope(args))
	case "dev-permission-grant":
		if len(args) != 3 {
			return usage()
		}
		return devPermissionGrant(ctx, args[1], args[2])
	case "dev-permission-revoke":
		if len(args) != 3 && len(args) != 4 {
			return usage()
		}
		reason := "dev-cli"
		if len(args) == 4 {
			reason = args[3]
		}
		return devPermissionRevoke(ctx, args[1], args[2], reason)
	case "dev-permission-list":
		if len(args) != 2 && len(args) != 3 {
			return usage()
		}
		activeOnly := false
		if len(args) == 3 {
			if args[2] != "--active-only" {
				return usage()
			}
			activeOnly = true
		}
		return devPermissionList(ctx, args[1], activeOnly)
	case "dev-export-data":
		if len(args) != 2 {
			return usage()
		}
		return devExportData(ctx, args[1])
	case "dev-import-data":
		if len(args) != 3 {
			return usage()
		}
		return devImportData(ctx, args[1], args[2])
	case "dev-delete-export":
		if len(args) != 3 {
			return usage()
		}
		return devDeleteExport(ctx, args[1], args[2])
	case "dev-disable":
		if len(args) != 2 {
			return usage()
		}
		return devDisable(ctx, args[1])
	case "dev-uninstall":
		if len(args) != 2 {
			return usage()
		}
		return devUninstall(ctx, args[1])
	case "dev-status":
		if len(args) != 2 {
			return usage()
		}
		return devStatus(args[1])
	case "examples-server":
		if len(args) != 3 {
			return usage()
		}
		return examplesServer(ctx, args[1], args[2])
	case "enable":
		if len(args) != 2 {
			return usage()
		}
		return lifecycleHarness(ctx, "enable", args[1])
	case "disable":
		if len(args) != 2 {
			return usage()
		}
		return lifecycleHarness(ctx, "disable", args[1])
	case "uninstall":
		if len(args) != 2 {
			return usage()
		}
		return lifecycleHarness(ctx, "uninstall", args[1])
	default:
		return usage()
	}
}

func verifyCompatibility(manifestFile string, artifactRoot string) error {
	raw, err := os.ReadFile(manifestFile)
	if err != nil {
		return err
	}
	manifest, err := version.DecodeCompatibilityManifest(raw)
	if err != nil {
		return err
	}
	if err := version.VerifyCompatibilityManifest(manifest, artifactRoot); err != nil {
		return err
	}
	return writeJSON(compatibilityVerifySummary{
		OK:            true,
		SchemaVersion: manifest.SchemaVersion,
		Contracts:     len(manifest.Contracts),
	})
}

func inspectData(ctx context.Context, root string, pluginInstanceID string) error {
	root, err := normalizeDevStateRoot(root)
	if err != nil {
		return err
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	registryStore, err := registry.NewSQLiteStore(ctx, filepath.Join(root, devRegistryFile))
	if err != nil {
		return err
	}
	pluginDataRoot := filepath.Join(root, devPluginDataDir)
	pluginData, err := plugindata.Open(ctx, pluginDataRoot, registryStore)
	if err != nil {
		_ = registryStore.Close()
		return err
	}
	defer func() {
		_ = pluginData.Close()
		_ = registryStore.Close()
	}()
	bindings := []plugindata.Binding{}
	for cursor := ""; ; {
		page, next, err := registryStore.ListBindings(ctx, cursor, 256)
		if err != nil {
			return err
		}
		bindings = append(bindings, page...)
		if next == "" {
			break
		}
		cursor = next
	}
	if pluginInstanceID != "" {
		filtered := bindings[:0]
		for _, binding := range bindings {
			if binding.PluginInstanceID == pluginInstanceID {
				filtered = append(filtered, binding)
			}
		}
		bindings = filtered
	}
	objects := []plugindata.Object{}
	if pluginInstanceID == "" {
		for cursor := ""; ; {
			page, next, err := registryStore.ListAllObjectsForMaintenance(ctx, cursor, 256)
			if err != nil {
				return err
			}
			for _, item := range page {
				objects = append(objects, item.Object)
			}
			if next == "" {
				break
			}
			cursor = next
		}
	} else {
		for cursor := ""; ; {
			page, next, err := registryStore.ListObjects(ctx, sessionctx.ScopeUser, pluginInstanceID, cursor, 256)
			if err != nil {
				return err
			}
			objects = append(objects, page...)
			if next == "" {
				break
			}
			cursor = next
		}
	}
	records := []storage.NamespaceRecord{}
	if pluginInstanceID != "" {
		records, err = pluginData.ListNamespaces(ctx, pluginInstanceID)
		if err != nil {
			return err
		}
	} else {
		for _, binding := range bindings {
			pluginRecords, err := pluginData.ListNamespaces(ctx, binding.PluginInstanceID)
			if err != nil {
				return err
			}
			records = append(records, pluginRecords...)
		}
	}
	totalUsage := int64(0)
	totalUsageFiles := int64(0)
	for i := range records {
		usage, err := pluginData.Usage(ctx, records[i].PluginInstanceID, records[i].StoreID)
		if err != nil {
			return err
		}
		records[i].UsageBytes = usage.UsageBytes
		records[i].QuotaBytes = usage.QuotaBytes
		records[i].UsageFiles = usage.UsageFiles
		records[i].QuotaFiles = usage.QuotaFiles
		totalUsage += usage.UsageBytes
		totalUsageFiles += usage.UsageFiles
	}
	return writeJSON(dataInspectSummary{
		OK:               true,
		StateRoot:        root,
		PluginDataRoot:   pluginDataRoot,
		PluginInstanceID: pluginInstanceID,
		BindingCount:     len(bindings),
		ObjectCount:      len(objects),
		NamespaceCount:   len(records),
		TotalUsageBytes:  totalUsage,
		TotalUsageFiles:  totalUsageFiles,
		Bindings:         bindings,
		Objects:          objects,
		Namespaces:       records,
		VersionMatrix:    version.CurrentMatrix(),
	})
}

func validate(ctx context.Context, filename string) error {
	if strings.HasSuffix(filename, ".redevplugin") || strings.HasSuffix(filename, ".zip") {
		pkg, err := pluginpkg.ReadFile(ctx, filename, pluginpkg.DefaultReadLimits())
		if err != nil {
			return err
		}
		signed, signatureKey, signatureAlgo := packageSignatureSummary(pkg)
		return writeJSON(validateSummary{
			OK:            true,
			Kind:          "package",
			PluginID:      pkg.Manifest.PluginID(),
			Version:       pkg.Manifest.Version(),
			PackageHash:   pkg.PackageHash,
			ManifestHash:  pkg.ManifestHash,
			EntriesHash:   pkg.EntriesHash,
			Signed:        signed,
			SignatureKey:  signatureKey,
			SignatureAlgo: signatureAlgo,
			VersionMatrix: version.CurrentMatrix(),
		})
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	decoded, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return writeJSON(validateSummary{
		OK:            true,
		Kind:          "manifest",
		PluginID:      decoded.PluginID(),
		Version:       decoded.Version(),
		VersionMatrix: version.CurrentMatrix(),
	})
}

func buildPackage(ctx context.Context, srcDir string, outFile string) error {
	if outDir := filepath.Dir(outFile); outDir != "." {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
	}
	var buf bytes.Buffer
	pkg, err := pluginpkg.BuildFromDir(ctx, srcDir, &buf, pluginpkg.DefaultReadLimits())
	if err != nil {
		return err
	}
	if err := os.WriteFile(outFile, buf.Bytes(), 0o644); err != nil {
		return err
	}
	signed, signatureKey, signatureAlgo := packageSignatureSummary(pkg)
	return writeJSON(validateSummary{
		OK:            true,
		Kind:          "package",
		PluginID:      pkg.Manifest.PluginID(),
		Version:       pkg.Manifest.Version(),
		PackageHash:   pkg.PackageHash,
		ManifestHash:  pkg.ManifestHash,
		EntriesHash:   pkg.EntriesHash,
		Signed:        signed,
		SignatureKey:  signatureKey,
		SignatureAlgo: signatureAlgo,
		VersionMatrix: version.CurrentMatrix(),
	})
}

func scaffoldPlugin(pluginID string, displayName string, outDir string) error {
	summary, err := createPluginScaffold(pluginID, displayName, outDir)
	if err != nil {
		return err
	}
	return writeJSON(summary)
}

func createPluginScaffold(pluginID string, displayName string, outDir string) (scaffoldSummary, error) {
	pluginID = strings.TrimSpace(pluginID)
	displayName = strings.TrimSpace(displayName)
	outDir = strings.TrimSpace(outDir)
	if pluginID == "" {
		return scaffoldSummary{}, fmt.Errorf("plugin_id is required")
	}
	if displayName == "" {
		return scaffoldSummary{}, fmt.Errorf("display_name is required")
	}
	if outDir == "" {
		return scaffoldSummary{}, fmt.Errorf("output directory is required")
	}
	manifestDoc := manifest.Manifest{
		SchemaVersion: "redevplugin.manifest.v5",
		Publisher: manifest.Publisher{
			PublisherID: "local.generated",
			DisplayName: "Local Generated",
		},
		Plugin: manifest.Plugin{
			PluginID:          pluginID,
			DisplayName:       displayName,
			Version:           "0.1.0",
			APIVersion:        "plugin-v1",
			MinRuntimeVersion: "0.5.0",
			UIProtocolVersion: "plugin-ui-v5",
		},
		Surfaces: []manifest.SurfaceSpec{{
			SurfaceID: pluginID + ".view",
			Kind:      manifest.SurfaceView,
			Intent:    manifest.SurfaceIntentPrimary,
			Label:     displayName,
			Entry:     "ui/index.html",
		}},
		Workers: []manifest.WorkerSpec{{
			WorkerID:         "backend",
			Artifact:         "workers/backend.wasm",
			ABI:              "redevplugin-wasm-worker-v2",
			Mode:             manifest.WorkerModeJob,
			Scope:            "user",
			MemoryLimitBytes: 16 << 20,
		}},
		Methods: []manifest.MethodSpec{{
			Method:    "worker.echo",
			Effect:    manifest.MethodEffectRead,
			Execution: manifest.MethodExecutionSync,
			Route:     manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "backend"},
			RequestSchema: closedRequiredMethodObjectSchema(map[string]any{
				"message": map[string]any{"type": "string"},
			}, []string{"message"}),
			ResponseSchema: scaffoldEchoResponseSchema(),
		}},
	}
	rawManifest, err := json.MarshalIndent(manifestDoc, "", "  ")
	if err != nil {
		return scaffoldSummary{}, err
	}
	platformVersion := version.CurrentCompatibilityVersion()
	manifestBytes := append(append([]byte(nil), rawManifest...), '\n')
	files := map[string][]byte{
		"README.md":                 []byte(scaffoldReadme(displayName, platformVersion)),
		"manifest.json":             append([]byte(nil), manifestBytes...),
		"package.json":              []byte(scaffoldPackageJSON(platformVersion)),
		"scripts/build.mjs":         []byte(scaffoldBuildScript()),
		"ui/index.html":             []byte(scaffoldIndexHTML(pluginID, displayName)),
		"ui/styles.css":             []byte(scaffoldStylesCSS()),
		"ui/src/app.ts":             scaffoldSource(scaffoldPluginWorkerTS, displayName),
		"worker/Cargo.toml":         []byte(scaffoldCargoTOML(platformVersion)),
		"worker/src/lib.rs":         append([]byte(nil), scaffoldWorkerRust...),
		"dist/manifest.json":        append([]byte(nil), manifestBytes...),
		"dist/ui/index.html":        []byte(scaffoldIndexHTML(pluginID, displayName)),
		"dist/ui/assets/app.js":     scaffoldSource(scaffoldPluginWorkerJS, displayName),
		"dist/ui/assets/styles.css": []byte(scaffoldStylesCSS()),
		"dist/workers/backend.wasm": append([]byte(nil), scaffoldWorkerWASM...),
	}
	if _, err := os.Stat(outDir); err == nil {
		entries, err := os.ReadDir(outDir)
		if err != nil {
			return scaffoldSummary{}, err
		}
		if len(entries) > 0 {
			return scaffoldSummary{}, fmt.Errorf("output directory %q is not empty", outDir)
		}
	} else if !os.IsNotExist(err) {
		return scaffoldSummary{}, err
	}
	created := make([]string, 0, len(files))
	for entryPath, content := range files {
		filename := filepath.Join(outDir, filepath.FromSlash(entryPath))
		if err := writeBytesFile(filename, content, 0o644); err != nil {
			return scaffoldSummary{}, err
		}
		created = append(created, entryPath)
	}
	sortStrings(created)
	return scaffoldSummary{
		OK:          true,
		Kind:        "plugin_scaffold",
		PluginID:    pluginID,
		Version:     manifestDoc.Plugin.Version,
		OutputDir:   outDir,
		Files:       created,
		VersionInfo: version.CurrentMatrix(),
	}, nil
}

func closedMethodObjectSchema(properties map[string]any) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
	}
}

func closedRequiredMethodObjectSchema(properties map[string]any, required []string) map[string]any {
	schema := closedMethodObjectSchema(properties)
	schema["required"] = append([]string(nil), required...)
	return schema
}

func scaffoldEchoResponseSchema() map[string]any {
	return closedRequiredMethodObjectSchema(map[string]any{
		"backend":   map[string]any{"type": "string"},
		"transport": map[string]any{"type": "string"},
		"method":    map[string]any{"type": "string", "const": "worker.echo"},
		"worker_id": map[string]any{"type": "string", "const": "backend"},
		"wasm_abi":  map[string]any{"type": "string", "const": version.WASMABIVersion},
		"message":   map[string]any{"type": "string"},
	}, []string{"backend", "transport", "method", "worker_id", "wasm_abi", "message"})
}

func scaffoldSource(source []byte, displayName string) []byte {
	encodedName, _ := json.Marshal(displayName)
	return []byte(strings.ReplaceAll(string(source), `"__REDEVPLUGIN_DISPLAY_NAME__"`, string(encodedName)))
}

func scaffoldPackageJSON(platformVersion string) string {
	return fmt.Sprintf(`{
  "name": "redevplugin-generated-plugin",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "node scripts/build.mjs",
    "build:ui": "esbuild ui/src/app.ts --bundle --format=iife --platform=browser --target=es2022 --outfile=dist/ui/assets/app.js",
    "typecheck": "tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext ui/src/app.ts"
  },
  "dependencies": {
    "@floegence/redevplugin-ui": %q
  },
  "devDependencies": {
    "esbuild": "0.25.5",
    "typescript": "5.9.3"
  }
}
`, platformVersion)
}

func scaffoldCargoTOML(platformVersion string) string {
	return fmt.Sprintf(`[package]
name = "redevplugin-generated-worker"
version = "0.1.0"
edition = "2024"
license = "MIT"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
redevplugin-worker-sdk = { git = "https://github.com/floegence/redevplugin", tag = "v%s" }
serde_json = "1.0"
`, platformVersion)
}

func scaffoldBuildScript() string {
	return `import { access, copyFile, mkdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";

run(npm, ["run", "build:ui"]);
try {
  await access(resolve(root, "worker/Cargo.lock"));
} catch {
  run(cargo, ["generate-lockfile", "--manifest-path", "worker/Cargo.toml"]);
}
run(cargo, ["build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "--manifest-path", "worker/Cargo.toml"]);
await mkdir(resolve(root, "dist/ui/assets"), { recursive: true });
await mkdir(resolve(root, "dist/workers"), { recursive: true });
await copyFile(resolve(root, "manifest.json"), resolve(root, "dist/manifest.json"));
await copyFile(resolve(root, "ui/index.html"), resolve(root, "dist/ui/index.html"));
await copyFile(resolve(root, "ui/styles.css"), resolve(root, "dist/ui/assets/styles.css"));
await copyFile(
  resolve(root, "worker/target/wasm32-unknown-unknown/release/redevplugin_generated_worker.wasm"),
  resolve(root, "dist/workers/backend.wasm"),
);

function run(command, args) {
  const result = spawnSync(command, args, { cwd: root, stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
`
}

func scaffoldReadme(displayName string, platformVersion string) string {
	return fmt.Sprintf(`# %s

This scaffold is a minimal ReDevPlugin application with an editable TypeScript
surface and Rust WASM worker. It requests no storage or network permissions.

The generated dist directory already contains compiled ui/assets/app.js and
workers/backend.wasm, so it can be validated and packaged immediately.

## Build

Requirements: Node.js 24, npm, Rust, and the wasm32-unknown-unknown target.

    npm install
    rustup target add wasm32-unknown-unknown
    npm run typecheck
    npm run build

The source dependencies are pinned to ReDevPlugin %s. After rebuilding, validate
and package the plugin from this directory:

    redevplugin validate dist/manifest.json
    redevplugin package dist %s.redevplugin

Edit ui/src/app.ts for the surface and worker/src/lib.rs for the WASM backend.
Add permissions to manifest.json only when the plugin
actually needs them.
`, displayName, platformVersion, strings.ReplaceAll(strings.ToLower(displayName), " ", "-"))
}

func keygen(keyID string, privateFile string, publicFile string) error {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return fmt.Errorf("key_id is required")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		return err
	}
	createdAt := time.Now().UTC().Format(time.RFC3339)
	privateDoc := signingPrivateKeyFile{
		SchemaVersion: "redevplugin.ed25519_signing_key.v1",
		Algorithm:     trust.AlgorithmEd25519,
		KeyID:         keyID,
		PrivateKey:    base64.StdEncoding.EncodeToString(privateKey),
		PublicKey:     base64.StdEncoding.EncodeToString(publicKey),
		CreatedAt:     createdAt,
	}
	publicDoc := signingPublicKeyFile{
		SchemaVersion: "redevplugin.ed25519_signing_key.v1",
		Algorithm:     trust.AlgorithmEd25519,
		KeyID:         keyID,
		PublicKey:     base64.StdEncoding.EncodeToString(publicKey),
		CreatedAt:     createdAt,
	}
	if err := writeJSONFile(privateFile, privateDoc, 0o600); err != nil {
		return err
	}
	if err := writeJSONFile(publicFile, publicDoc, 0o644); err != nil {
		return err
	}
	return writeJSON(keygenSummary{
		OK:         true,
		Algorithm:  trust.AlgorithmEd25519,
		KeyID:      keyID,
		PrivateKey: privateFile,
		PublicKey:  publicFile,
		CreatedAt:  createdAt,
	})
}

func signPackage(ctx context.Context, packageFile string, privateKeyFile string, outFile string) error {
	pkg, err := pluginpkg.ReadFile(ctx, packageFile, pluginpkg.DefaultReadLimits())
	if err != nil {
		return err
	}
	privateDoc, privateKey, err := readSigningPrivateKey(privateKeyFile)
	if err != nil {
		return err
	}
	sig, err := trust.SignatureForPackage(pkg, privateDoc.KeyID, privateDoc.PublisherID, privateDoc.PluginID, privateKey, time.Now().UTC())
	if err != nil {
		return err
	}
	pkg.PackageSignature = &sig
	var buf bytes.Buffer
	if err := pluginpkg.WritePackage(ctx, &buf, pkg); err != nil {
		return err
	}
	if err := writeBytesFile(outFile, buf.Bytes(), 0o644); err != nil {
		return err
	}
	signedPkg, err := pluginpkg.Read(ctx, bytes.NewReader(buf.Bytes()), int64(buf.Len()), pluginpkg.DefaultReadLimits())
	if err != nil {
		return err
	}
	signed, signatureKey, signatureAlgo := packageSignatureSummary(signedPkg)
	return writeJSON(validateSummary{
		OK:            true,
		Kind:          "package",
		PluginID:      signedPkg.Manifest.PluginID(),
		Version:       signedPkg.Manifest.Version(),
		PackageHash:   signedPkg.PackageHash,
		ManifestHash:  signedPkg.ManifestHash,
		EntriesHash:   signedPkg.EntriesHash,
		Signed:        signed,
		SignatureKey:  signatureKey,
		SignatureAlgo: signatureAlgo,
		VersionMatrix: version.CurrentMatrix(),
	})
}

func readSigningPrivateKey(filename string) (signingPrivateKeyFile, ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return signingPrivateKeyFile{}, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc signingPrivateKeyFile
	if err := decoder.Decode(&doc); err != nil {
		return signingPrivateKeyFile{}, nil, err
	}
	if doc.SchemaVersion != "redevplugin.ed25519_signing_key.v1" {
		return signingPrivateKeyFile{}, nil, fmt.Errorf("unsupported key schema_version %q", doc.SchemaVersion)
	}
	if doc.Algorithm != trust.AlgorithmEd25519 {
		return signingPrivateKeyFile{}, nil, fmt.Errorf("unsupported key algorithm %q", doc.Algorithm)
	}
	if strings.TrimSpace(doc.KeyID) == "" {
		return signingPrivateKeyFile{}, nil, fmt.Errorf("key_id is required")
	}
	privateKey, err := base64.StdEncoding.DecodeString(doc.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return signingPrivateKeyFile{}, nil, fmt.Errorf("private_key is not a valid ed25519 private key")
	}
	if doc.PublicKey != "" {
		publicKey, err := base64.StdEncoding.DecodeString(doc.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return signingPrivateKeyFile{}, nil, fmt.Errorf("public_key is not a valid ed25519 public key")
		}
		derivedPublicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
		if !bytes.Equal(publicKey, derivedPublicKey) {
			return signingPrivateKeyFile{}, nil, fmt.Errorf("public_key does not match private_key")
		}
	}
	doc.KeyID = strings.TrimSpace(doc.KeyID)
	return doc, ed25519.PrivateKey(privateKey), nil
}

func packageSignatureSummary(pkg pluginpkg.Package) (bool, string, string) {
	if pkg.PackageSignature == nil {
		return false, "", ""
	}
	return true, pkg.PackageSignature.KeyID, pkg.PackageSignature.Algorithm
}

func optionalSecretScope(args []string) string {
	if len(args) == 4 {
		return args[3]
	}
	return "user"
}

func writeJSON(v any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}

func writeJSONFile(filename string, value any, perm os.FileMode) error {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	return writeBytesFile(filename, buf.Bytes(), perm)
}

func writeBytesFile(filename string, data []byte, perm os.FileMode) error {
	if outDir := filepath.Dir(filename); outDir != "." {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filename, data, perm); err != nil {
		return err
	}
	return os.Chmod(filename, perm)
}

func usage() error {
	return fmt.Errorf("usage: redevplugin validate <manifest.json|package.redevplugin> | redevplugin scaffold <plugin-id> <display-name> <out-dir> | redevplugin package <dir> <out.redevplugin> | redevplugin keygen <key-id> <private.json> <public.json> | redevplugin sign <package.redevplugin> <private.json> <out.redevplugin> | redevplugin host-capability build <config.json> <out-dir> | redevplugin host-capability verify <artifact-root> <pin.json> <public.json> | redevplugin host-capability generate-client <artifact-root> <pin.json> <public.json> <out.ts> [--check] | redevplugin inspect-data <state-root> [plugin-instance-id] | redevplugin install-local <package> | redevplugin install-verified <signed-package> <public.json> | redevplugin dev-install <state-root> <package> [--capability <artifact-root> <pin.json> <public.json>]... | redevplugin dev-enable <state-root> | redevplugin dev-open <state-root> <surface-id> | redevplugin dev-secret-bind <state-root> <secret-ref> [user|environment] | redevplugin dev-secret-test <state-root> <secret-ref> [user|environment] | redevplugin dev-secret-delete <state-root> <secret-ref> [user|environment] | redevplugin dev-permission-grant <state-root> <permission-id> | redevplugin dev-permission-revoke <state-root> <permission-id> [reason] | redevplugin dev-permission-list <state-root> [--active-only] | redevplugin dev-export-data <state-root> | redevplugin dev-import-data <state-root> <bundle-ref> | redevplugin dev-delete-export <state-root> <bundle-ref> | redevplugin dev-disable <state-root> | redevplugin dev-uninstall <state-root> | redevplugin dev-status <state-root> | redevplugin examples-server <state-root> <runtime-path> | redevplugin enable <package> | redevplugin disable <package> | redevplugin uninstall <package> | redevplugin version | redevplugin verify-compatibility <compatibility.json> <artifact-root>")
}

func lifecycleHarness(ctx context.Context, action string, packageFile string) error {
	data, err := os.ReadFile(packageFile)
	if err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "redevplugin-lifecycle-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	registryStore := registry.NewMemoryStore()
	pluginData, err := plugindata.Open(ctx, filepath.Join(root, "plugin-data"), registryStore)
	if err != nil {
		return err
	}
	h, err := host.Open(ctx, newEphemeralCLIAdapters(registryStore, pluginData))
	if err != nil {
		_ = pluginData.Close()
		return err
	}
	defer h.Close()
	pluginInstanceID, err := newCLIPluginInstanceID()
	if err != nil {
		return err
	}
	record, err := host.ImportLocalPackageBytes(ctx, h, pluginInstanceID, data)
	if err != nil {
		return err
	}
	switch action {
	case "install-local":
		return writeLifecycle(action, record)
	case "enable":
		record, err = h.EnablePlugin(ctx, host.EnableRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision})
	case "disable":
		record, err = h.EnablePlugin(ctx, host.EnableRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision})
		if err == nil {
			record, err = h.DisablePlugin(ctx, host.DisableRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, Reason: "cli"})
		}
	case "uninstall":
		record, err = h.UninstallPlugin(ctx, host.UninstallRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, DeleteData: true})
	}
	if err != nil {
		return err
	}
	return writeLifecycle(action, record)
}

func installVerifiedHarness(ctx context.Context, packageFile string, publicKeyFile string) error {
	data, err := os.ReadFile(packageFile)
	if err != nil {
		return err
	}
	publicDoc, publicKey, err := readSigningPublicKey(publicKeyFile)
	if err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "redevplugin-verified-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	registryStore := registry.NewMemoryStore()
	pluginData, err := plugindata.Open(ctx, filepath.Join(root, "plugin-data"), registryStore)
	if err != nil {
		return err
	}
	adapters := newEphemeralCLIAdapters(registryStore, pluginData)
	verifier := trust.Ed25519Verifier{
		Keyring: trust.StaticKeyring{Keys: []trust.SigningKey{{
			Algorithm:   publicDoc.Algorithm,
			KeyID:       publicDoc.KeyID,
			PublisherID: publicDoc.PublisherID,
			PluginID:    publicDoc.PluginID,
			PublicKey:   publicKey,
		}}},
	}
	adapters.Core.PackageTrustVerifier = verifier
	h, err := host.Open(ctx, adapters)
	if err != nil {
		_ = pluginData.Close()
		return err
	}
	defer h.Close()
	pluginInstanceID, err := newCLIPluginInstanceID()
	if err != nil {
		return err
	}
	record, err := host.ImportLocalPackageBytes(ctx, h, pluginInstanceID, data)
	if err != nil {
		return err
	}
	return writeLifecycle("install-verified", record)
}

func newCLIPluginInstanceID() (string, error) {
	raw := make([]byte, 18)
	if _, err := crand.Read(raw); err != nil {
		return "", err
	}
	return "plugini_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func writeLifecycle(action string, record registry.PluginRecord) error {
	return writeJSON(lifecycleSummary{
		OK:                 true,
		Action:             action,
		PluginInstanceID:   record.PluginInstanceID,
		PluginID:           record.PluginID,
		Version:            record.Version,
		TrustState:         record.TrustState,
		EnableState:        record.EnableState,
		PolicyRevision:     record.PolicyRevision,
		ManagementRevision: record.ManagementRevision,
		RevokeEpoch:        record.RevokeEpoch,
	})
}

func readSigningPublicKey(filename string) (signingPublicKeyFile, ed25519.PublicKey, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return signingPublicKeyFile{}, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc signingPublicKeyFile
	if err := decoder.Decode(&doc); err != nil {
		return signingPublicKeyFile{}, nil, err
	}
	if doc.SchemaVersion != "redevplugin.ed25519_signing_key.v1" {
		return signingPublicKeyFile{}, nil, fmt.Errorf("unsupported key schema_version %q", doc.SchemaVersion)
	}
	if doc.Algorithm != trust.AlgorithmEd25519 {
		return signingPublicKeyFile{}, nil, fmt.Errorf("unsupported key algorithm %q", doc.Algorithm)
	}
	doc.KeyID = strings.TrimSpace(doc.KeyID)
	if doc.KeyID == "" {
		return signingPublicKeyFile{}, nil, fmt.Errorf("key_id is required")
	}
	publicKey, err := base64.StdEncoding.DecodeString(doc.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return signingPublicKeyFile{}, nil, fmt.Errorf("public_key is not a valid ed25519 public key")
	}
	return doc, ed25519.PublicKey(publicKey), nil
}

func scaffoldIndexHTML(_ string, displayName string) string {
	title := htmlEscape(displayName)
	return "<!doctype html>\n" +
		"<html lang=\"en\">\n" +
		"  <head>\n" +
		"    <meta charset=\"utf-8\">\n" +
		"    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
		"    <title>" + title + "</title>\n" +
		"    <link rel=\"stylesheet\" href=\"assets/styles.css\">\n" +
		"  </head>\n" +
		"  <body>\n" +
		"    <main class=\"surface\">\n" +
		"      <section class=\"surface\">\n" +
		"        <p class=\"eyebrow\">Plugin surface</p>\n" +
		"        <h1>" + title + "</h1>\n" +
		"        <p class=\"status\">Starting isolated worker...</p>\n" +
		"      </section>\n" +
		"    </main>\n" +
		"    <script type=\"text/redevplugin-worker\" src=\"assets/app.js\"></script>\n" +
		"  </body>\n" +
		"</html>\n"
}

func scaffoldStylesCSS() string {
	return ":root {\n" +
		"  color-scheme: light dark;\n" +
		"  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif;\n" +
		"}\n\n" +
		"* {\n" +
		"  box-sizing: border-box;\n" +
		"}\n\n" +
		"body {\n" +
		"  margin: 0;\n" +
		"  min-height: 100vh;\n" +
		"  background: Canvas;\n" +
		"  color: CanvasText;\n" +
		"}\n\n" +
		".surface {\n" +
		"  display: grid;\n" +
		"  gap: 14px;\n" +
		"  min-height: 100vh;\n" +
		"  align-content: start;\n" +
		"  padding: 20px;\n" +
		"}\n\n" +
		".eyebrow {\n" +
		"  margin: 0;\n" +
		"  font-size: 12px;\n" +
		"  opacity: 0.68;\n" +
		"  text-transform: uppercase;\n" +
		"}\n\n" +
		"h1 {\n" +
		"  margin: 0;\n" +
		"  font-size: 24px;\n" +
		"  font-weight: 650;\n" +
		"}\n\n" +
		"h2 {\n" +
		"  margin: 0;\n" +
		"  font-size: 18px;\n" +
		"  font-weight: 650;\n" +
		"}\n\n" +
		".status {\n" +
		"  margin: 0;\n" +
		"  font-size: 14px;\n" +
		"  line-height: 1.5;\n" +
		"  min-height: 22px;\n" +
		"}\n\n" +
		".toolbar {\n" +
		"  align-items: center;\n" +
		"  display: flex;\n" +
		"  flex-wrap: wrap;\n" +
		"  gap: 12px;\n" +
		"}\n\n" +
		"button {\n" +
		"  width: fit-content;\n" +
		"  border: 1px solid ButtonBorder;\n" +
		"  border-radius: 6px;\n" +
		"  background: ButtonFace;\n" +
		"  color: ButtonText;\n" +
		"  cursor: pointer;\n" +
		"  font: inherit;\n" +
		"  padding: 8px 12px;\n" +
		"}\n\n" +
		".planner-panel {\n" +
		"  display: grid;\n" +
		"  gap: 12px;\n" +
		"  border: 1px solid color-mix(in srgb, CanvasText 18%, transparent);\n" +
		"  border-radius: 8px;\n" +
		"  padding: 14px;\n" +
		"}\n\n" +
		".schedule-grid {\n" +
		"  display: grid;\n" +
		"  gap: 10px;\n" +
		"  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));\n" +
		"}\n\n" +
		".schedule-tile {\n" +
		"  display: grid;\n" +
		"  gap: 4px;\n" +
		"  border: 1px solid color-mix(in srgb, CanvasText 12%, transparent);\n" +
		"  border-radius: 8px;\n" +
		"  padding: 10px;\n" +
		"}\n\n" +
		".schedule-tile span,\n" +
		".schedule-list span {\n" +
		"  font-size: 12px;\n" +
		"  opacity: 0.72;\n" +
		"}\n\n" +
		".schedule-list {\n" +
		"  display: grid;\n" +
		"  gap: 8px;\n" +
		"  list-style: none;\n" +
		"  margin: 0;\n" +
		"  padding: 0;\n" +
		"}\n\n" +
		".schedule-list li {\n" +
		"  display: grid;\n" +
		"  gap: 4px;\n" +
		"  border-left: 3px solid color-mix(in srgb, Highlight 72%, CanvasText 8%);\n" +
		"  padding: 8px 10px;\n" +
		"}\n"
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(value)
}

func sortStrings(values []string) {
	sort.Strings(values)
}

func cliContext(ctx context.Context) context.Context {
	return sessionctx.WithContext(ctx, sessionctx.Context{
		OwnerSessionHash:     "cli_owner_session",
		OwnerUserHash:        "cli_owner_user",
		OwnerEnvHash:         "cli_owner_environment",
		SessionChannelIDHash: "cli_session_channel",
	})
}

func newEphemeralCLIAdapters(registryStore registry.Store, pluginData host.PluginData) host.Config {
	events := observability.NewMemoryStore()
	connectivityBroker := connectivity.NewMemoryBroker()
	return host.Config{
		Core: host.CoreAdapters{
			Policy:               staticPolicyAdapter{},
			Authorization:        staticAuthorizationAdapter{},
			PackageTrustVerifier: trust.Ed25519Verifier{Keyring: trust.StaticKeyring{}},
			Registry:             registryStore,
			Audit:                events,
			SecurityAudit:        events,
			Diagnostics:          events,
			SurfaceTokens:        bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{}),
			PluginData:           pluginData,
			Assets:               pluginpkg.NewMemoryAssetStore(),
			InstallStages:        installstage.NewMemoryStore(),
			Operations:           operation.NewMemoryStore(),
			ConfirmationIntents:  security.NewMemoryConfirmationIntentStore(),
			Streams:              stream.NewMemoryStore(),
		},
		Connectivity: &host.ConnectivityModule{
			Broker:          connectivityBroker,
			NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{}),
		},
		Secrets: &host.SecretsModule{Store: secrets.NewMemoryStore()},
	}
}

type staticPolicyAdapter struct{}

type staticAuthorizationAdapter struct{}

func (staticAuthorizationAdapter) Authorize(_ context.Context, req host.AuthorizationRequest) error {
	if !req.Session.Valid() || !req.Action.Valid() || !req.Target.Kind.Valid() || req.Target.Kind != req.Action.Resource() {
		return host.ErrActionDenied
	}
	return nil
}

func (staticPolicyAdapter) EvaluateLocalPolicy(context.Context, sessionctx.Context, host.PluginRef, manifest.MethodSpec) (host.PolicyDecision, error) {
	return host.PolicyAllow, nil
}

func (staticPolicyAdapter) DeveloperModeEnabled(context.Context, sessionctx.Context) (bool, error) {
	return true, nil
}

func (staticPolicyAdapter) LocalGeneratedPluginsEnabled(context.Context, sessionctx.Context) (bool, error) {
	return true, nil
}
