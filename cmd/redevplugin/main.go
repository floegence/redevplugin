package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/storage"
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
	OK                 bool                       `json:"ok"`
	Action             string                     `json:"action"`
	PluginInstanceID   string                     `json:"plugin_instance_id"`
	PluginID           string                     `json:"plugin_id"`
	Version            string                     `json:"version"`
	TrustState         registry.TrustState        `json:"trust_state"`
	EnableState        registry.EnableState       `json:"enable_state"`
	RetainedDataState  registry.RetainedDataState `json:"retained_data_state"`
	PolicyRevision     uint64                     `json:"policy_revision"`
	ManagementRevision uint64                     `json:"management_revision"`
	RevokeEpoch        uint64                     `json:"revoke_epoch"`
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

type compatibilityVerifySummary struct {
	OK            bool   `json:"ok"`
	SchemaVersion string `json:"schema_version"`
	Contracts     int    `json:"contracts"`
}

type storageInspectSummary struct {
	OK               bool                      `json:"ok"`
	StorageRoot      string                    `json:"storage_root"`
	PluginInstanceID string                    `json:"plugin_instance_id,omitempty"`
	NamespaceCount   int                       `json:"namespace_count"`
	TotalUsageBytes  int64                     `json:"total_usage_bytes"`
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
	case "inspect-storage":
		if len(args) != 2 && len(args) != 3 {
			return usage()
		}
		pluginInstanceID := ""
		if len(args) == 3 {
			pluginInstanceID = args[2]
		}
		return inspectStorage(ctx, args[1], pluginInstanceID)
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
		if len(args) != 3 {
			return usage()
		}
		return devInstall(ctx, args[1], args[2])
	case "dev-enable":
		if len(args) != 2 {
			return usage()
		}
		return devEnable(ctx, args[1])
	case "dev-open":
		if len(args) != 3 && len(args) != 4 {
			return usage()
		}
		sandboxOrigin := ""
		if len(args) == 4 {
			sandboxOrigin = args[3]
		}
		return devOpen(ctx, args[1], args[2], sandboxOrigin)
	case "dev-disable":
		if len(args) != 2 {
			return usage()
		}
		return devDisable(ctx, args[1])
	case "dev-uninstall":
		if len(args) != 2 && len(args) != 3 {
			return usage()
		}
		deleteData := true
		if len(args) == 3 {
			switch args[2] {
			case "--delete-data":
				deleteData = true
			case "--keep-data":
				deleteData = false
			default:
				return usage()
			}
		}
		return devUninstall(ctx, args[1], deleteData)
	case "dev-status":
		if len(args) != 2 {
			return usage()
		}
		return devStatus(args[1])
	case "demo-real-server":
		if len(args) != 3 {
			return usage()
		}
		return demoRealServer(ctx, args[1], args[2])
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

func inspectStorage(ctx context.Context, root string, pluginInstanceID string) error {
	root = strings.TrimSpace(root)
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if root == "" {
		return fmt.Errorf("storage root is required")
	}
	broker, err := storage.NewFileBroker(root)
	if err != nil {
		return err
	}
	records, err := broker.ListNamespaces(ctx, pluginInstanceID)
	if err != nil {
		return err
	}
	totalUsage := int64(0)
	for i := range records {
		usage, err := broker.Usage(ctx, records[i].PluginInstanceID, records[i].StoreID)
		if err != nil {
			return err
		}
		records[i].UsageBytes = usage.UsageBytes
		records[i].QuotaBytes = usage.QuotaBytes
		totalUsage += usage.UsageBytes
	}
	return writeJSON(storageInspectSummary{
		OK:               true,
		StorageRoot:      broker.Root(),
		PluginInstanceID: pluginInstanceID,
		NamespaceCount:   len(records),
		TotalUsageBytes:  totalUsage,
		Namespaces:       records,
		VersionMatrix:    version.CurrentMatrix(),
	})
}

func validate(ctx context.Context, filename string) error {
	if strings.HasSuffix(filename, ".redevplugin") || strings.HasSuffix(filename, ".zip") {
		pkg, err := pluginpkg.ReadFile(ctx, filename, pluginpkg.DefaultReadOptions())
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
	pkg, err := pluginpkg.BuildFromDir(ctx, srcDir, &buf, pluginpkg.DefaultReadOptions())
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
		SchemaVersion: "redevplugin.manifest.v1",
		Publisher: manifest.Publisher{
			PublisherID: "local.generated",
			DisplayName: "Local Generated",
		},
		Plugin: manifest.Plugin{
			PluginID:          pluginID,
			DisplayName:       displayName,
			Version:           "0.1.0",
			APIVersion:        "plugin-v1",
			MinRuntimeVersion: "0.1.0",
			UIProtocolVersion: "plugin-ui-v1",
		},
		Surfaces: []manifest.SurfaceSpec{{
			SurfaceID: pluginID + ".activity",
			Kind:      manifest.SurfaceActivity,
			Label:     displayName,
			Entry:     "ui/index.html",
			Method:    "worker.echo",
		}},
		Workers: []manifest.WorkerSpec{{
			WorkerID:         "backend",
			Artifact:         "workers/backend.wasm",
			ABI:              "redevplugin-wasm-worker-v1",
			Mode:             manifest.WorkerModeJob,
			Scope:            "user",
			MemoryLimitBytes: 16 << 20,
		}, {
			WorkerID:         "broker_backend",
			Artifact:         "workers/broker.wasm",
			ABI:              "redevplugin-wasm-worker-v1",
			Mode:             manifest.WorkerModeJob,
			Scope:            "user",
			MemoryLimitBytes: 16 << 20,
		}},
		Methods: []manifest.MethodSpec{{
			Method:         "worker.echo",
			Effect:         manifest.MethodEffectRead,
			Execution:      manifest.MethodExecutionSync,
			Route:          manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "backend", Export: "redevplugin_worker_invoke"},
			RequestSchema:  map[string]any{"type": "object", "additionalProperties": true},
			ResponseSchema: map[string]any{"type": "object"},
		}, {
			Method:         "worker.brokerDemo",
			Effect:         manifest.MethodEffectWrite,
			Execution:      manifest.MethodExecutionSync,
			Route:          manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "broker_backend", Export: "redevplugin_worker_invoke"},
			RequestSchema:  map[string]any{"type": "object", "additionalProperties": true},
			ResponseSchema: map[string]any{"type": "object"},
		}},
		Storage: &manifest.StorageSpec{
			Stores: []manifest.StoreSpec{{
				StoreID:       "workspace",
				Kind:          string(storage.StoreFiles),
				Scope:         "user",
				QuotaBytes:    1 << 20,
				SchemaVersion: 1,
				Migration: manifest.MigrationSpec{
					FromVersion:    0,
					ToVersion:      1,
					Reversible:     true,
					RequiresWorker: false,
					EstimatedBytes: 0,
					MaxDurationMS:  1000,
					DataLossRisk:   false,
					StepsHash:      "sha256:generated-workspace-v1",
				},
			}, {
				StoreID:       "settings",
				Kind:          string(storage.StoreKV),
				Scope:         "user",
				QuotaBytes:    256 << 10,
				SchemaVersion: 1,
				Migration: manifest.MigrationSpec{
					FromVersion:    0,
					ToVersion:      1,
					Reversible:     true,
					RequiresWorker: false,
					EstimatedBytes: 0,
					MaxDurationMS:  1000,
					DataLossRisk:   false,
					StepsHash:      "sha256:generated-settings-v1",
				},
			}, {
				StoreID:       "db",
				Kind:          string(storage.StoreSQLite),
				Scope:         "user",
				QuotaBytes:    1 << 20,
				SchemaVersion: 1,
				Migration: manifest.MigrationSpec{
					FromVersion:    0,
					ToVersion:      1,
					Reversible:     true,
					RequiresWorker: false,
					EstimatedBytes: 0,
					MaxDurationMS:  1000,
					DataLossRisk:   false,
					StepsHash:      "sha256:generated-sqlite-v1",
				},
			}},
		},
		NetworkAccess: &manifest.NetworkAccessSpec{
			Connectors: []manifest.NetworkConnectorSpec{{
				ConnectorID:  "api",
				Transport:    "http",
				Scope:        "user",
				Destinations: []string{"https://api.example.com"},
			}, {
				ConnectorID:  "stream",
				Transport:    "websocket",
				Scope:        "user",
				Destinations: []string{"wss://stream.example.com"},
			}, {
				ConnectorID:  "mysql",
				Transport:    "tcp",
				Scope:        "user",
				Destinations: []string{"db.example.com:3306"},
			}, {
				ConnectorID:  "metrics",
				Transport:    "udp",
				Scope:        "user",
				Destinations: []string{"metrics.example.com:8125"},
			}},
		},
	}
	rawManifest, err := json.MarshalIndent(manifestDoc, "", "  ")
	if err != nil {
		return scaffoldSummary{}, err
	}
	files := map[string][]byte{
		"manifest.json":        append(rawManifest, '\n'),
		"ui/index.html":        []byte(scaffoldIndexHTML(pluginID, displayName)),
		"ui/assets/app.js":     []byte(scaffoldAppJS(displayName)),
		"ui/assets/styles.css": []byte(scaffoldStylesCSS()),
		"workers/backend.wat":  []byte(scaffoldWorkerWAT()),
		"workers/backend.wasm": minimalWorkerWASM(),
		"workers/broker.wat":   []byte(scaffoldBrokerWorkerWAT()),
		"workers/broker.wasm":  scaffoldBrokerWorkerWASM(),
		"workers/abi.json":     []byte(scaffoldWorkerABIJSON()),
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
	pkg, err := pluginpkg.ReadFile(ctx, packageFile, pluginpkg.DefaultReadOptions())
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
	signedPkg, err := pluginpkg.Read(ctx, bytes.NewReader(buf.Bytes()), int64(buf.Len()), pluginpkg.DefaultReadOptions())
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
	return fmt.Errorf("usage: redevplugin validate <manifest.json|package.redevplugin> | redevplugin scaffold <plugin-id> <display-name> <out-dir> | redevplugin package <dir> <out.redevplugin> | redevplugin keygen <key-id> <private.json> <public.json> | redevplugin sign <package.redevplugin> <private.json> <out.redevplugin> | redevplugin inspect-storage <storage-root> [plugin-instance-id] | redevplugin install-local <package> | redevplugin install-verified <signed-package> <public.json> | redevplugin dev-install <state-root> <package> | redevplugin dev-enable <state-root> | redevplugin dev-open <state-root> <surface-id> [sandbox-origin] | redevplugin dev-disable <state-root> | redevplugin dev-uninstall <state-root> [--delete-data|--keep-data] | redevplugin dev-status <state-root> | redevplugin demo-real-server <state-root> <runtime-path> | redevplugin enable <package> | redevplugin disable <package> | redevplugin uninstall <package> | redevplugin version | redevplugin verify-compatibility <compatibility.json> <artifact-root>")
}

func lifecycleHarness(ctx context.Context, action string, packageFile string) error {
	data, err := os.ReadFile(packageFile)
	if err != nil {
		return err
	}
	h, err := host.New(host.Adapters{
		SessionResolver: staticSessionResolver{},
		Policy:          staticPolicyAdapter{},
		Storage:         storage.NewMemoryBroker(),
	})
	if err != nil {
		return err
	}
	record, err := host.InstallPackageBytes(ctx, h, data, registry.TrustUnsignedLocal)
	if err != nil {
		return err
	}
	switch action {
	case "install-local":
		return writeLifecycle(action, record)
	case "enable":
		record, err = h.EnablePlugin(ctx, host.EnableRequest{PluginInstanceID: record.PluginInstanceID})
	case "disable":
		record, err = h.EnablePlugin(ctx, host.EnableRequest{PluginInstanceID: record.PluginInstanceID})
		if err == nil {
			record, err = h.DisablePlugin(ctx, host.DisableRequest{PluginInstanceID: record.PluginInstanceID, Reason: "cli"})
		}
	case "uninstall":
		record, err = h.UninstallPlugin(ctx, host.UninstallRequest{PluginInstanceID: record.PluginInstanceID, DeleteData: true})
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
	h, err := host.New(host.Adapters{
		SessionResolver: staticSessionResolver{},
		Policy:          staticPolicyAdapter{},
		PackageTrustVerifier: trust.Ed25519Verifier{
			Keyring: trust.StaticKeyring{Keys: []trust.SigningKey{{
				Algorithm:   publicDoc.Algorithm,
				KeyID:       publicDoc.KeyID,
				PublisherID: publicDoc.PublisherID,
				PluginID:    publicDoc.PluginID,
				PublicKey:   publicKey,
			}}},
		},
	})
	if err != nil {
		return err
	}
	record, err := host.InstallPackageBytes(ctx, h, data, registry.TrustVerified)
	if err != nil {
		return err
	}
	return writeLifecycle("install-verified", record)
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
		RetainedDataState:  record.RetainedDataState,
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

func scaffoldIndexHTML(pluginID string, displayName string) string {
	pluginID = htmlEscape(pluginID)
	title := htmlEscape(displayName)
	surfaceID := htmlEscape(pluginID + ".activity")
	return "<!doctype html>\n" +
		"<html lang=\"en\">\n" +
		"  <head>\n" +
		"    <meta charset=\"utf-8\">\n" +
		"    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
		"    <title>" + title + "</title>\n" +
		"    <link rel=\"stylesheet\" href=\"assets/styles.css\">\n" +
		"    <script src=\"assets/app.js\" defer></script>\n" +
		"  </head>\n" +
		"  <body>\n" +
		"    <main id=\"app\" data-plugin-title=\"" + title + "\" data-plugin-id=\"" + pluginID + "\" data-surface-id=\"" + surfaceID + "\">\n" +
		"      <section class=\"surface\">\n" +
		"        <p class=\"eyebrow\">Plugin surface</p>\n" +
		"        <h1>" + title + "</h1>\n" +
		"        <div class=\"toolbar\">\n" +
		"          <p class=\"status\" id=\"status\">Ready</p>\n" +
		"          <button id=\"invoke-worker\" type=\"button\">Invoke backend</button>\n" +
		"          <button id=\"invoke-broker\" type=\"button\">Storage + network</button>\n" +
		"        </div>\n" +
		"        <pre id=\"result\" aria-label=\"Latest result\">Waiting for bridge handshake...</pre>\n" +
		"      </section>\n" +
		"    </main>\n" +
		"  </body>\n" +
		"</html>\n"
}

func scaffoldAppJS(displayName string) string {
	message, _ := json.Marshal("Hello from " + displayName)
	return "const status = document.getElementById('status');\n" +
		"const invokeButton = document.getElementById('invoke-worker');\n" +
		"const brokerButton = document.getElementById('invoke-broker');\n" +
		"const result = document.getElementById('result');\n" +
		"const params = new URLSearchParams(window.location.search);\n" +
		"const parentOrigin = params.get('parent_origin');\n" +
		"const bootstrap = {\n" +
		"  pluginId: params.get('plugin_id') || document.getElementById('app')?.dataset.pluginId || 'local.generated.plugin',\n" +
		"  surfaceId: params.get('surface_id') || document.getElementById('app')?.dataset.surfaceId || 'local.generated.plugin.activity',\n" +
		"  surfaceInstanceId: params.get('surface_instance_id') || 'surface_generated_preview',\n" +
		"  activeFingerprint: params.get('active_fingerprint') || 'sha256:generated-preview',\n" +
		"  bridgeNonce: params.get('bridge_nonce') || 'bridge_nonce_generated_preview',\n" +
		"};\n" +
		"let nextID = 1;\n" +
		"const pending = new Map();\n" +
		"if (!parentOrigin || parentOrigin === '*') {\n" +
		"  setStatus('Missing exact parent_origin');\n" +
		"} else {\n" +
		"  window.addEventListener('message', handleMessage);\n" +
		"  window.parent.postMessage({\n" +
		"    type: 'redevplugin.bridge.handshake',\n" +
		"    plugin_id: bootstrap.pluginId,\n" +
		"    surface_id: bootstrap.surfaceId,\n" +
		"    surface_instance_id: bootstrap.surfaceInstanceId,\n" +
		"    active_fingerprint: bootstrap.activeFingerprint,\n" +
		"    bridge_nonce: bootstrap.bridgeNonce,\n" +
		"    ui_protocol_version: 'plugin-ui-v1',\n" +
		"  }, parentOrigin);\n" +
		"  setStatus('Handshaking with host...');\n" +
		"}\n" +
		"if (invokeButton) {\n" +
		"  invokeButton.addEventListener('click', async () => {\n" +
		"    try {\n" +
		"      setStatus('Calling worker.echo...');\n" +
		"      const response = await callHost('worker.echo', { message: " + string(message) + " });\n" +
		"      setStatus('Backend responded');\n" +
		"      writeResult({ method: 'worker.echo', response });\n" +
		"    } catch (error) {\n" +
		"      setStatus('Backend call failed');\n" +
		"      writeResult({ error: String(error?.message || error), error_code: error?.errorCode });\n" +
		"    }\n" +
		"  });\n" +
		"}\n" +
		"if (brokerButton) {\n" +
		"  brokerButton.addEventListener('click', async () => {\n" +
		"    try {\n" +
		"      setStatus('Calling worker.brokerDemo...');\n" +
		"      const response = await callHost('worker.brokerDemo', { note: 'Generated plugin storage and network sample' });\n" +
		"      setStatus('Brokered backend responded');\n" +
		"      writeResult({ method: 'worker.brokerDemo', response, token_leak_check: tokenLeakCheck(response) });\n" +
		"    } catch (error) {\n" +
		"      setStatus('Brokered backend failed');\n" +
		"      writeResult({ method: 'worker.brokerDemo', error: String(error?.message || error), error_code: error?.errorCode });\n" +
		"    }\n" +
		"  });\n" +
		"}\n" +
		"function handleMessage(event) {\n" +
		"  if (event.origin !== parentOrigin) {\n" +
		"    return;\n" +
		"  }\n" +
		"  const data = event.data;\n" +
		"  if (data?.type === 'redevplugin.bridge.lifecycle') {\n" +
		"    setStatus(data.event?.type === 'ready' ? 'Ready' : `Lifecycle: ${data.event?.type || 'unknown'}`);\n" +
		"    return;\n" +
		"  }\n" +
		"  if (data?.type !== 'redevplugin.bridge.response' || typeof data.id !== 'string') {\n" +
		"    return;\n" +
		"  }\n" +
		"  const call = pending.get(data.id);\n" +
		"  if (!call) {\n" +
		"    return;\n" +
		"  }\n" +
		"  pending.delete(data.id);\n" +
		"  window.clearTimeout(call.timer);\n" +
		"  if (data.ok) {\n" +
		"    call.resolve(data.data);\n" +
		"  } else {\n" +
		"    const error = new Error(data.error || 'Plugin call failed');\n" +
		"    error.errorCode = data.error_code || 'PLUGIN_CALL_FAILED';\n" +
		"    call.reject(error);\n" +
		"  }\n" +
		"}\n" +
		"function callHost(method, callParams) {\n" +
		"  if (!parentOrigin || parentOrigin === '*') {\n" +
		"    return Promise.reject(new Error('parent_origin must be an exact origin'));\n" +
		"  }\n" +
		"  const id = String(nextID++);\n" +
		"  const promise = new Promise((resolve, reject) => {\n" +
		"    const timer = window.setTimeout(() => {\n" +
		"      pending.delete(id);\n" +
		"      reject(new Error(`Plugin bridge call ${id} timed out`));\n" +
		"    }, 30000);\n" +
		"    pending.set(id, { resolve, reject, timer });\n" +
		"  });\n" +
		"  window.parent.postMessage({ type: 'redevplugin.bridge.call', request: { id, method, params: callParams } }, parentOrigin);\n" +
		"  return promise;\n" +
		"}\n" +
		"function setStatus(value) {\n" +
		"  if (status) {\n" +
		"    status.textContent = value;\n" +
		"  }\n" +
		"}\n" +
		"function writeResult(value) {\n" +
		"  if (result) {\n" +
		"    result.textContent = JSON.stringify(value, null, 2);\n" +
		"  }\n" +
		"}\n" +
		"function tokenLeakCheck(value) {\n" +
		"  const raw = JSON.stringify(value || {});\n" +
		"  return {\n" +
		"    gateway_token_visible: raw.includes('gateway_token'),\n" +
		"    storage_grant_visible: raw.includes('storage_handle_grant_token') || raw.includes('storage_kv_handle_grant_token') || raw.includes('storage_sqlite_handle_grant_token'),\n" +
		"    network_grant_visible: raw.includes('connection_grant_token'),\n" +
		"  };\n" +
		"}\n"
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
		"}\n"
}

func scaffoldWorkerWAT() string {
	return "(module\n" +
		"  ;; Minimal ReDevPlugin worker scaffold. Replace this module with a\n" +
		"  ;; generated worker that implements redevplugin-wasm-worker-v1.\n" +
		"  (func $redevplugin_worker_invoke (export \"redevplugin_worker_invoke\")\n" +
		"    nop)\n" +
		")\n"
}

func scaffoldBrokerWorkerWAT() string {
	var b strings.Builder
	b.WriteString("(module\n" +
		"  ;; Broker worker scaffold. Generated plugins use the real\n" +
		"  ;; linear-memory storage/network ABI; Host injects identity,\n" +
		"  ;; handle grants, policy revisions, and network grants at runtime.\n" +
		"  (import \"redevplugin.storage\" \"files\" (func $storage_files (param i32 i32 i32 i32) (result i32)))\n" +
		"  (import \"redevplugin.storage\" \"kv\" (func $storage_kv (param i32 i32 i32 i32) (result i32)))\n" +
		"  (import \"redevplugin.storage\" \"sqlite\" (func $storage_sqlite (param i32 i32 i32 i32) (result i32)))\n" +
		"  (import \"redevplugin.network\" \"http_request\" (func $network_http_request (param i32 i32 i32 i32) (result i32)))\n" +
		"  (memory (export \"memory\") 1)\n" +
		"  (func $redevplugin_worker_invoke (export \"redevplugin_worker_invoke\")\n" +
		"    ;; Each call passes request_ptr, request_len, response_ptr, response_len.\n")
	requestOffset := uint32(0)
	responseOffset := uint32(4096)
	for _, call := range scaffoldBrokerHostcalls() {
		fmt.Fprintf(&b, "    i32.const %d\n", requestOffset)
		fmt.Fprintf(&b, "    i32.const %d\n", len(call.Request))
		fmt.Fprintf(&b, "    i32.const %d\n", responseOffset)
		fmt.Fprintf(&b, "    i32.const %d\n", call.OutLen)
		fmt.Fprintf(&b, "    call $%s_%s\n", strings.ReplaceAll(call.Module, "redevplugin.", ""), call.Name)
		b.WriteString("    drop\n")
		requestOffset += uint32(len(call.Request)) + 16
		responseOffset += call.OutLen
	}
	b.WriteString("  )\n")
	requestOffset = 0
	for _, call := range scaffoldBrokerHostcalls() {
		fmt.Fprintf(&b, "  (data (i32.const %d) %q)\n", requestOffset, string(call.Request))
		requestOffset += uint32(len(call.Request)) + 16
	}
	b.WriteString(")\n")
	return b.String()
}

func scaffoldWorkerABIJSON() string {
	return "{\n" +
		"  \"abi_version\": \"redevplugin-wasm-worker-v1\",\n" +
		"  \"exports\": [\"redevplugin_worker_invoke\"],\n" +
		"  \"imports\": [\"redevplugin.log\", \"redevplugin.storage\", \"redevplugin.network\", \"redevplugin.operation\", \"redevplugin.clock\"]\n" +
		"}\n"
}

func minimalWorkerWASM() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x1d, 0x01, 0x19,
		0x72, 0x65, 0x64, 0x65, 0x76, 0x70, 0x6c, 0x75,
		0x67, 0x69, 0x6e, 0x5f, 0x77, 0x6f, 0x72, 0x6b,
		0x65, 0x72, 0x5f, 0x69, 0x6e, 0x76, 0x6f, 0x6b,
		0x65,
		0x00, 0x00,
		0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
	}
}

func scaffoldBrokerWorkerWASM() []byte {
	return importedMemoryHostcallSequenceWorkerWASM("redevplugin_worker_invoke", scaffoldBrokerHostcalls())
}

func scaffoldBrokerHostcalls() []memoryHostcallSpec {
	return []memoryHostcallSpec{
		{
			Module:  "redevplugin.storage",
			Name:    "files",
			Request: mustJSONBytes(map[string]any{"store_id": "workspace", "operation": "write", "path": "notes/generated-broker-demo.txt", "data_base64": "Z2VuZXJhdGVkIHBsdWdpbiBzdG9yYWdlIHNhbXBsZQ==", "max_bytes": 0, "max_entries": 0, "recursive": false}),
			OutLen:  4096,
		},
		{
			Module:  "redevplugin.storage",
			Name:    "kv",
			Request: mustJSONBytes(map[string]any{"store_id": "settings", "operation": "put", "key": "demo/last_broker_run", "value_base64": "Z2VuZXJhdGVkIGJhY2tlbmQga3Ygc2FtcGxl", "prefix": "", "max_bytes": 0, "max_entries": 0}),
			OutLen:  4096,
		},
		{
			Module:  "redevplugin.storage",
			Name:    "sqlite",
			Request: mustJSONBytes(map[string]any{"store_id": "db", "operation": "exec", "database": "plugin.sqlite", "sql": "CREATE TABLE IF NOT EXISTS worker_runs (id INTEGER PRIMARY KEY, note TEXT NOT NULL)", "args": []any{}, "max_rows": 0, "max_response_bytes": 0, "timeout_ms": 1000}),
			OutLen:  4096,
		},
		{
			Module:  "redevplugin.network",
			Name:    "http_request",
			Request: mustJSONBytes(map[string]any{"connector_id": "api", "transport": "http", "destination": "https://api.example.com", "operation": "http", "method": "POST", "path": "/v1/worker", "headers": map[string]any{"Content-Type": []string{"text/plain"}}, "body_base64": "Z2VuZXJhdGVkIGJyb2tlcmVkIGh0dHAgcmVxdWVzdA==", "max_request_bytes": 1024, "max_response_bytes": 4096, "timeout_ms": 1000}),
			OutLen:  8192,
		},
		{
			Module:  "redevplugin.network",
			Name:    "http_request",
			Request: mustJSONBytes(map[string]any{"connector_id": "stream", "transport": "websocket", "destination": "wss://stream.example.com", "operation": "websocket_round_trip", "message_type": "text", "payload_base64": "Z2VuZXJhdGVkIHdlYnNvY2tldCByb3VuZCB0cmlw", "max_request_bytes": 1024, "max_response_bytes": 4096, "timeout_ms": 1000}),
			OutLen:  8192,
		},
		{
			Module:  "redevplugin.network",
			Name:    "http_request",
			Request: mustJSONBytes(map[string]any{"connector_id": "mysql", "transport": "tcp", "destination": "db.example.com:3306", "operation": "tcp_round_trip", "payload_base64": "Z2VuZXJhdGVkIHRjcCByb3VuZCB0cmlw", "max_request_bytes": 1024, "max_response_bytes": 4096, "timeout_ms": 1000}),
			OutLen:  8192,
		},
		{
			Module:  "redevplugin.network",
			Name:    "http_request",
			Request: mustJSONBytes(map[string]any{"connector_id": "metrics", "transport": "udp", "destination": "metrics.example.com:8125", "operation": "udp_round_trip", "payload_base64": "Z2VuZXJhdGVkIHVkcCByb3VuZCB0cmlw", "max_request_bytes": 1024, "max_response_bytes": 4096, "timeout_ms": 1000}),
			OutLen:  8192,
		},
	}
}

type memoryHostcallSpec struct {
	Module  string
	Name    string
	Request []byte
	OutLen  uint32
}

func mustJSONBytes(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func importedMemoryHostcallSequenceWorkerWASM(exportName string, calls []memoryHostcallSpec) []byte {
	exportNameBytes := []byte(exportName)
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x0c, 0x02,
		0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
		0x60, 0x00, 0x00,
		0x02,
	}
	importPayload := []byte{byte(len(calls))}
	for _, call := range calls {
		importModule := []byte(call.Module)
		importName := []byte(call.Name)
		importPayload = append(importPayload, byte(len(importModule)))
		importPayload = append(importPayload, importModule...)
		importPayload = append(importPayload, byte(len(importName)))
		importPayload = append(importPayload, importName...)
		importPayload = append(importPayload, 0x00, 0x00)
	}
	module = appendLEBUint32(module, uint32(len(importPayload)))
	module = append(module, importPayload...)
	module = append(module,
		0x03, 0x02, 0x01, 0x01,
		0x05, 0x03, 0x01, 0x00, 0x01,
		0x07,
	)
	exportPayload := []byte{0x02, 0x06}
	exportPayload = append(exportPayload, []byte("memory")...)
	exportPayload = append(exportPayload, 0x02, 0x00, byte(len(exportNameBytes)))
	exportPayload = append(exportPayload, exportNameBytes...)
	exportPayload = append(exportPayload, 0x00, byte(len(calls)))
	module = appendLEBUint32(module, uint32(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module, 0x0a)
	codePayload := []byte{0x01}
	body := []byte{0x00}
	dataPayload := []byte{byte(len(calls))}
	requestOffset := uint32(0)
	responseOffset := uint32(4096)
	for index, call := range calls {
		body = append(body, 0x41)
		body = appendLEBInt32(body, int32(requestOffset))
		body = append(body, 0x41)
		body = appendLEBInt32(body, int32(len(call.Request)))
		body = append(body, 0x41)
		body = appendLEBInt32(body, int32(responseOffset))
		body = append(body, 0x41)
		body = appendLEBInt32(body, int32(call.OutLen))
		body = append(body, 0x10, byte(index), 0x1a)

		dataPayload = append(dataPayload, 0x00, 0x41)
		dataPayload = appendLEBInt32(dataPayload, int32(requestOffset))
		dataPayload = append(dataPayload, 0x0b)
		dataPayload = appendLEBUint32(dataPayload, uint32(len(call.Request)))
		dataPayload = append(dataPayload, call.Request...)

		requestOffset += uint32(len(call.Request)) + 16
		responseOffset += call.OutLen
	}
	body = append(body, 0x0b)
	codePayload = appendLEBUint32(codePayload, uint32(len(body)))
	codePayload = append(codePayload, body...)
	module = appendLEBUint32(module, uint32(len(codePayload)))
	module = append(module, codePayload...)
	module = append(module, 0x0b)
	module = appendLEBUint32(module, uint32(len(dataPayload)))
	module = append(module, dataPayload...)
	return module
}

func importedNoArgHostcallWorkerWASM(exportName string, imports [][2]string) []byte {
	exportNameBytes := []byte(exportName)
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x07, 0x02,
		0x60, 0x00, 0x00,
		0x60, 0x00, 0x00,
		0x02,
	}
	importPayload := []byte{byte(len(imports))}
	for _, item := range imports {
		importModule := []byte(item[0])
		importName := []byte(item[1])
		importPayload = append(importPayload, byte(len(importModule)))
		importPayload = append(importPayload, importModule...)
		importPayload = append(importPayload, byte(len(importName)))
		importPayload = append(importPayload, importName...)
		importPayload = append(importPayload, 0x00, 0x00)
	}
	module = appendLEBUint32(module, uint32(len(importPayload)))
	module = append(module, importPayload...)
	module = append(module, 0x03, 0x02, 0x01, 0x01, 0x07)
	exportPayload := []byte{0x01, byte(len(exportNameBytes))}
	exportPayload = append(exportPayload, exportNameBytes...)
	exportPayload = append(exportPayload, 0x00, byte(len(imports)))
	module = appendLEBUint32(module, uint32(len(exportPayload)))
	module = append(module, exportPayload...)
	codePayload := []byte{0x01}
	body := []byte{0x00}
	for index := range imports {
		body = append(body, 0x10, byte(index))
	}
	body = append(body, 0x0b)
	codePayload = appendLEBUint32(codePayload, uint32(len(body)))
	codePayload = append(codePayload, body...)
	module = append(module, 0x0a)
	module = appendLEBUint32(module, uint32(len(codePayload)))
	module = append(module, codePayload...)
	return module
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

type staticSessionResolver struct{}

func (staticSessionResolver) ResolveSession(context.Context, string) (sessionctx.Context, error) {
	return sessionctx.Context{}, nil
}

type staticPolicyAdapter struct{}

func (staticPolicyAdapter) EvaluateLocalPolicy(context.Context, sessionctx.Context, host.PluginRef, manifest.MethodSpec) (host.PolicyDecision, error) {
	return host.PolicyAllow, nil
}

func (staticPolicyAdapter) DeveloperModeEnabled(context.Context, sessionctx.Context) (bool, error) {
	return true, nil
}

func (staticPolicyAdapter) LocalGeneratedPluginsEnabled(context.Context, sessionctx.Context) (bool, error) {
	return true, nil
}
