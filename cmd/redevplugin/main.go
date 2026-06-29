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
		return writeJSON(version.CurrentMatrix())
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

func validate(ctx context.Context, filename string) error {
	if strings.HasSuffix(filename, ".redeven-plugin") || strings.HasSuffix(filename, ".zip") {
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
	pluginID = strings.TrimSpace(pluginID)
	displayName = strings.TrimSpace(displayName)
	outDir = strings.TrimSpace(outDir)
	if pluginID == "" {
		return fmt.Errorf("plugin_id is required")
	}
	if displayName == "" {
		return fmt.Errorf("display_name is required")
	}
	if outDir == "" {
		return fmt.Errorf("output directory is required")
	}
	manifestDoc := manifest.Manifest{
		SchemaVersion: "redeven.plugin.manifest.v1",
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
			ABI:              "redeven-wasm-worker-v1",
			Mode:             manifest.WorkerModeJob,
			Scope:            "user",
			MemoryLimitBytes: 16 << 20,
		}},
		Methods: []manifest.MethodSpec{{
			Method:         "worker.echo",
			Effect:         manifest.MethodEffectRead,
			Execution:      manifest.MethodExecutionSync,
			Route:          manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "backend", Export: "redeven_worker_invoke"},
			RequestSchema:  map[string]any{"type": "object", "additionalProperties": true},
			ResponseSchema: map[string]any{"type": "object"},
		}},
	}
	rawManifest, err := json.MarshalIndent(manifestDoc, "", "  ")
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"manifest.json":        append(rawManifest, '\n'),
		"ui/index.html":        []byte(scaffoldIndexHTML(displayName)),
		"ui/assets/app.js":     []byte(scaffoldAppJS(displayName)),
		"ui/assets/styles.css": []byte(scaffoldStylesCSS()),
		"workers/backend.wat":  []byte(scaffoldWorkerWAT()),
		"workers/backend.wasm": minimalWorkerWASM(),
		"workers/abi.json":     []byte(scaffoldWorkerABIJSON()),
	}
	if _, err := os.Stat(outDir); err == nil {
		entries, err := os.ReadDir(outDir)
		if err != nil {
			return err
		}
		if len(entries) > 0 {
			return fmt.Errorf("output directory %q is not empty", outDir)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	created := make([]string, 0, len(files))
	for entryPath, content := range files {
		filename := filepath.Join(outDir, filepath.FromSlash(entryPath))
		if err := writeBytesFile(filename, content, 0o644); err != nil {
			return err
		}
		created = append(created, entryPath)
	}
	sortStrings(created)
	return writeJSON(scaffoldSummary{
		OK:          true,
		Kind:        "plugin_scaffold",
		PluginID:    pluginID,
		Version:     manifestDoc.Plugin.Version,
		OutputDir:   outDir,
		Files:       created,
		VersionInfo: version.CurrentMatrix(),
	})
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
	return fmt.Errorf("usage: redevplugin validate <manifest.json|package.redeven-plugin> | redevplugin scaffold <plugin-id> <display-name> <out-dir> | redevplugin package <dir> <out.redeven-plugin> | redevplugin keygen <key-id> <private.json> <public.json> | redevplugin sign <package.redeven-plugin> <private.json> <out.redeven-plugin> | redevplugin install-local <package> | redevplugin install-verified <signed-package> <public.json> | redevplugin enable <package> | redevplugin disable <package> | redevplugin uninstall <package> | redevplugin version")
}

func lifecycleHarness(ctx context.Context, action string, packageFile string) error {
	data, err := os.ReadFile(packageFile)
	if err != nil {
		return err
	}
	h, err := host.New(host.Adapters{
		SessionResolver: staticSessionResolver{},
		Policy:          staticPolicyAdapter{},
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

func scaffoldIndexHTML(displayName string) string {
	title := htmlEscape(displayName)
	return "<!doctype html>\n" +
		"<html>\n" +
		"  <head>\n" +
		"    <meta charset=\"utf-8\">\n" +
		"    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
		"    <title>" + title + "</title>\n" +
		"    <link rel=\"stylesheet\" href=\"assets/styles.css\">\n" +
		"    <script src=\"assets/app.js\" defer></script>\n" +
		"  </head>\n" +
		"  <body>\n" +
		"    <main id=\"app\" data-plugin-title=\"" + title + "\">\n" +
		"      <section class=\"surface\">\n" +
		"        <p class=\"eyebrow\">Plugin surface</p>\n" +
		"        <h1>" + title + "</h1>\n" +
		"        <p class=\"status\" id=\"status\">Ready</p>\n" +
		"        <button id=\"invoke-worker\" type=\"button\">Invoke backend</button>\n" +
		"      </section>\n" +
		"    </main>\n" +
		"  </body>\n" +
		"</html>\n"
}

func scaffoldAppJS(displayName string) string {
	message, _ := json.Marshal(displayName + " loaded")
	return "const status = document.getElementById('status');\n" +
		"const invokeButton = document.getElementById('invoke-worker');\n" +
		"if (status) {\n" +
		"  status.textContent = " + string(message) + ";\n" +
		"}\n" +
		"if (invokeButton) {\n" +
		"  invokeButton.addEventListener('click', () => {\n" +
		"    if (status) {\n" +
		"      status.textContent = 'Backend method declared as worker.echo';\n" +
		"    }\n" +
		"  });\n" +
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
		"  gap: 8px;\n" +
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
		"  ;; generated worker that implements redeven-wasm-worker-v1.\n" +
		"  (func $redeven_worker_invoke (export \"redeven_worker_invoke\")\n" +
		"    nop)\n" +
		")\n"
}

func scaffoldWorkerABIJSON() string {
	return "{\n" +
		"  \"abi_version\": \"redeven-wasm-worker-v1\",\n" +
		"  \"exports\": [\"redeven_worker_invoke\"],\n" +
		"  \"imports\": [\"redeven.log\", \"redeven.storage\", \"redeven.network\", \"redeven.operation\", \"redeven.clock\"]\n" +
		"}\n"
}

func minimalWorkerWASM() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x18, 0x01, 0x15,
		0x72, 0x65, 0x64, 0x65, 0x76, 0x65, 0x6e, 0x5f,
		0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x5f, 0x69,
		0x6e, 0x76, 0x6f, 0x6b, 0x65,
		0x00, 0x00,
		0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
	}
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
