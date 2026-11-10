package authoring

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/authorapi"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

type TemplateResult struct {
	OK        bool     `json:"ok"`
	Kind      string   `json:"kind"`
	PluginID  string   `json:"plugin_id"`
	Version   string   `json:"version"`
	OutputDir string   `json:"output_dir"`
	Files     []string `json:"files"`
}

type scaffoldManifestV9 struct {
	NetworkAccess *manifest.NetworkAccessSpec   `json:"network_access,omitempty"`
	Storage       *manifest.StorageSpec         `json:"storage,omitempty"`
	SchemaVersion string                        `json:"schema_version"`
	Publisher     manifest.Publisher            `json:"publisher"`
	Plugin        scaffoldPluginV9              `json:"plugin"`
	API           manifest.PublicAPIRequirement `json:"api"`
	Permissions   []manifest.PermissionID       `json:"permissions"`
	Presentation  scaffoldPresentationV9        `json:"presentation"`
	Surfaces      []manifest.SurfaceSpec        `json:"surfaces"`
	Workers       []scaffoldWorkerV9            `json:"workers"`
	Methods       []scaffoldMethodV9            `json:"methods"`
	Intents       []manifest.IntentSpec         `json:"intents"`
}

type scaffoldPluginV9 struct {
	PluginID    string `json:"plugin_id"`
	DisplayName string `json:"display_name"`
	Version     string `json:"version"`
}

type scaffoldPresentationV9 struct {
	Category manifest.PluginCategory `json:"category"`
	Locales  map[string]string       `json:"locales"`
}

type scaffoldWorkerV9 struct {
	WorkerID         string              `json:"worker_id"`
	Artifact         string              `json:"artifact"`
	Mode             manifest.WorkerMode `json:"mode"`
	Scope            string              `json:"scope"`
	MemoryLimitBytes int64               `json:"memory_limit_bytes"`
}

type scaffoldMethodV9 struct {
	Method         string                       `json:"method"`
	Effect         manifest.MethodEffect        `json:"effect"`
	Execution      manifest.MethodExecutionMode `json:"execution"`
	RequestSchema  map[string]any               `json:"request_schema"`
	ResponseSchema map[string]any               `json:"response_schema"`
	Route          manifest.MethodRouteSpec     `json:"route"`
}

//go:embed scaffold_assets/app.js
var scaffoldAppJS []byte

//go:embed scaffold_assets/app.ts
var scaffoldAppTS []byte

//go:embed scaffold_assets/styles.css
var scaffoldAppCSS []byte

//go:embed scaffold_assets/styles-source.css
var scaffoldSourceCSS []byte

//go:embed scaffold_assets/backend.wasm
var scaffoldWorkerWASM []byte

//go:embed scaffold_assets/worker-lib.rs
var scaffoldWorkerRust []byte

func Init(pluginID string, displayName string, outDir string, template string) (TemplateResult, error) {
	pluginID = strings.TrimSpace(pluginID)
	displayName = strings.TrimSpace(displayName)
	outDir = strings.TrimSpace(outDir)
	if outDir == "" {
		return TemplateResult{}, fmt.Errorf("output directory is required")
	}
	files, err := templateFiles(pluginID, displayName, template)
	if err != nil {
		return TemplateResult{}, err
	}
	return writeTemplateFiles(pluginID, outDir, files)
}

// templateFiles validates the complete author input before any filesystem or
// durable initialization claim is created.
func templateFiles(pluginID, displayName, template string) (map[string][]byte, error) {
	if template != "web" && template != "data" && template != "worker" && template != "monitor" && template != "files" {
		return nil, fmt.Errorf("unknown template %q; choose web, data, worker, monitor or files", template)
	}
	pluginID = strings.TrimSpace(pluginID)
	displayName = strings.TrimSpace(displayName)
	if err := pluginidentity.ValidateSlug(pluginID); err != nil {
		return nil, err
	}
	if displayName == "" {
		return nil, fmt.Errorf("display_name is required")
	}
	platformVersion := version.CurrentPlatformVersion()
	manifestDoc := scaffoldManifestV9{
		SchemaVersion: manifest.SchemaVersionV9,
		Publisher: manifest.Publisher{
			PublisherID: "local.generated",
			DisplayName: "Local Generated",
		},
		Plugin:       scaffoldPluginV9{PluginID: pluginID, DisplayName: displayName, Version: "0.1.0"},
		API:          manifest.PublicAPIRequirement{Major: 1, OptionalFeatures: []manifest.FeatureID{manifest.FeatureIOStream}},
		Permissions:  []manifest.PermissionID{},
		Presentation: scaffoldPresentationV9{Category: "other", Locales: map[string]string{"default": "en-US"}},
		Surfaces: []manifest.SurfaceSpec{{
			SurfaceID: pluginID + ".view",
			Kind:      manifest.SurfaceView,
			Intent:    manifest.SurfaceIntentPrimary,
			Label:     displayName,
			Entry:     "ui/index.html", Web: manifest.SurfaceWebSpec{Root: "ui"},
		}},
		Workers: []scaffoldWorkerV9{{WorkerID: "backend", Artifact: "workers/backend.wasm", Mode: manifest.WorkerModeJob, Scope: "user", MemoryLimitBytes: 16 << 20}},
		Methods: []scaffoldMethodV9{{
			Method: "worker.echo",
			Effect: manifest.MethodEffectRead, Execution: manifest.MethodExecutionSync,
			Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "backend"},
			RequestSchema: closedRequiredMethodObjectSchema(map[string]any{
				"message": map[string]any{"type": "string"},
			}, []string{"message"}),
			ResponseSchema: scaffoldEchoResponseSchema(),
		}},
	}
	manifestDoc.Methods = append(manifestDoc.Methods, scaffoldMethodV9{
		Method: "application.read", Effect: manifest.MethodEffectRead, Execution: manifest.MethodExecutionSync,
		Route:          manifest.MethodRouteSpec{Kind: manifest.MethodRouteSurface, SurfaceID: pluginID + ".view"},
		RequestSchema:  map[string]any{"type": "object", "additionalProperties": false},
		ResponseSchema: closedRequiredMethodObjectSchema(map[string]any{"message": map[string]any{"type": "string"}}, []string{"message"}),
	})
	manifestDoc.Intents = []manifest.IntentSpec{{IntentID: "application.read", Method: "application.read"}}
	if template != "worker" {
		manifestDoc.Workers = []scaffoldWorkerV9{}
		manifestDoc.Methods = manifestDoc.Methods[1:]
		manifestDoc.API.OptionalFeatures = nil
	}

	if template == "web" {
		manifestDoc.Methods = []scaffoldMethodV9{}
		manifestDoc.Intents = []manifest.IntentSpec{}
	}

	if template == "data" {
		manifestDoc.API.RequiredFeatures = []manifest.FeatureID{manifest.FeatureSurfaceResources}
		manifestDoc.Storage = &manifest.StorageSpec{Stores: []manifest.StoreSpec{{StoreID: "documents", Kind: "kv", Scope: "user", QuotaBytes: 8 << 20, SchemaVersion: 1}}}
		manifestDoc.Surfaces[0].Web.Storage = []manifest.StorageBrokerAccessSpec{{StoreID: "documents", Operations: []string{"get", "put", "list"}}}
		manifestDoc.Methods[0].ResponseSchema = closedRequiredMethodObjectSchema(map[string]any{"message": map[string]any{"type": "string"}, "revision": map[string]any{"type": "integer", "minimum": 0}}, []string{"message", "revision"})
		manifestDoc.Methods = append(manifestDoc.Methods, scaffoldMethodV9{Method: "document.replace", Effect: manifest.MethodEffectWrite, Execution: manifest.MethodExecutionSync, Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteSurface, SurfaceID: pluginID + ".view"}, RequestSchema: closedRequiredMethodObjectSchema(map[string]any{"message": map[string]any{"type": "string", "maxLength": 24000}, "expected_revision": map[string]any{"type": "integer", "minimum": 0}}, []string{"message", "expected_revision"}), ResponseSchema: closedRequiredMethodObjectSchema(map[string]any{"applied": map[string]any{"type": "boolean"}, "revision": map[string]any{"type": "integer", "minimum": 0}}, []string{"applied", "revision"})})
		manifestDoc.Intents = append(manifestDoc.Intents, manifest.IntentSpec{IntentID: "document.replace", Method: "document.replace"})
	}
	if template == "monitor" {
		manifestDoc.API.RequiredFeatures = []manifest.FeatureID{manifest.FeatureSurfaceResources, manifest.FeatureNetWebSocket}
		manifestDoc.Permissions = []manifest.PermissionID{manifest.PermissionNetworkClient}
		manifestDoc.NetworkAccess = &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{{ConnectorID: "events", Transport: "websocket", Scope: "user", Configurable: true}}}
		manifestDoc.Surfaces[0].Web.Network = []manifest.NetworkBrokerAccessSpec{{ConnectorID: "events", Transport: "websocket", Operations: []string{"websocket"}}}
	}
	if template == "files" {
		manifestDoc.API.RequiredFeatures = []manifest.FeatureID{manifest.FeatureSurfaceResources}
		manifestDoc.Storage = &manifest.StorageSpec{Stores: []manifest.StoreSpec{{StoreID: "imports", Kind: "files", Scope: "user", QuotaBytes: 128 << 20, SchemaVersion: 1}}}
		manifestDoc.Surfaces[0].Web.Storage = []manifest.StorageBrokerAccessSpec{{StoreID: "imports", Operations: []string{"read", "write", "list", "delete"}}}
	}
	rawManifest, err := json.MarshalIndent(manifestDoc, "", "  ")
	if err != nil {
		return nil, err
	}
	manifestBytes := append(append([]byte(nil), rawManifest...), '\n')
	sourceBytes, err := manifest.AuthorSource(manifestBytes, pluginID)
	if err != nil {
		return nil, err
	}
	var formattedSource bytes.Buffer
	if err := json.Indent(&formattedSource, sourceBytes, "", "  "); err != nil {
		return nil, err
	}
	sourceBytes = formattedSource.Bytes()
	files := map[string][]byte{
		"README.md":                 []byte(scaffoldReadme(displayName, platformVersion)),
		"redevplugin.project.json":  []byte(scaffoldProjectConfig()),
		"manifest.json":             append(sourceBytes, '\n'),
		"package.json":              []byte(scaffoldPackageJSON(platformVersion)),
		"tsconfig.json":             []byte(scaffoldTSConfig()),
		"scripts/build.mjs":         []byte(scaffoldBuildScript()),
		"ui/index.html":             []byte(scaffoldIndexHTML(pluginID, displayName)),
		"ui/styles.css":             []byte(scaffoldStylesCSS()),
		"ui/src/app.ts":             scaffoldSource(scaffoldAppTS, displayName),
		"rust-toolchain.toml":       []byte("[toolchain]\nchannel = \"1.98.0\"\ntargets = [\"wasm32-unknown-unknown\"]\nprofile = \"minimal\"\n"),
		"worker/Cargo.toml":         []byte(scaffoldCargoTOML(platformVersion)),
		"worker/src/lib.rs":         append([]byte(nil), scaffoldWorkerRust...),
		"dist/manifest.json":        append([]byte(nil), manifestBytes...),
		"dist/ui/index.html":        []byte(scaffoldIndexHTML(pluginID, displayName)),
		"dist/ui/assets/app.js":     scaffoldSource(scaffoldAppJS, displayName),
		"dist/ui/assets/styles.css": append([]byte(nil), scaffoldAppCSS...),
		"dist/workers/backend.wasm": append([]byte(nil), scaffoldWorkerWASM...),
	}
	if _, err := manifest.Decode(bytes.NewReader(manifestBytes)); err != nil {
		return nil, err
	}
	if template != "worker" {
		configureWebTemplate(files, displayName, platformVersion, template)
	}
	if template == "data" {
		configureDataTemplate(files, displayName)
	}
	if template == "monitor" || template == "files" {
		configureResourceTemplate(files, displayName, template)
	}
	configureAuthorProject(files, template)
	bindings, err := authorapi.Generate(manifestBytes)
	if err != nil {
		return nil, err
	}
	for name, data := range bindings {
		files["generated/"+name] = data
	}
	if template != "worker" {
		source := string(files["ui/src/app.ts"])
		source = `import { registerAction } from "../../generated/actions.js";
` + strings.ReplaceAll(strings.ReplaceAll(source, `bridge.registerMethod("application.read",`, `registerAction(bridge, "application.read",`), `bridge.registerMethod("document.replace",`, `registerAction(bridge, "document.replace",`)
		files["ui/src/app.ts"] = []byte(source)
	}
	return files, nil
}

func writeTemplateFiles(pluginID, outDir string, files map[string][]byte) (TemplateResult, error) {
	if _, err := os.Stat(outDir); err == nil {
		entries, err := os.ReadDir(outDir)
		if err != nil {
			return TemplateResult{}, err
		}
		if len(entries) > 0 {
			return TemplateResult{}, fmt.Errorf("output directory %q is not empty", outDir)
		}
	} else if !os.IsNotExist(err) {
		return TemplateResult{}, err
	}
	created := make([]string, 0, len(files))
	for entryPath, content := range files {
		filename := filepath.Join(outDir, filepath.FromSlash(entryPath))
		if err := writeTemplateFile(filename, content); err != nil {
			return TemplateResult{}, err
		}
		created = append(created, entryPath)
	}
	sort.Strings(created)
	return TemplateResult{
		OK:        true,
		Kind:      "plugin_scaffold",
		PluginID:  pluginID,
		Version:   "0.1.0",
		OutputDir: outDir,
		Files:     created,
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
		"message":   map[string]any{"type": "string"},
	}, []string{"backend", "transport", "method", "worker_id", "message"})
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
    "check": "npm run typecheck && npm run build",
    "build": "redevplugin build .",
    "build:release": "redevplugin build . --release",
    "build:ui": "esbuild ui/src/app.ts --bundle --format=esm --platform=browser --target=es2022 --outfile=dist/ui/assets/app.js && esbuild ui/styles.css --bundle --outfile=dist/ui/assets/styles.css",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "test": "cargo test --manifest-path worker/Cargo.toml"
  },
  "dependencies": {
    "@floegence/redevplugin-ui": %q,
    "@floegence/floe-webapp-core": "0.86.65",
    "solid-js": "1.9.17"
  },
  "overrides": {
    "dompurify": "3.4.17",
    "katex": "0.18.2"
  },
  "devDependencies": {
    "esbuild": "0.25.5",
    "typescript": "5.9.3"
  }
}
`, platformVersion)
}

func scaffoldTSConfig() string {
	return `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true,
    "lib": ["ES2022", "DOM", "WebWorker"]
  },
  "include": ["ui/src/**/*.ts", "generated/**/*.ts"]
}
`
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
redevplugin-worker-sdk = "=%s"
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
await copyFile(resolve(root, "generated/manifest.json"), resolve(root, "dist/manifest.json"));
await copyFile(resolve(root, "ui/index.html"), resolve(root, "dist/ui/index.html"));
await copyFile(
  resolve(process.env.CARGO_TARGET_DIR || resolve(root, "worker/target"), "wasm32-unknown-unknown/release/redevplugin_generated_worker.wasm"),
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

## Develop and test

    redevplugin dev . --runtime /path/to/verified-runtime --runtime-sha256 <verified-build-sha256>
    redevplugin test .

The preview uses an isolated temporary Host, a random loopback port, the real
WASM runtime, and explicit permission controls. It watches declared source
inputs, retains the last preview after build errors, and creates fresh surface
authority after a successful update. Ctrl-C removes its temporary state.
The executable digest must come from independently verified build evidence;
hashing an arbitrary executable does not establish trust.

The test command reports business/package checks separately from real runtime
execution. To exercise the generated worker with the real runtime:

    redevplugin test . --runtime /path/to/verified-runtime --runtime-sha256 <verified-build-sha256> --surface <slug>.view --method worker.echo --params '{"message":"hello"}'

Build/test argv and watched inputs live in redevplugin.project.json. These
commands run only for explicitly selected local source; installed packages do
not execute them. Install source dependencies before starting the preview.

## Build

Requirements: Node.js 26, npm, Rust, and the wasm32-unknown-unknown target.

    npm install
    rustup target add wasm32-unknown-unknown
    npm run check

The source dependencies are pinned to ReDevPlugin %s. After rebuilding, validate
and package the plugin from this directory:

    redevplugin validate dist/manifest.json
    redevplugin package dist %s.redevplugin

The application.read intent reads the current native input through an awaited
bridge.registerMethod handler. A trusted host invokes it against the exact open
surface; it cannot run when the page is closed. Add document revisions and use
your existing undo transaction when exposing application write operations.

Set presentation.category in manifest.json to development, infrastructure,
utilities, data, collaboration, productivity, or other. Omission means other;
unknown values are rejected. Categories describe the plugin and grant no permissions.

Edit ui/src/app.ts for the surface and worker/src/lib.rs for the WASM backend.
Add permissions to manifest.json only when the plugin
actually needs them.
`, displayName, platformVersion, strings.ReplaceAll(strings.ToLower(displayName), " ", "-"))
}

func scaffoldIndexHTML(_ string, displayName string) string {
	title := htmlEscape(displayName)
	return "<!doctype html>\n" +
		"<html lang=\"en\" class=\"light\" data-floe-surface-style=\"soft-neumorphic\">\n" +
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
		"    <script type=\"module\" src=\"assets/app.js\"></script>\n" +
		"  </body>\n" +
		"</html>\n"
}

func scaffoldStylesCSS() string {
	return string(scaffoldSourceCSS)
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

func scaffoldProjectConfig() string {
	return `{
  "schema_version": "redevplugin.project.v1",
  "output": "dist",
  "build": ["node", "scripts/build.mjs"],
  "test": ["npm", "test"],
  "watch": ["manifest.json", "ui", "worker/src", "worker/Cargo.toml", "scripts", "package.json"]
}
`
}

func writeTemplateFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0644)
}
