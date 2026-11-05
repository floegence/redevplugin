package authoring

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed scaffold_assets/web-app.ts
var scaffoldWebAppTS []byte

//go:embed scaffold_assets/web-app.js
var scaffoldWebAppJS []byte

//go:embed scaffold_assets/data-app.ts
var scaffoldDataAppTS []byte

//go:embed scaffold_assets/data-app.js
var scaffoldDataAppJS []byte

func configureDataTemplate(files map[string][]byte, displayName string) {
	files["ui/src/app.ts"] = scaffoldSource(scaffoldDataAppTS, displayName)
	files["dist/ui/assets/app.js"] = scaffoldSource(scaffoldDataAppJS, displayName)
	files["README.md"] = append(files["README.md"], []byte("\nThis data application uses a user-scoped private KV store directly from its Surface.\nSaving uses content ETags; a conflict keeps the unsaved editor text. An unknown\nwrite result is never retried automatically. Reload explicitly before saving again.\nContent ETags identify bytes, not a monotonic revision: equal content has an equal ETag.\n")...)
}

func configureWebTemplate(files map[string][]byte, displayName, platformVersion string) {
	for _, name := range []string{"rust-toolchain.toml", "worker/Cargo.toml", "worker/src/lib.rs", "dist/workers/backend.wasm"} {
		delete(files, name)
	}
	files["ui/src/app.ts"] = scaffoldSource(scaffoldWebAppTS, displayName)
	files["dist/ui/assets/app.js"] = scaffoldSource(scaffoldWebAppJS, displayName)
	var pkg map[string]any
	if err := json.Unmarshal(files["package.json"], &pkg); err != nil {
		panic(err)
	}
	pkg["scripts"].(map[string]any)["test"] = "node --test tests/*.test.mjs"
	files["package.json"], _ = json.MarshalIndent(pkg, "", "  ")
	files["redevplugin.project.json"] = []byte(`{
  "schema_version": "redevplugin.project.v1",
  "output": "dist",
  "build": ["npm", "run", "build"],
  "test": ["npm", "test"],
  "watch": ["manifest.json", "ui", "scripts", "tests", "package.json"],
  "typecheck": ["npm", "run", "typecheck"],
  "bindings": "generated"
}
`)
	files["scripts/build.mjs"] = []byte(`import { copyFile, mkdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const built = spawnSync(process.platform === "win32" ? "npm.cmd" : "npm", ["run", "build:ui"], { cwd: root, stdio: "inherit" });
if (built.status !== 0) process.exit(built.status ?? 1);
await mkdir(resolve(root, "dist/ui/assets"), { recursive: true });
await copyFile(resolve(root, "manifest.json"), resolve(root, "dist/manifest.json"));
await copyFile(resolve(root, "ui/index.html"), resolve(root, "dist/ui/index.html"));
`)
	files["README.md"] = []byte(fmt.Sprintf(`# %s

A regular Web application with no default host action. No Rust toolchain or
Worker is needed to build or package it. Dependencies use ReDevPlugin %s.

    npm install
    redevplugin doctor .
    redevplugin check .
    redevplugin test .
    redevplugin package dist app.redevplugin

Edit ui/src/app.ts and use your preferred browser framework. Internal functions
and state stay ordinary application code. This basic Web template declares no
host actions; add a method and intent only when another trusted surface must
invoke the application.

    redevplugin dev . --state ../development-state --manual

The preview uses a real isolated Host and authenticated sandbox. Add an explicit
verified runtime when adding a Worker. Build and test commands only run against
this explicitly selected source project, never during package installation.
`, displayName, platformVersion))
}

//go:embed scaffold_assets/monitor-app.ts
var scaffoldMonitorTS []byte

//go:embed scaffold_assets/monitor-app.js
var scaffoldMonitorJS []byte

//go:embed scaffold_assets/files-app.ts
var scaffoldFilesTS []byte

//go:embed scaffold_assets/files-app.js
var scaffoldFilesJS []byte

func configureResourceTemplate(files map[string][]byte, displayName, template string) {
	source, bundle := scaffoldMonitorTS, scaffoldMonitorJS
	if template == "files" {
		source, bundle = scaffoldFilesTS, scaffoldFilesJS
	}
	files["ui/src/app.ts"] = scaffoldSource(source, displayName)
	files["dist/ui/assets/app.js"] = scaffoldSource(bundle, displayName)
	if template == "monitor" {
		files["README.md"] = append(files["README.md"], []byte("\nConfigure the events WebSocket connection in your host and grant network.client.\nEach incoming text or binary message is one complete application snapshot.\nReconnect explicitly after closure or overflow; no commands are replayed.\nUse Resources and connections in the CLI preview to review and approve the destination.\n")...)
	}
	if template == "files" {
		files["README.md"] = append(files["README.md"], []byte("\nSelect browser files for a sequential, cancellable private import. Each completed\nfile commits atomically; prior completed files remain after cancellation. The UI\nkeeps explicit per-file outcomes and verifies imported byte counts with bounded reads.\nThese page-owned tasks stop when the page closes. Use a declared Worker operation\nand the generated action client for jobs that must outlive the page.\n")...)
	}
}
