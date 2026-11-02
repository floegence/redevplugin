package main

import (
	"encoding/json"
	"strings"
)

func configureAuthorProject(files map[string][]byte, template string) {
	var config map[string]any
	if err := json.Unmarshal(files["redevplugin.project.json"], &config); err != nil {
		panic(err)
	}
	config["typecheck"] = []string{"npm", "run", "typecheck"}
	config["bindings"] = "generated"
	var npm map[string]any
	if err := json.Unmarshal(files["package.json"], &npm); err != nil {
		panic(err)
	}
	npm["engines"] = map[string]string{"node": ">=26.0.0 <27"}
	npm["scripts"].(map[string]any)["check"] = "redevplugin check ."
	files["package.json"], _ = json.MarshalIndent(npm, "", "  ")
	if template == "worker" {
		config["prepare"] = []string{"node", "scripts/prepare.mjs"}
		files["scripts/prepare.mjs"] = []byte(`import { access } from "node:fs/promises";
import { spawnSync } from "node:child_process";
try { await access("worker/Cargo.lock"); }
catch (error) {
  if (error.code !== "ENOENT") throw error;
  const result = spawnSync("cargo", ["generate-lockfile", "--manifest-path", "worker/Cargo.toml"], {stdio: "inherit"});
  if (result.status !== 0) process.exit(result.status ?? 1);
}
`)
	}
	files["redevplugin.project.json"], _ = json.MarshalIndent(config, "", "  ")
	files[".gitignore"] = []byte(`node_modules/
dist/
worker/target/
`)
	if template == "worker" {
		return
	}
	// Test ordinary business logic without treating mocks as authorization evidence.
	files["ui/src/application.ts"] = []byte(`export function applicationSnapshot(message: string) {
  return { message };
}
`)
	source := string(files["ui/src/app.ts"])
	source = `import { applicationSnapshot } from "./application.js";
` + source
	source = strings.ReplaceAll(source, "return { message: input.value };", "return applicationSnapshot(input.value);")
	source = strings.ReplaceAll(source, "({ message: snapshot })", "applicationSnapshot(snapshot)")
	source = strings.ReplaceAll(source, "({ message: summary })", "applicationSnapshot(summary)")
	source = strings.ReplaceAll(source, "{ message: editor.value, revision }", "{ ...applicationSnapshot(editor.value), revision }")
	files["ui/src/app.ts"] = []byte(source)
	files["tests/application.test.mjs"] = []byte(`import assert from "node:assert/strict";
import test from "node:test";
import { applicationSnapshot } from "../ui/src/application.ts";
test("public snapshots preserve exact application text", () => {
  assert.deepEqual(applicationSnapshot("  draft  "), { message: "  draft  " });
  assert.deepEqual(applicationSnapshot(""), { message: "" });
  assert.notEqual(applicationSnapshot("draft"), applicationSnapshot("draft"));
});
`)
}
