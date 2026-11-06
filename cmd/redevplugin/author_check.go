package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/authorapi"
	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/repositoryindex"
)

type authorDiagnostic struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

func runAuthorCheck(ctx context.Context, root string, doctor bool) error {
	diagnostics := []authorDiagnostic{}
	add := func(code, path, message string) {
		diagnostics = append(diagnostics, authorDiagnostic{code, path, message})
	}
	project, err := authorproject.Load(root)
	if err != nil {
		add("PROJECT_INVALID", authorproject.ConfigFile, err.Error())
	}
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	var m manifest.Manifest
	if err != nil {
		add("MANIFEST_UNAVAILABLE", "manifest.json", err.Error())
	} else {
		m, _, err = manifest.DecodeAuthorCanonical(bytes.NewReader(raw))
		if err != nil {
			add("MANIFEST_INVALID", "manifest.json", err.Error())
		}
	}
	if err == nil {
		if failure := checkEnclosingRepositoryIndex(root, m.PluginID()); failure != nil {
			add("REPOSITORY_INDEX_INVALID", repositoryindex.IndexPath, failure.Error())
		}
		directory := "generated"
		if project != nil && project.Config.Bindings != "" {
			directory = project.Config.Bindings
		}
		if _, failure := os.Lstat(filepath.Join(root, directory)); failure == nil || (project != nil && project.Config.Bindings != "") {
			if failure := authorapi.Write(filepath.Join(root, "manifest.json"), filepath.Join(root, directory), true); failure != nil {
				add("BINDING_STALE", directory, failure.Error()+"; run redevplugin generate manifest.json "+directory)
			}
		}
	}
	stages := []authorproject.Stage{}
	tools := map[string]bool{}
	if project != nil {
		tools = checkAuthorReadiness(ctx, project, len(m.Workers) > 0, true, add)
		if !doctor && len(diagnostics) == 0 {
			result, failure := project.Build(ctx, authorproject.PipelineOptions{Test: true})
			stages = result.Stages
			if failure != nil {
				add("CHECK_FAILED", authorproject.ConfigFile, failure.Error()+authorCommandOutput(result.Commands))
			}
		}
	}
	command := "check"
	if doctor {
		command = "doctor"
	}
	if err := writeJSON(map[string]any{"ok": len(diagnostics) == 0, "command": command, "diagnostics": diagnostics, "tools": tools, "stages": stages, "runtime_required": len(m.Workers) > 0, "note": "Tool and dependency readiness is not runtime admission. Declared tests are not proof of browser or WASM execution."}); err != nil {
		return err
	}
	if len(diagnostics) > 0 {
		return errors.New("author project needs attention; see diagnostics")
	}
	return nil
}

func checkAuthorReadiness(ctx context.Context, project *authorproject.Project, worker, includeTests bool, add func(string, string, string)) map[string]bool {
	commands := [][]string{project.Config.Build, project.Config.Prepare, project.Config.Typecheck}
	if includeTests {
		commands = append(commands, project.Config.Test)
	}
	tools := map[string]bool{}
	for _, argv := range commands {
		if len(argv) == 0 {
			continue
		}
		executable := argv[0]
		if strings.ContainsAny(executable, `/\`) && !filepath.IsAbs(executable) {
			executable = filepath.Join(project.Root, executable)
		}
		_, failure := exec.LookPath(executable)
		tools[argv[0]] = failure == nil
		if failure != nil {
			add("TOOL_UNAVAILABLE", argv[0], "Install the project's declared build tool")
		}
	}
	// Preparation may install dependencies before the build starts.
	if len(project.Config.Prepare) == 0 {
		checkAuthorDependencies(project, commands, add)
	}
	checkAuthorToolchains(ctx, project, commands, worker, add)
	return tools
}
func authorCommandOutput(commands []authorproject.CommandResult) string {
	var output strings.Builder
	for _, command := range commands {
		output.WriteString(command.Output)
	}
	return output.String()
}
func checkAuthorDependencies(project *authorproject.Project, commands [][]string, add func(string, string, string)) {
	usesNPM := false
	for _, argv := range commands {
		if len(argv) > 0 && (argv[0] == "npm" || argv[0] == "npm.cmd") {
			usesNPM = true
		}
	}
	if !usesNPM {
		return
	}
	raw, err := os.ReadFile(filepath.Join(project.Root, "package.json"))
	if err != nil {
		add("DEPENDENCY_UNAVAILABLE", "package.json", "Read package.json and install dependencies with npm install")
		return
	}
	var pkg struct {
		Dependencies    map[string]string
		DevDependencies map[string]string
	}
	if json.Unmarshal(raw, &pkg) != nil {
		add("PACKAGE_CONFIG_INVALID", "package.json", "Expected a valid npm package manifest")
		return
	}
	names := []string{}
	for name := range pkg.Dependencies {
		names = append(names, name)
	}
	for name := range pkg.DevDependencies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.Contains(name, "..") || filepath.IsAbs(name) || strings.ContainsAny(name, string(rune(0))+string(rune(92))) {
			add("PACKAGE_CONFIG_INVALID", "package.json", "Invalid dependency name")
			continue
		}
		installed, failure := os.ReadFile(filepath.Join(project.Root, "node_modules", filepath.FromSlash(name), "package.json"))
		var metadata struct{ Version string }
		expected := pkg.Dependencies[name]
		if expected == "" {
			expected = pkg.DevDependencies[name]
		}
		if failure != nil || json.Unmarshal(installed, &metadata) != nil || metadata.Version == "" {
			add("DEPENDENCY_UNAVAILABLE", "node_modules/"+name, "Run npm install in this project, then run doctor again")
		} else if regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(expected) && expected != metadata.Version {
			add("DEPENDENCY_VERSION_MISMATCH", "node_modules/"+name, "Run npm install; expected "+expected+", found "+metadata.Version)
		}
	}
}

func checkAuthorToolchains(ctx context.Context, p *authorproject.Project, commands [][]string, worker bool, add func(string, string, string)) {
	usesNPM := false
	for _, command := range commands {
		if len(command) > 0 && (command[0] == "npm" || command[0] == "npm.cmd") {
			usesNPM = true
		}
	}
	if usesNPM && authorUsesGeneratedNodeToolchain(p.Root) {
		value, err := exec.CommandContext(ctx, "node", "--version").Output()
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(value)), "v26.") {
			add("TOOLCHAIN_MISMATCH", "node", "Use Node.js 26 for the generated author project")
		}
	}
	if !worker || !authorUsesGeneratedRustToolchain(p.Root) {
		return
	}
	command := exec.CommandContext(ctx, "rustc", "--version")
	command.Dir = p.Root
	value, err := command.Output()
	if err != nil || !strings.HasPrefix(string(value), "rustc 1.98.0 ") {
		add("TOOLCHAIN_MISMATCH", "rustc", "Install Rust 1.98.0 with rustup toolchain install 1.98.0 --profile minimal")
	}
	command = exec.CommandContext(ctx, "rustup", "target", "list", "--installed", "--toolchain", "1.98.0")
	command.Dir = p.Root
	value, err = command.Output()
	if err != nil || !strings.Contains(string(value), "wasm32-unknown-unknown") {
		add("TARGET_UNAVAILABLE", "wasm32-unknown-unknown", "Run rustup target add wasm32-unknown-unknown --toolchain 1.98.0")
	}
}

func authorUsesGeneratedNodeToolchain(root string) bool {
	raw, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return false
	}
	var pkg struct {
		Engines map[string]string `json:"engines"`
	}
	return json.Unmarshal(raw, &pkg) == nil && pkg.Engines["node"] == ">=26.0.0 <27"
}

func authorUsesGeneratedRustToolchain(root string) bool {
	raw, err := os.ReadFile(filepath.Join(root, "rust-toolchain.toml"))
	return err == nil && string(raw) == "[toolchain]\nchannel = \"1.98.0\"\ntargets = [\"wasm32-unknown-unknown\"]\nprofile = \"minimal\"\n"
}
