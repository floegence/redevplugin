package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/authorproject"
)

func TestAuthorDoctorReportsMissingInstalledDependencies(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	if _, err := createPluginTemplate("example-readiness", "Readiness", root, "web"); err != nil {
		t.Fatal(err)
	}
	output, err := captureCLIOutput(t, "doctor", root)
	if err == nil || !strings.Contains(string(output), "DEPENDENCY_UNAVAILABLE") {
		t.Fatalf("uninstalled project reported ready: %s (%v)", output, err)
	}
}

func TestAuthorDevReportsMissingDependenciesBeforeCreatingState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	if _, err := createPluginTemplate("example-devreadiness", "Readiness", root, "web"); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	err := runAuthorDev(context.Background(), []string{root, "--state", state})
	if err == nil || !strings.Contains(err.Error(), "DEPENDENCY_UNAVAILABLE") || !strings.Contains(err.Error(), "npm install") {
		t.Fatalf("dev did not report actionable dependency diagnostics: %v", err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("dev changed state before readiness check: %v", err)
	}
}

func TestAuthorDevReadinessDoesNotRequireTestOnlyTool(t *testing.T) {
	project := &authorproject.Project{Root: t.TempDir(), Config: authorproject.Config{Build: []string{"go"}, Test: []string{"redevplugin-missing-test-tool"}}}
	var diagnostics []string
	add := func(code, _, _ string) { diagnostics = append(diagnostics, code) }
	checkAuthorReadiness(context.Background(), project, false, false, add)
	if len(diagnostics) != 0 {
		t.Fatalf("test-only tool blocked dev: %v", diagnostics)
	}
	checkAuthorReadiness(context.Background(), project, false, true, add)
	if len(diagnostics) != 1 || diagnostics[0] != "TOOL_UNAVAILABLE" {
		t.Fatalf("doctor did not check test-only tool: %v", diagnostics)
	}
}

func TestGeneratedToolchainChecksDoNotConstrainCustomProjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	if _, err := createPluginTemplate("example-toolchain", "Toolchain", root, "worker"); err != nil {
		t.Fatal(err)
	}
	if !authorUsesGeneratedNodeToolchain(root) || !authorUsesGeneratedRustToolchain(root) {
		t.Fatal("generated toolchains were not detected")
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"engines":{"node":">=22"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "rust-toolchain.toml"), []byte("[toolchain]\nchannel = \"stable\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if authorUsesGeneratedNodeToolchain(root) || authorUsesGeneratedRustToolchain(root) {
		t.Fatal("custom toolchains were treated as generated requirements")
	}
}

func TestAuthorReadinessAllowsPreparationToInstallDependencies(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"example":"1.0.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	project := &authorproject.Project{Root: root, Config: authorproject.Config{Prepare: []string{"go"}, Build: []string{"npm", "run", "build"}}}
	var diagnostics []string
	checkAuthorReadiness(context.Background(), project, false, false, func(code, _, _ string) { diagnostics = append(diagnostics, code) })
	for _, code := range diagnostics {
		if code == "DEPENDENCY_UNAVAILABLE" {
			t.Fatal("readiness rejected dependencies that preparation may install")
		}
	}
}

func TestAuthorWebTemplateRunsBusinessTestsAndChecksTypesDuringBuild(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	if _, err := createPluginTemplate("example-business", "Business", root, "web"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pkg.Scripts["test"], "--test") {
		t.Fatalf("test is not a business test: %s", pkg.Scripts["test"])
	}
	config, err := os.ReadFile(filepath.Join(root, "redevplugin.project.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "typecheck") {
		t.Fatal("developer build has no static check stage")
	}
}

func TestAuthorReadinessResolvesProjectRelativeCommands(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts", "build")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	project := &authorproject.Project{Root: root, Config: authorproject.Config{Build: []string{"./scripts/build"}}}
	var diagnostics []string
	checkAuthorReadiness(context.Background(), project, false, false, func(code, _, _ string) { diagnostics = append(diagnostics, code) })
	if len(diagnostics) != 0 {
		t.Fatalf("project-relative executable was rejected: %v", diagnostics)
	}
	if _, err := project.Run(context.Background(), project.Config.Build); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	checkAuthorReadiness(context.Background(), project, false, false, func(code, _, _ string) { diagnostics = append(diagnostics, code) })
	if len(diagnostics) != 1 || diagnostics[0] != "TOOL_UNAVAILABLE" {
		t.Fatalf("missing executable was accepted: %v", diagnostics)
	}
}
