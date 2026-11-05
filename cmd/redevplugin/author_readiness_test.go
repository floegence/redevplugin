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
	if _, err := createPluginTemplate("example.readiness", "Readiness", root, "web"); err != nil {
		t.Fatal(err)
	}
	output, err := captureCLIOutput(t, "doctor", root)
	if err == nil || !strings.Contains(string(output), "DEPENDENCY_UNAVAILABLE") {
		t.Fatalf("uninstalled project reported ready: %s (%v)", output, err)
	}
}

func TestAuthorDevReportsMissingDependenciesBeforeCreatingState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	if _, err := createPluginTemplate("example.devreadiness", "Readiness", root, "web"); err != nil {
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

func TestAuthorWebTemplateRunsBusinessTestsAndChecksTypesDuringBuild(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	if _, err := createPluginTemplate("example.business", "Business", root, "web"); err != nil {
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
