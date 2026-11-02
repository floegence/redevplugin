package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
