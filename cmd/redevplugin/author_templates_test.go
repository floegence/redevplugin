package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/authorproject"
)

func TestInitDefaultsToPackageableWebApplication(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	if _, err := captureCLIOutput(t, "init", "example.web", "Web Application", root); err != nil {
		t.Fatal(err)
	}
	project, err := authorproject.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _, err := project.Package(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.Manifest.Workers) != 0 {
		t.Fatal("Web application unexpectedly requires a Worker")
	}
	if len(pkg.Manifest.Methods) != 1 || pkg.Manifest.Methods[0].Method != "application.read" {
		t.Fatal("expected the explicit Surface action")
	}
	for _, name := range []string{"worker", "rust-toolchain.toml", "dist/workers"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("unexpected Worker input %s: %v", name, err)
		}
	}
	build, err := os.ReadFile(filepath.Join(root, "scripts/build.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(build, []byte("cargo")) {
		t.Fatal("Web build requires Cargo")
	}
}

func TestInitRejectsUnknownTemplateWithoutWriting(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	if _, err := captureCLIOutput(t, "init", "example.web", "Web Application", root, "--template", "unknown"); err == nil {
		t.Fatal("unknown template accepted")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("invalid template created output")
	}
}

func TestDataTemplateDeclaresDirectPrivateStorage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if _, err := createPluginTemplate("example.data", "Data Application", root, "data"); err != nil {
		t.Fatal(err)
	}
	p, err := authorproject.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _, err := p.Package(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.Manifest.Workers) != 0 || len(pkg.Manifest.Surfaces[0].Web.Storage) != 1 {
		t.Fatal("data application requires a forwarding Worker")
	}
	if _, err := os.Stat(filepath.Join(root, "generated/actions.ts")); err != nil {
		t.Fatal(err)
	}
}

func TestResourceTemplatesPackageWithoutWorkers(t *testing.T) {
	for _, template := range []string{"monitor", "files"} {
		t.Run(template, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), template)
			if _, err := createPluginTemplate("example."+template, "Resource Application", root, template); err != nil {
				t.Fatal(err)
			}
			p, err := authorproject.Load(root)
			if err != nil {
				t.Fatal(err)
			}
			pkg, _, err := p.Package(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(pkg.Manifest.Workers) != 0 {
				t.Fatal("resource template requires forwarding Worker")
			}
		})
	}
}
