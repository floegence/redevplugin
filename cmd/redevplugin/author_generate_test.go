package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateAuthorContractAndCheckDrift(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source")
	if _, err := createPluginScaffold("example-contract", "Contract", root); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "manifest.json")
	output := filepath.Join(root, "generated")
	if _, err := captureCLIOutput(t, "generate", input, output); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"actions.ts": "worker.echo", "actions.rs": "pub trait WorkerActions", "manifest.json": "example-contract", "source-map.json": "/methods/0"} {
		raw, err := os.ReadFile(filepath.Join(output, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("%s missing %s", name, want)
		}
	}
	if _, err := captureCLIOutput(t, "generate", input, output, "--check"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "actions.ts"), []byte("drift"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureCLIOutput(t, "generate", input, output, "--check"); err == nil {
		t.Fatal("generated drift accepted")
	}
	raw, _ := os.ReadFile(filepath.Join(output, "actions.ts"))
	if string(raw) != "drift" {
		t.Fatal("check modified source")
	}
}

func TestGenerateRejectsSourceDirectoryAndSymlinkOutput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source")
	if _, err := createPluginScaffold("example-contract", "Contract", root); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "manifest.json")
	before, _ := os.ReadFile(input)
	if err := generateAuthorAPI(input, root, false); err == nil {
		t.Fatal("source overwrite accepted")
	}
	after, _ := os.ReadFile(input)
	if !bytes.Equal(before, after) {
		t.Fatal("source manifest changed")
	}
	output := filepath.Join(root, "generated")
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "important.ts")
	if err := os.WriteFile(victim, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(output, "actions.ts")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(output, "actions.ts")); err != nil {
		t.Fatal(err)
	}
	if err := generateAuthorAPI(input, output, false); err == nil {
		t.Fatal("symlink output accepted")
	}
	content, _ := os.ReadFile(victim)
	if string(content) != "preserve" {
		t.Fatal("symlink target changed")
	}
}
