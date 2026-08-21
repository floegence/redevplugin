package host

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnvironmentResetIsBlockedWhileHostOwnsTargetAndPreservesUnknownData(t *testing.T) {
	root := filepath.Join(t.TempDir(), "environment")
	config := modularTestConfig(t)
	config.StateRoot = root
	host, err := Open(hostTestContext(), config)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewEnvironmentResetOwnershipManifest("env_local",
		EnvironmentResetHostControl,
		EnvironmentResetPluginData,
		EnvironmentResetExternalInspection,
		EnvironmentResetAssets,
		EnvironmentResetObservability,
		EnvironmentResetSecrets,
		EnvironmentResetRuntimeExecution,
		EnvironmentResetReleaseArtifacts,
		EnvironmentResetTrust,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := EnvironmentResetRequest{StateRoot: root, OperationID: "reinstall-1", OwnershipManifest: manifest}
	if _, err := PreflightEnvironmentReset(t.Context(), request); !errors.Is(err, ErrEnvironmentResetBlocked) {
		t.Fatalf("PreflightEnvironmentReset() while open error = %v, want %v", err, ErrEnvironmentResetBlocked)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}

	unknownPath := filepath.Join(root, "redeven-owned.txt")
	if err := os.WriteFile(unknownPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Entries {
		target := filepath.Join(root, entry.RelativePath)
		if filepath.Ext(target) == ".sqlite" {
			if err := os.WriteFile(target+"-wal", []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "old-data"), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	preflight, err := PreflightEnvironmentReset(t.Context(), request)
	if err != nil || len(preflight.DeleteEntries) != len(manifest.Entries) {
		t.Fatalf("PreflightEnvironmentReset() = %#v, %v", preflight, err)
	}
	result, err := ResetEnvironment(t.Context(), request)
	if err != nil || len(result.ResetEntries) != len(manifest.Entries) {
		t.Fatalf("ResetEnvironment() = %#v, %v", result, err)
	}
	if content, err := os.ReadFile(unknownPath); err != nil || string(content) != "keep" {
		t.Fatalf("unknown data = %q, %v", content, err)
	}
	if _, err := os.Stat(filepath.Join(root, "control.sqlite")); err != nil {
		t.Fatalf("fresh control store missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "plugin-data", "old-data")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old plugin data remains: %v", err)
	}
	if _, err := ResetEnvironment(t.Context(), request); err != nil {
		t.Fatalf("repeated ResetEnvironment() error = %v", err)
	}
}

func TestEnvironmentResetRejectsTamperedManifestAndSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "environment")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, err := NewEnvironmentResetOwnershipManifest("env_local", EnvironmentResetAssets)
	if err != nil {
		t.Fatal(err)
	}
	tampered := manifest
	tampered.Entries = append([]EnvironmentResetOwnershipEntry(nil), manifest.Entries...)
	tampered.Entries[0].RelativePath = "../outside"
	request := EnvironmentResetRequest{StateRoot: root, OperationID: "reinstall-2", OwnershipManifest: tampered}
	if _, err := PreflightEnvironmentReset(t.Context(), request); !errors.Is(err, ErrEnvironmentResetRequest) {
		t.Fatalf("tampered manifest error = %v, want %v", err, ErrEnvironmentResetRequest)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "assets")); err != nil {
		t.Fatal(err)
	}
	request.OwnershipManifest = manifest
	if _, err := ResetEnvironment(t.Context(), request); !errors.Is(err, ErrEnvironmentResetBlocked) {
		t.Fatalf("symlink reset error = %v, want %v", err, ErrEnvironmentResetBlocked)
	}
}
