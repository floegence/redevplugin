package settings

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
)

func TestMemoryStoreDefaultsPatchAndSecretRedaction(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	spec := settingsSpec()

	created, err := store.Ensure(context.Background(), EnsureRequest{
		PluginInstanceID: "plugini_settings",
		Spec:             &spec,
		Now:              now,
	})
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if created.SettingsRevision != 1 || created.Values["engine"] != "docker" || created.Values["enabled"] != true {
		t.Fatalf("created snapshot mismatch: %#v", created)
	}
	secret, ok := created.Values["api_key"].(SecretValue)
	if !ok || secret.Set {
		t.Fatalf("secret default should be redacted unset state: %#v", created.Values["api_key"])
	}

	patched, err := store.Patch(context.Background(), PatchRequest{
		PluginInstanceID: "plugini_settings",
		Values:           map[string]any{"engine": "podman", "retry_count": 3},
		Now:              now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Patch() error = %v", err)
	}
	if patched.SettingsRevision != 2 || patched.Values["engine"] != "podman" || patched.Values["retry_count"] != int64(3) {
		t.Fatalf("patched snapshot mismatch: %#v", patched)
	}

	marked, err := store.MarkSecret(context.Background(), MarkSecretRequest{
		PluginInstanceID: "plugini_settings",
		SecretRef:        "api_key",
		Set:              true,
		LastTestStatus:   "passed",
		Now:              now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("MarkSecret() error = %v", err)
	}
	secret, ok = marked.Values["api_key"].(SecretValue)
	if !ok || !secret.Set || secret.LastTestStatus != "passed" || secret.UpdatedAt == nil {
		t.Fatalf("secret state mismatch: %#v", marked.Values["api_key"])
	}
}

func TestMemoryStoreRejectsInvalidSettings(t *testing.T) {
	store := NewMemoryStore()
	spec := settingsSpec()
	if _, err := store.Ensure(context.Background(), EnsureRequest{PluginInstanceID: "plugini_settings", Spec: &spec}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Patch(context.Background(), PatchRequest{
		PluginInstanceID: "plugini_settings",
		Values:           map[string]any{"api_key": "plaintext"},
	}); !errors.Is(err, ErrInvalidSetting) {
		t.Fatalf("Patch(secret) error = %v, want ErrInvalidSetting", err)
	}
	if _, err := store.Patch(context.Background(), PatchRequest{
		PluginInstanceID: "plugini_settings",
		Values:           map[string]any{"engine": "containerd"},
	}); !errors.Is(err, ErrInvalidSetting) {
		t.Fatalf("Patch(enum) error = %v, want ErrInvalidSetting", err)
	}
	if _, err := store.Patch(context.Background(), PatchRequest{
		PluginInstanceID: "plugini_settings",
		Values:           map[string]any{"retry_count": 9},
	}); !errors.Is(err, ErrInvalidSetting) {
		t.Fatalf("Patch(maximum) error = %v, want ErrInvalidSetting", err)
	}
}

func TestMemoryStoreDeleteRetainLifecycle(t *testing.T) {
	store := NewMemoryStore()
	spec := settingsSpec()
	if _, err := store.Ensure(context.Background(), EnsureRequest{PluginInstanceID: "plugini_settings", Spec: &spec}); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), DeleteRequest{PluginInstanceID: "plugini_settings"}); err != nil {
		t.Fatalf("Delete(retain) error = %v", err)
	}
	if _, err := store.Get(context.Background(), GetRequest{PluginInstanceID: "plugini_settings"}); !errors.Is(err, ErrNotDeclared) {
		t.Fatalf("Get(retained) error = %v, want ErrNotDeclared", err)
	}
	if snapshot, err := store.Ensure(context.Background(), EnsureRequest{PluginInstanceID: "plugini_settings", Spec: &spec}); err != nil || snapshot.SettingsRevision != 3 {
		t.Fatalf("Ensure(reactivate) snapshot=%#v err=%v", snapshot, err)
	}
	if err := store.Delete(context.Background(), DeleteRequest{PluginInstanceID: "plugini_settings", DeleteData: true}); err != nil {
		t.Fatalf("Delete(delete data) error = %v", err)
	}
	if _, err := store.Get(context.Background(), GetRequest{PluginInstanceID: "plugini_settings"}); !errors.Is(err, ErrNotDeclared) {
		t.Fatalf("Get(deleted) error = %v, want ErrNotDeclared", err)
	}
}

func settingsSpec() manifest.SettingsSpec {
	return manifest.SettingsSpec{
		SchemaVersion: 1,
		Migration: manifest.MigrationSpec{
			FromVersion:    1,
			ToVersion:      1,
			Reversible:     true,
			RequiresWorker: false,
			StepsHash:      "sha256:test",
		},
		Fields: []manifest.SettingFieldSpec{
			{Key: "engine", Type: FieldSelect, Label: "Engine", Scope: "user", Default: "docker", Options: []string{"docker", "podman"}},
			{Key: "enabled", Type: FieldBoolean, Label: "Enabled", Scope: "user", Default: true},
			{Key: "retry_count", Type: FieldInteger, Label: "Retries", Scope: "user", Default: 1, Validation: map[string]any{"minimum": 0, "maximum": 5}},
			{Key: "api_key", Type: FieldSecret, Label: "API Key", Scope: "user", SecretRef: "api_key"},
		},
	}
}
