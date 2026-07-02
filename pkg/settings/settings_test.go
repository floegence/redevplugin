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

func TestMemoryStoreBindRetainedSettings(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	spec := settingsSpec()
	if _, err := store.Ensure(ctx, EnsureRequest{PluginInstanceID: "plugini_source", Spec: &spec}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Patch(ctx, PatchRequest{
		PluginInstanceID: "plugini_source",
		Values:           map[string]any{"engine": "podman", "retry_count": 4},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkSecret(ctx, MarkSecretRequest{
		PluginInstanceID: "plugini_source",
		SecretRef:        "api_key",
		Set:              true,
		LastTestStatus:   "passed",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, DeleteRequest{PluginInstanceID: "plugini_source"}); err != nil {
		t.Fatal(err)
	}

	bound, err := store.BindRetained(ctx, BindRetainedRequest{
		SourcePluginInstanceID: "plugini_source",
		TargetPluginInstanceID: "plugini_target",
		Spec:                   &spec,
	})
	if err != nil {
		t.Fatalf("BindRetained() error = %v", err)
	}
	if bound.PluginInstanceID != "plugini_target" || bound.Values["engine"] != "podman" || bound.Values["retry_count"] != int64(4) {
		t.Fatalf("bound settings mismatch: %#v", bound)
	}
	secret, ok := bound.Values["api_key"].(SecretValue)
	if !ok {
		t.Fatalf("bound secret should be redacted state: %#v", bound.Values["api_key"])
	}
	if secret.Set || secret.LastTestStatus != "" || secret.UpdatedAt != nil {
		t.Fatalf("retained bind must not restore secret binding state: %#v", secret)
	}
	if _, err := store.Get(ctx, GetRequest{PluginInstanceID: "plugini_source"}); !errors.Is(err, ErrNotDeclared) {
		t.Fatalf("Get(source after bind) error = %v, want ErrNotDeclared", err)
	}
}

func TestMemoryStoreExportImportSettingsData(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	spec := settingsSpec()
	now := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	if _, err := store.Ensure(ctx, EnsureRequest{PluginInstanceID: "plugini_source", Spec: &spec, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Patch(ctx, PatchRequest{
		PluginInstanceID: "plugini_source",
		Values:           map[string]any{"engine": "podman", "retry_count": 4},
		Now:              now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkSecret(ctx, MarkSecretRequest{
		PluginInstanceID: "plugini_source",
		SecretRef:        "api_key",
		Set:              true,
		LastTestStatus:   "passed",
		Now:              now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	archiveRef, err := store.Export(ctx, ExportRequest{
		PluginInstanceID: "plugini_source",
		IncludeSecrets:   true,
		Now:              now.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if archiveRef == "" {
		t.Fatal("Export() returned empty archive ref")
	}
	store.mu.Lock()
	if got := store.archives[archiveRef].Secrets["api_key"]; !got.Set || got.LastTestStatus != "passed" {
		store.mu.Unlock()
		t.Fatalf("include_secrets export should retain redacted secret metadata: %#v", got)
	}
	store.mu.Unlock()

	imported, err := store.Import(ctx, ImportRequest{
		PluginInstanceID: "plugini_target",
		ArchiveRef:       archiveRef,
		DeleteExisting:   true,
		Spec:             &spec,
		Now:              now.Add(4 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if imported.Values["engine"] != "podman" || imported.Values["retry_count"] != int64(4) {
		t.Fatalf("imported values mismatch: %#v", imported.Values)
	}
	secret, ok := imported.Values["api_key"].(SecretValue)
	if !ok {
		t.Fatalf("imported secret should be redacted metadata: %#v", imported.Values["api_key"])
	}
	if secret.Set || secret.UpdatedAt != nil || secret.LastTestStatus != "" {
		t.Fatalf("import should not restore secret binding state: %#v", secret)
	}
}

func TestMemoryStoreExportOmitsSecretMetadataByDefault(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	spec := settingsSpec()
	if _, err := store.Ensure(ctx, EnsureRequest{PluginInstanceID: "plugini_source", Spec: &spec}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkSecret(ctx, MarkSecretRequest{
		PluginInstanceID: "plugini_source",
		SecretRef:        "api_key",
		Set:              true,
		LastTestStatus:   "passed",
	}); err != nil {
		t.Fatal(err)
	}
	archiveRef, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_source"})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.archives[archiveRef].Secrets) != 0 {
		t.Fatalf("default export should omit secret metadata: %#v", store.archives[archiveRef].Secrets)
	}
}

func TestMemoryStoreStateRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	spec := settingsSpec()
	now := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	if _, err := store.Ensure(ctx, EnsureRequest{PluginInstanceID: "plugini_source", Spec: &spec, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Patch(ctx, PatchRequest{
		PluginInstanceID: "plugini_source",
		Values:           map[string]any{"engine": "podman", "retry_count": 2},
		Now:              now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkSecret(ctx, MarkSecretRequest{
		PluginInstanceID: "plugini_source",
		SecretRef:        "api_key",
		Set:              true,
		LastTestStatus:   "passed",
		Now:              now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	archiveRef, err := store.Export(ctx, ExportRequest{
		PluginInstanceID: "plugini_source",
		IncludeSecrets:   true,
		Now:              now.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	restored := NewMemoryStoreFromState(store.State())
	snapshot, err := restored.Get(ctx, GetRequest{PluginInstanceID: "plugini_source"})
	if err != nil {
		t.Fatalf("Get(restored) error = %v", err)
	}
	if snapshot.SettingsRevision != 3 || snapshot.Values["engine"] != "podman" || snapshot.Values["retry_count"] != int64(2) {
		t.Fatalf("restored snapshot mismatch: %#v", snapshot)
	}
	secret, ok := snapshot.Values["api_key"].(SecretValue)
	if !ok || !secret.Set || secret.LastTestStatus != "passed" {
		t.Fatalf("restored secret metadata mismatch: %#v", snapshot.Values["api_key"])
	}
	imported, err := restored.Import(ctx, ImportRequest{
		PluginInstanceID: "plugini_target",
		ArchiveRef:       archiveRef,
		DeleteExisting:   true,
		Spec:             &spec,
		Now:              now.Add(4 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Import(restored archive) error = %v", err)
	}
	if imported.Values["engine"] != "podman" {
		t.Fatalf("restored archive import mismatch: %#v", imported.Values)
	}
}

func TestMemoryStoreImportRejectsInvalidArchiveSetting(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	spec := settingsSpec()
	if _, err := store.Ensure(ctx, EnsureRequest{PluginInstanceID: "plugini_source", Spec: &spec}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Patch(ctx, PatchRequest{
		PluginInstanceID: "plugini_source",
		Values:           map[string]any{"engine": "podman"},
	}); err != nil {
		t.Fatal(err)
	}
	archiveRef, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_source"})
	if err != nil {
		t.Fatal(err)
	}

	targetSpec := settingsSpec()
	targetSpec.Fields[0].Options = []string{"docker"}
	if _, err := store.Import(ctx, ImportRequest{
		PluginInstanceID: "plugini_target",
		ArchiveRef:       archiveRef,
		Spec:             &targetSpec,
	}); !errors.Is(err, ErrInvalidSetting) {
		t.Fatalf("Import(incompatible option) error = %v, want ErrInvalidSetting", err)
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
