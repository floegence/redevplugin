package registry

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
)

func TestMemoryStoreRevisionsAndList(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
	record := PluginRecord{
		PluginInstanceID:  "plugini_test",
		PublisherID:       "example",
		PluginID:          "com.example.test",
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:test",
		TrustState:        TrustVerified,
		EnableState:       EnableDisabled,
		Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.test", Version: "1.0.0"}},
	}
	stored, err := store.PutPlugin(context.Background(), record, PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if stored.PolicyRevision != 1 || stored.ManagementRevision != 1 || stored.RevokeEpoch != 0 {
		t.Fatalf("initial revisions = %#v", stored)
	}

	enabled, err := store.SetEnableState(context.Background(), stored.PluginInstanceID, EnableEnabled, "", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if enabled.ManagementRevision != 2 || enabled.RevokeEpoch != 1 || enabled.EnabledAt == nil {
		t.Fatalf("enable revisions = %#v", enabled)
	}

	granted, err := store.BumpPolicyRevision(context.Background(), stored.PluginInstanceID, false, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if granted.PolicyRevision != 2 || granted.ManagementRevision != 2 || granted.RevokeEpoch != 1 {
		t.Fatalf("grant policy revisions = %#v", granted)
	}

	revoked, err := store.BumpPolicyRevision(context.Background(), stored.PluginInstanceID, true, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if revoked.PolicyRevision != 3 || revoked.ManagementRevision != 2 || revoked.RevokeEpoch != 2 {
		t.Fatalf("revoke policy revisions = %#v", revoked)
	}

	uninstalled, err := store.MarkUninstalled(context.Background(), stored.PluginInstanceID, RetainedDataDeleted, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if uninstalled.ManagementRevision != 3 || uninstalled.PolicyRevision != 3 || uninstalled.RevokeEpoch != 3 || uninstalled.DeletedAt == nil {
		t.Fatalf("uninstall revisions = %#v", uninstalled)
	}
	list, err := store.ListPlugins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("ListPlugins() returned deleted record: %#v", list)
	}
}

func TestMemoryStorePreservesVersionHistoryOnOverwrite(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
	record := PluginRecord{
		PluginInstanceID:  "plugini_test",
		PublisherID:       "example",
		PluginID:          "com.example.test",
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:v1",
		PackageHash:       "sha256:v1",
		TrustState:        TrustVerified,
		EnableState:       EnableEnabled,
		Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.test", Version: "1.0.0"}},
	}
	stored, err := store.PutPlugin(context.Background(), record, PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	stored.Version = "2.0.0"
	stored.ActiveFingerprint = "sha256:v2"
	stored.PackageHash = "sha256:v2"
	stored.VersionHistory = []PluginVersion{{Version: "1.0.0", PackageHash: "sha256:v1"}}
	updated, err := store.PutPlugin(context.Background(), stored, PutOptions{Now: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ManagementRevision != 2 || updated.RevokeEpoch != 1 || len(updated.VersionHistory) != 1 || updated.VersionHistory[0].Version != "1.0.0" {
		t.Fatalf("updated record mismatch: %#v", updated)
	}
}

func TestRunnableTrustState(t *testing.T) {
	for _, state := range []TrustState{TrustBundled, TrustVerified, TrustUnsignedLocal} {
		if !RunnableTrustState(state) {
			t.Fatalf("%s should be runnable", state)
		}
	}
	for _, state := range []TrustState{TrustUntrusted, TrustNeedsReview, TrustBlockedSecurity} {
		if RunnableTrustState(state) {
			t.Fatalf("%s should not be runnable", state)
		}
	}
}
