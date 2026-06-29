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

	uninstalled, err := store.MarkUninstalled(context.Background(), stored.PluginInstanceID, RetainedDataDeleted, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if uninstalled.ManagementRevision != 3 || uninstalled.RevokeEpoch != 2 || uninstalled.DeletedAt == nil {
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
