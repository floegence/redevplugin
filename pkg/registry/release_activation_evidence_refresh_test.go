package registry

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
)

func TestRefreshReleaseActivationEvidenceIsAtomicAndIdempotent(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := registryTestContext()
			store := tc.open(t)
			before := putReleaseActivationEvidenceRecord(t, store, "plugini_activation_refresh")
			oldDigest := before.ReleaseTrustBinding.ActivationEvidenceSHA256
			nextState := strings.Repeat("3", 64)
			updatedAt := before.UpdatedAt.Add(time.Minute)
			req := RefreshReleaseActivationEvidenceRequest{
				PluginInstanceID: before.PluginInstanceID, ExpectedManagementRevision: before.ManagementRevision,
				ExpectedStateSHA256: before.ReleaseTrustBinding.VerifiedStateSHA256,
				NextStateSHA256:     nextState, Now: updatedAt,
			}

			first, err := store.RefreshReleaseActivationEvidence(ctx, req)
			if err != nil {
				t.Fatalf("RefreshReleaseActivationEvidence() error = %v", err)
			}
			if first.ReleaseTrustBinding == nil || first.ReleaseTrustBinding.VerifiedStateSHA256 != nextState ||
				first.ReleaseTrustBinding.ActivationEvidenceSHA256 == oldDigest || first.UpdatedAt != updatedAt {
				t.Fatalf("refreshed record = %#v", first)
			}
			if first.ManagementRevision != before.ManagementRevision || first.PolicyRevision != before.PolicyRevision || first.RevokeEpoch != before.RevokeEpoch ||
				first.Metadata["preserved"] != "yes" || !reflect.DeepEqual(first.Manifest, before.Manifest) {
				t.Fatalf("refresh changed unrelated security or product fields:\nbefore=%#v\nafter=%#v", before, first)
			}
			if err := ValidateReleaseActivationEvidence(first); err != nil {
				t.Fatalf("ValidateReleaseActivationEvidence() error = %v", err)
			}

			second, err := store.RefreshReleaseActivationEvidence(ctx, req)
			if err != nil {
				t.Fatalf("idempotent RefreshReleaseActivationEvidence() error = %v", err)
			}
			if !reflect.DeepEqual(second, first) {
				t.Fatalf("idempotent refresh changed record:\nfirst=%#v\nsecond=%#v", first, second)
			}
		})
	}
}

func TestRefreshReleaseActivationEvidenceRejectsConflictsCancellationAndTampering(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := registryTestContext()
			store := tc.open(t)
			before := putReleaseActivationEvidenceRecord(t, store, "plugini_activation_reject")
			valid := RefreshReleaseActivationEvidenceRequest{
				PluginInstanceID: before.PluginInstanceID, ExpectedManagementRevision: before.ManagementRevision,
				ExpectedStateSHA256: before.ReleaseTrustBinding.VerifiedStateSHA256,
				NextStateSHA256:     strings.Repeat("4", 64), Now: before.UpdatedAt.Add(time.Minute),
			}

			checks := []struct {
				name string
				ctx  context.Context
				req  RefreshReleaseActivationEvidenceRequest
			}{
				{name: "management revision", ctx: ctx, req: func() RefreshReleaseActivationEvidenceRequest {
					req := valid
					req.ExpectedManagementRevision++
					return req
				}()},
				{name: "state digest", ctx: ctx, req: func() RefreshReleaseActivationEvidenceRequest {
					req := valid
					req.ExpectedStateSHA256 = strings.Repeat("5", 64)
					return req
				}()},
				{name: "canceled", ctx: func() context.Context { canceled, cancel := context.WithCancel(ctx); cancel(); return canceled }(), req: valid},
			}
			for _, check := range checks {
				t.Run(check.name, func(t *testing.T) {
					if _, err := store.RefreshReleaseActivationEvidence(check.ctx, check.req); err == nil {
						t.Fatal("RefreshReleaseActivationEvidence() error = nil")
					}
					after, err := store.GetPlugin(ctx, before.PluginInstanceID)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(after, before) {
						t.Fatalf("rejected refresh mutated record:\nbefore=%#v\nafter=%#v", before, after)
					}
				})
			}

			tampered := before
			binding := *before.ReleaseTrustBinding
			tampered.ReleaseTrustBinding = &binding
			tampered.ReleaseTrustBinding.ActivationEvidenceSHA256 = strings.Repeat("0", 64)
			if _, err := store.PutPlugin(ctx, tampered, PutOptions{Now: before.UpdatedAt.Add(2 * time.Minute)}); err == nil {
				t.Fatal("PutPlugin() accepted tampered evidence")
			}
		})
	}
}

func putReleaseActivationEvidenceRecord(t *testing.T, store Store, pluginInstanceID string) PluginRecord {
	t.Helper()
	record := PluginRecord{
		PluginInstanceID: pluginInstanceID, PublisherID: "example.publisher", PluginID: "com.example.clone", Version: "1.0.0",
		ActiveFingerprint: "sha256:" + strings.Repeat("a", 64), PackageHash: "sha256:" + strings.Repeat("b", 64),
		ManifestHash: "sha256:" + strings.Repeat("c", 64), EntriesHash: "sha256:" + strings.Repeat("d", 64),
		TrustState: TrustVerified, EnableState: EnableEnabled, ReleaseTrustBinding: testReleaseTrustBinding("source.activation", "1.0.0"),
		Manifest: manifest.Manifest{SchemaVersion: manifest.SchemaVersionV8, Publisher: manifest.Publisher{PublisherID: "example.publisher"}, Plugin: manifest.Plugin{PluginID: "com.example.clone", Version: "1.0.0"}},
		Metadata: map[string]string{"preserved": "yes"},
	}
	if err := SealReleaseActivationEvidence(&record); err != nil {
		t.Fatal(err)
	}
	stored, err := store.PutPlugin(registryTestContext(), record, PutOptions{Now: time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}
