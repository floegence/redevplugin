package host

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestRetainedRecoveryPreservesTargetDataAndReconcilesWithoutReplay(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recovery-root")
	opts := testHostOptions{developerMode: true, localGenerated: true, stateRoot: root}
	h, _, _ := newTestHostWithOptions(t, opts)
	ctx := hostTestContext()
	pkg := buildWorkerStorageFixturePackage(t)
	source, err := ImportLocalPackageBytes(ctx, h, "recovery_source", pkg)
	if err != nil {
		t.Fatal(err)
	}
	target, err := ImportLocalPackageBytes(ctx, h, "recovery_target", pkg)
	if err != nil {
		t.Fatal(err)
	}
	for id, value := range map[string]string{source.PluginInstanceID: "retained content", target.PluginInstanceID: "target content"} {
		_, err := h.WritePluginDataFile(ctx, WritePluginDataFileRequest{PluginInstanceID: id, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "notes.txt", Data: []byte(value)})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, ExpectedManagementRevision: source.ManagementRevision}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.InspectRetainedRecovery(ctx, InspectRetainedRecoveryRequest{SourcePluginInstanceID: source.PluginInstanceID, TargetPluginInstanceID: target.PluginInstanceID}); !errors.Is(err, plugindata.ErrBindingConflict) {
		t.Fatalf("enabled target: %v", err)
	}
	if _, err := h.DisablePlugin(ctx, DisableRequest{PluginInstanceID: target.PluginInstanceID, ExpectedManagementRevision: target.ManagementRevision}); err != nil {
		t.Fatal(err)
	}
	candidates, err := h.ListRetainedData(ctx, ListRetainedDataRequest{TargetPluginInstanceID: target.PluginInstanceID})
	if err != nil || len(candidates) != 1 || candidates[0].PluginInstanceID != source.PluginInstanceID {
		t.Fatalf("recovery candidates = %#v, %v", candidates, err)
	}
	filtered, err := h.ListRetainedData(ctx, ListRetainedDataRequest{PluginInstanceID: "unrelated_source", TargetPluginInstanceID: target.PluginInstanceID})
	if err != nil || len(filtered) != 0 {
		t.Fatalf("filtered recovery candidates = %#v, %v", filtered, err)
	}
	plan, err := h.InspectRetainedRecovery(ctx, InspectRetainedRecoveryRequest{SourcePluginInstanceID: source.PluginInstanceID, TargetPluginInstanceID: target.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := h.GetRetainedRecoveryStatus(ctx, plan)
	if err != nil || pending.State != "pending" {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
	changed := plan
	changed.Plan.TargetActiveFingerprint += "tampered"
	if _, err := h.CommitRetainedRecovery(ctx, changed); !errors.Is(err, plugindata.ErrBindingConflict) {
		t.Fatalf("changed plan: %v", err)
	}
	session, _ := sessionctx.FromContext(ctx)
	session.OwnerUserHash = "different_user"
	if _, err := h.CommitRetainedRecovery(sessionctx.WithContext(ctx, session), plan); !errors.Is(err, plugindata.ErrBindingConflict) {
		t.Fatalf("wrong owner: %v", err)
	}
	session.OwnerEnvHash = "different_environment"
	if _, err := h.CommitRetainedRecovery(sessionctx.WithContext(ctx, session), plan); !errors.Is(err, plugindata.ErrBindingConflict) {
		t.Fatalf("wrong environment: %v", err)
	}
	beforeGrants, err := h.ListPermissionGrants(ctx, ListPermissionGrantsRequest{PluginInstanceID: target.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.CommitRetainedRecovery(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	afterGrants, err := h.ListPermissionGrants(ctx, ListPermissionGrantsRequest{PluginInstanceID: target.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(beforeGrants) != len(afterGrants) {
		t.Fatal("recovery changed permission grants")
	}
	if result.Active.GenerationID != plan.Plan.Source.GenerationID || result.Retained.GenerationID != plan.Plan.Target.GenerationID {
		t.Fatalf("lost generation: %#v", result)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	h, _, _ = newTestHostWithOptions(t, opts)
	applied, err := h.GetRetainedRecoveryStatus(ctx, plan)
	if err != nil || applied.State != "applied" {
		t.Fatalf("applied = %#v, %v", applied, err)
	}
	if _, err := h.CommitRetainedRecovery(ctx, plan); !errors.Is(err, plugindata.ErrBindingConflict) {
		t.Fatalf("replayed commit: %v", err)
	}
	if _, err := ImportLocalPackageBytes(ctx, h, source.PluginInstanceID, pkg); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{source.PluginInstanceID: "target content", target.PluginInstanceID: "retained content"} {
		read, err := h.ReadPluginDataFile(ctx, ReadPluginDataFileRequest{PluginInstanceID: id, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "notes.txt", MaxBytes: 1024})
		if err != nil {
			t.Fatal(err)
		}
		if string(read.Data) != want {
			t.Fatalf("%s: %q, want %q", id, read.Data, want)
		}
	}
	record, err := h.getPluginRecord(ctx, target.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if string(record.EnableState) != "disabled_by_user" {
		t.Fatalf("recovery enabled the target: %#v", record)
	}
}

func TestRetainedRecoveryDiscoveryAuthorizesTargetBeforeReading(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	authorization := &recordingAuthorizationAdapter{err: ErrActionDenied}
	h.adapters.Authorization = authorization
	_, err := h.ListRetainedData(hostTestContext(), ListRetainedDataRequest{TargetPluginInstanceID: " target "})
	if !errors.Is(err, ErrActionDenied) || len(authorization.requests) != 1 {
		t.Fatalf("authorization=%#v err=%v", authorization.requests, err)
	}
	request := authorization.requests[0]
	if request.Target.Kind != ResourceRetainedData || !request.Target.Collection || len(request.RelatedTargets) != 1 || request.RelatedTargets[0].ID != "target" || request.RelatedTargets[0].Kind != ResourcePlugin || request.RelatedTargets[0].Scope == nil || request.RelatedTargets[0].Scope.OwnerEnvHash != "env_hash" {
		t.Fatalf("unexpected discovery authority: %#v", request)
	}
}
