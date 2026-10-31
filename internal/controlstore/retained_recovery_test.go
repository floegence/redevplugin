package controlstore

import (
	"errors"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func TestRetainedRecoveryPreservesBothGenerations(t *testing.T) {
	ctx := pluginDataCatalogContext("env-recovery", "user-recovery")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	source := putPluginDataCatalogRecord(t, store, ctx, "source")
	target := putPluginDataCatalogRecord(t, store, ctx, "target")
	target, upgradeErr := store.Registry().PutPlugin(ctx, "env-recovery", pluginDataUpgradeRecord(t, target, "2.0.0"), time.Now().UTC())
	if upgradeErr != nil {
		t.Fatal(upgradeErr)
	}
	if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{PluginInstanceID: source.PluginInstanceID, ExpectedManagementRevision: source.ManagementRevision, Now: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	target.EnableState = registry.EnableDisabledByUser
	var err error
	target, err = store.Registry().PutPlugin(ctx, "env-recovery", target, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	retained, _, err := store.GetBinding(ctx, source.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	active, _, err := store.GetBinding(ctx, target.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := plugindata.ShapeFromManifest(target.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	plan := plugindata.RetainedRecoveryPlan{OwnerEnvHash: "env-recovery", Source: retained, Target: active, TargetManagementRevision: target.ManagementRevision, TargetActiveFingerprint: target.ActiveFingerprint, RetainedAt: time.Now().UTC()}
	result, err := store.CommitRetainedRecovery(ctx, plan, shape)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := store.Registry().GetPlugin(ctx, "env-recovery", target.PluginInstanceID)
	if err != nil || len(restored.VersionHistory) != 1 || restored.VersionHistory[0].DataGenerationID != result.Active.GenerationID {
		t.Fatalf("restored version retains moved data authority: %v", err)
	}
	if result.Active.GenerationID != retained.GenerationID || result.Retained.GenerationID != active.GenerationID {
		t.Fatalf("recovery lost a generation: %#v", result)
	}
	if result.Active.PluginInstanceID != target.PluginInstanceID || result.Retained.PluginInstanceID != source.PluginInstanceID {
		t.Fatalf("unexpected binding identities: %#v", result)
	}
	if result.Active.Revision != active.Revision+1 || result.Retained.Revision != retained.Revision+1 {
		t.Fatalf("revisions must advance per binding: %#v", result)
	}
	if _, err := store.CommitRetainedRecovery(ctx, plan, shape); err == nil {
		t.Fatal("stale plan must not reverse the swap")
	}
}

func TestRetainedRecoveryRollsBackBothBindingsAndRecord(t *testing.T) {
	ctx := pluginDataCatalogContext("env-rollback", "user")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	source := putPluginDataCatalogRecord(t, store, ctx, "source")
	target := putPluginDataCatalogRecord(t, store, ctx, "target")
	if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{PluginInstanceID: source.PluginInstanceID, ExpectedManagementRevision: source.ManagementRevision, Now: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	target.EnableState = registry.EnableDisabledByUser
	target, err := store.Registry().PutPlugin(ctx, "env-rollback", target, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	sourceBinding, _, err := store.GetBinding(ctx, source.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	targetBinding, _, err := store.GetBinding(ctx, target.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := plugindata.ShapeFromManifest(target.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	plan := plugindata.RetainedRecoveryPlan{OwnerEnvHash: "env-rollback", Source: sourceBinding, Target: targetBinding, TargetManagementRevision: target.ManagementRevision, TargetActiveFingerprint: target.ActiveFingerprint, RetainedAt: time.Now().UTC()}
	if _, err := store.db.Exec("CREATE TRIGGER fail_recovery_target BEFORE UPDATE ON plugin_data_bindings WHEN NEW.plugin_instance_id='target' BEGIN SELECT RAISE(ABORT, 'recovery interruption'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitRetainedRecovery(ctx, plan, shape); err == nil {
		t.Fatal("expected injected interruption")
	}
	for _, expected := range []plugindata.Binding{sourceBinding, targetBinding} {
		actual, found, err := store.GetBinding(ctx, expected.PluginInstanceID)
		if err != nil || !found || !plugindata.SameBinding(actual, expected) {
			t.Fatalf("binding changed after rollback: %#v %v", actual, err)
		}
	}
	actual, err := store.Registry().GetPlugin(ctx, "env-rollback", target.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if actual.ManagementRevision != target.ManagementRevision || actual.RevokeEpoch != target.RevokeEpoch {
		t.Fatal("record changed after rollback")
	}
	if _, err := store.db.Exec("DROP TRIGGER fail_recovery_target"); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*plugindata.RetainedRecoveryPlan){"owner": func(p *plugindata.RetainedRecoveryPlan) { p.OwnerEnvHash = "other" }, "source revision": func(p *plugindata.RetainedRecoveryPlan) { p.Source.Revision++ }, "target revision": func(p *plugindata.RetainedRecoveryPlan) { p.Target.Revision++ }, "fingerprint": func(p *plugindata.RetainedRecoveryPlan) { p.TargetActiveFingerprint = "different" }, "management revision": func(p *plugindata.RetainedRecoveryPlan) { p.TargetManagementRevision++ }} {
		t.Run(name, func(t *testing.T) {
			changed := plan
			change(&changed)
			if _, err := store.CommitRetainedRecovery(ctx, changed, shape); err == nil {
				t.Fatal("accepted stale or foreign plan")
			}
		})
	}
	if _, err := store.CommitRetainedRecovery(ctx, plan, shape); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedRecoveryConcurrentCommitHasOneWinner(t *testing.T) {
	ctx := pluginDataCatalogContext("env-concurrent", "user")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	source := putPluginDataCatalogRecord(t, store, ctx, "source")
	target := putPluginDataCatalogRecord(t, store, ctx, "target")
	if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{PluginInstanceID: source.PluginInstanceID, ExpectedManagementRevision: source.ManagementRevision, Now: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	target.EnableState = registry.EnableDisabledByUser
	target, err := store.Registry().PutPlugin(ctx, "env-concurrent", target, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	sourceBinding, _, err := store.GetBinding(ctx, source.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	targetBinding, _, err := store.GetBinding(ctx, target.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := plugindata.ShapeFromManifest(target.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	plan := plugindata.RetainedRecoveryPlan{OwnerEnvHash: "env-concurrent", Source: sourceBinding, Target: targetBinding, TargetManagementRevision: target.ManagementRevision, TargetActiveFingerprint: target.ActiveFingerprint, RetainedAt: time.Now().UTC()}
	start := make(chan struct{})
	done := make(chan error, 2)
	for range 2 {
		go func() { <-start; _, err := store.CommitRetainedRecovery(ctx, plan, shape); done <- err }()
	}
	close(start)
	success := 0
	for range 2 {
		if err := <-done; err == nil {
			success++
		} else if !errors.Is(err, plugindata.ErrRetainedRecoveryConflict) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("successful concurrent commits=%d", success)
	}
	if err := store.DeleteRetained(ctx, sourceBinding); !errors.Is(err, plugindata.ErrBindingConflict) {
		t.Fatalf("stale GC/delete removed replacement retained data: %v", err)
	}
	active, found, err := store.GetBinding(ctx, target.PluginInstanceID)
	if err != nil || !found || active.GenerationID != sourceBinding.GenerationID {
		t.Fatalf("active=%#v %v", active, err)
	}
	retained, found, err := store.GetBinding(ctx, source.PluginInstanceID)
	if err != nil || !found || retained.GenerationID != targetBinding.GenerationID {
		t.Fatalf("retained=%#v %v", retained, err)
	}
}

func TestRetainedRecoveryRejectsExpiredSourceWithoutMutation(t *testing.T) {
	ctx := pluginDataCatalogContext("env-expired", "user")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	source := putPluginDataCatalogRecord(t, store, ctx, "source")
	target := putPluginDataCatalogRecord(t, store, ctx, "target")
	retainedAt := time.Now().UTC().Add(-2 * time.Hour)
	expiry := retainedAt.Add(time.Hour)
	if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{PluginInstanceID: source.PluginInstanceID, ExpectedManagementRevision: source.ManagementRevision, Now: retainedAt, RetainUntil: &expiry}); err != nil {
		t.Fatal(err)
	}
	target.EnableState = registry.EnableDisabledByUser
	target, err := store.Registry().PutPlugin(ctx, "env-expired", target, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	sourceBinding, _, err := store.GetBinding(ctx, source.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	targetBinding, _, err := store.GetBinding(ctx, target.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := plugindata.ShapeFromManifest(target.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	plan := plugindata.RetainedRecoveryPlan{OwnerEnvHash: "env-expired", Source: sourceBinding, Target: targetBinding, TargetManagementRevision: target.ManagementRevision, TargetActiveFingerprint: target.ActiveFingerprint, RetainedAt: time.Now().UTC()}
	if _, err := store.CommitRetainedRecovery(ctx, plan, shape); !errors.Is(err, plugindata.ErrRetainedRecoveryConflict) {
		t.Fatalf("expired source: %v", err)
	}
	actual, _, err := store.GetBinding(ctx, source.PluginInstanceID)
	if err != nil || !plugindata.SameBinding(actual, sourceBinding) {
		t.Fatal("expired source changed")
	}
	actual, _, err = store.GetBinding(ctx, target.PluginInstanceID)
	if err != nil || !plugindata.SameBinding(actual, targetBinding) {
		t.Fatal("target changed")
	}
}

func TestRetainedRecoveryCandidatesFilterIdentityShapeExpiryAndOwner(t *testing.T) {
	ctx := pluginDataCatalogContext("env-discovery", "user")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	target := putPluginDataCatalogRecord(t, store, ctx, "target")
	now := time.Now().UTC()
	for index, id := range []string{"first", "second", "publisher", "plugin", "shape", "expired", "active"} {
		record := putPluginDataCatalogRecord(t, store, ctx, id)
		if id == "active" {
			continue
		}
		if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{PluginInstanceID: id, ExpectedManagementRevision: record.ManagementRevision, Now: now.Add(time.Duration(index) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	// Alter individual catalog facts to exercise each discovery predicate.
	for _, query := range []string{
		"UPDATE plugin_records SET publisher_id='different' WHERE plugin_instance_id='publisher'",
		"UPDATE plugin_records SET plugin_id='different' WHERE plugin_instance_id='plugin'",
		"UPDATE plugin_data_bindings SET shape_hash='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE plugin_instance_id='shape'",
		"UPDATE plugin_data_bindings SET expires_at=1 WHERE plugin_instance_id='expired'",
	} {
		if _, err := store.db.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	candidates, err := store.ListRetainedRecoveryCandidates(ctx, target.PluginInstanceID, "")
	if err != nil || len(candidates) != 2 || candidates[0].PluginInstanceID != "second" || candidates[1].PluginInstanceID != "first" {
		t.Fatalf("candidates=%#v err=%v", candidates, err)
	}
	one, err := store.ListRetainedRecoveryCandidates(ctx, target.PluginInstanceID, "first")
	if err != nil || len(one) != 1 || one[0].PluginInstanceID != "first" {
		t.Fatalf("exact source=%#v err=%v", one, err)
	}
	foreign := pluginDataCatalogContext("other-environment", "user")
	if rows, err := store.ListRetainedRecoveryCandidates(foreign, target.PluginInstanceID, ""); err != nil || len(rows) != 0 {
		t.Fatalf("foreign candidates=%#v err=%v", rows, err)
	}
	if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{PluginInstanceID: target.PluginInstanceID, ExpectedManagementRevision: target.ManagementRevision, Now: now}); err != nil {
		t.Fatal(err)
	}
	if rows, err := store.ListRetainedRecoveryCandidates(ctx, target.PluginInstanceID, ""); err != nil || len(rows) != 0 {
		t.Fatalf("deleted target candidates=%#v err=%v", rows, err)
	}
}
