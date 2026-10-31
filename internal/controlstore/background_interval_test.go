package controlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func installIntervalRecord(t *testing.T, s *Store, owner, instance string) registry.PluginRecord {
	t.Helper()
	ctx := pluginDataCatalogContext(owner, "user")
	record := putPluginDataCatalogRecord(t, s, ctx, instance)
	record.Manifest.Background = &manifest.BackgroundSpec{Strategy: manifest.BackgroundInterval, WorkerID: "worker", Method: "refresh", IntervalMS: 1000, MaxRuntimeMS: 100}
	record.Manifest.API.RequiredFeatures = []manifest.FeatureID{manifest.FeatureBackgroundMethod, manifest.FeatureBackgroundInterval}
	record.Manifest.Workers = []manifest.WorkerSpec{{WorkerID: "worker", Artifact: "workers/main.wasm", Mode: manifest.WorkerModeJob, Scope: "environment", MemoryLimitBytes: 16777216}}
	record.Manifest.Methods = []manifest.MethodSpec{{Method: "refresh", Execution: manifest.MethodExecutionSync, Effect: manifest.MethodEffectRead, Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "worker"}, RequestSchema: map[string]any{"type": "object", "additionalProperties": false}, ResponseSchema: map[string]any{"type": "object", "additionalProperties": false}}}
	record.CanonicalManifest = ""
	raw, err := encodeRegistryPluginRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE plugin_records SET record_json=? WHERE owner_env_hash=? AND plugin_instance_id=?", string(raw), owner, instance); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestIntervalClaimIsAtomicAndRecoveryNeverReplays(t *testing.T) {
	ctx := context.Background()
	s := openPluginDataCatalogStore(t)
	defer s.Close()
	installIntervalRecord(t, s, "owner", "instance")
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	if err := s.ReconcileIntervals(ctx, now); err != nil {
		t.Fatal(err)
	}
	plans, err := s.IntervalPlans(ctx)
	if err != nil || len(plans) != 1 {
		t.Fatalf("plans=%v err=%v", plans, err)
	}
	if _, claimed, err := s.ClaimInterval(ctx, plans[0], now); err != nil || claimed {
		t.Fatalf("early claim=%v %v", claimed, err)
	}
	claims := make(chan IntervalPlan, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, ok, err := s.ClaimInterval(ctx, plans[0], now.Add(time.Second))
			if err != nil {
				t.Error(err)
			}
			if ok {
				claims <- p
			}
		}()
	}
	wg.Wait()
	close(claims)
	var claim IntervalPlan
	count := 0
	for p := range claims {
		claim = p
		count++
	}
	if count != 1 {
		t.Fatalf("claims=%d", count)
	}
	recovered := now.Add(time.Hour)
	if err := s.RecoverIntervalClaims(ctx, recovered); err != nil {
		t.Fatal(err)
	}
	plans, err = s.IntervalPlans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if plans[0].Outcome != "unknown" || plans[0].ClaimID != "" || !plans[0].NextRun.Equal(recovered.Add(time.Second)) {
		t.Fatalf("recovered=%+v", plans[0])
	}
	if ok, err := s.FinishInterval(ctx, claim, recovered, "success"); err != nil || ok {
		t.Fatalf("stale completion=%v %v", ok, err)
	}
	if _, ok, err := s.ClaimInterval(ctx, plans[0], recovered); err != nil || ok {
		t.Fatalf("replayed=%v %v", ok, err)
	}
	next, ok, err := s.ClaimInterval(ctx, plans[0], recovered.Add(time.Second))
	if err != nil || !ok || next.ClaimID == claim.ClaimID {
		t.Fatalf("next=%+v %v %v", next, ok, err)
	}
	finished := recovered.Add(10 * time.Second)
	if ok, err := s.FinishInterval(ctx, next, finished, "success"); err != nil || !ok {
		t.Fatalf("finish=%v %v", ok, err)
	}
	plans, err = s.IntervalPlans(ctx)
	if err != nil || !plans[0].NextRun.Equal(finished.Add(time.Second)) {
		t.Fatalf("missed periods not coalesced: %+v %v", plans, err)
	}
}

func TestIntervalRevisionAndOwnerIsolation(t *testing.T) {
	ctx := context.Background()
	s := openPluginDataCatalogStore(t)
	defer s.Close()
	a := installIntervalRecord(t, s, "owner-a", "same")
	installIntervalRecord(t, s, "owner-b", "same")
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	if err := s.ReconcileIntervals(ctx, now); err != nil {
		t.Fatal(err)
	}
	plans, err := s.IntervalPlans(ctx)
	if err != nil || len(plans) != 2 {
		t.Fatalf("plans=%v %v", plans, err)
	}
	claim, ok, err := s.ClaimInterval(ctx, plans[0], now.Add(time.Second))
	if err != nil || !ok {
		t.Fatal("claim", err)
	}
	a.EnableState = registry.EnableDisabledByUser
	if _, err := s.Registry().PutPlugin(pluginDataCatalogContext("owner-a", "user"), "owner-a", a, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileIntervals(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.FinishInterval(ctx, claim, now.Add(2*time.Second), "success"); err != nil || ok {
		t.Fatalf("old completion changed state=%v %v", ok, err)
	}
	if _, ok, err := s.ClaimInterval(ctx, plans[0], now.Add(2*time.Second)); err != nil || ok {
		t.Fatalf("disabled claim=%v %v", ok, err)
	}
	if _, ok, err := s.ClaimInterval(ctx, plans[1], now.Add(2*time.Second)); err != nil || !ok {
		t.Fatalf("sibling blocked=%v %v", ok, err)
	}
}

type interruptedIntervalMigration struct{ *sql.Tx }

func (q interruptedIntervalMigration) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if query == "UPDATE control_schema SET version=5 WHERE id=1 AND version=4" {
		return nil, errors.New("injected interruption")
	}
	return q.Tx.ExecContext(ctx, query, args...)
}

func TestIntervalMigrationPreservesReleasedSchemas(t *testing.T) {
	for _, version := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			db, path := pluginDataHistoricalDatabase(t, version)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			for round := range 2 {
				s, err := Open(context.Background(), Config{Path: path})
				if err != nil {
					t.Fatal(err)
				}
				var value string
				want := "original"
				if round == 1 {
					want = "updated"
				}
				if err := s.db.QueryRow("SELECT value_json FROM control_metadata WHERE key='upgrade-preserved'").Scan(&value); err != nil || value != want {
					t.Fatalf("metadata=%q %v", value, err)
				}
				if _, err := s.db.Exec("UPDATE control_metadata SET value_json='updated' WHERE key='upgrade-preserved'"); err != nil {
					t.Fatal(err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestIntervalMigrationInterruptionRollsBack(t *testing.T) {
	db, path := pluginDataHistoricalDatabase(t, 4)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateBackgroundIntervals(ctx, interruptedIntervalMigration{tx}); err == nil {
		t.Fatal("missing injected failure")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var version, count int
	if err := db.QueryRow("SELECT version FROM control_schema").Scan(&version); err != nil || version != 4 {
		t.Fatalf("version=%d %v", version, err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='background_intervals'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial schema=%d %v", count, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestIntervalMigrationRejectsDriftWithoutWriting(t *testing.T) {
	db, path := pluginDataHistoricalDatabase(t, 4)
	if _, err := db.Exec("CREATE TABLE background_intervals(unrecognized TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := Open(context.Background(), Config{Path: path}); err == nil {
		s.Close()
		t.Fatal("drift admitted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("unknown database changed")
	}
}

func TestIntervalClaimAndCompletionBindExactSchedule(t *testing.T) {
	ctx := context.Background()
	s := openPluginDataCatalogStore(t)
	defer s.Close()
	installIntervalRecord(t, s, "owner", "instance")
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	if err := s.ReconcileIntervals(ctx, now); err != nil {
		t.Fatal(err)
	}
	plans, err := s.IntervalPlans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*IntervalPlan){func(p *IntervalPlan) { p.IntervalMS++ }, func(p *IntervalPlan) { p.MaxRuntimeMS++ }, func(p *IntervalPlan) { p.NextRun = p.NextRun.Add(time.Second) }} {
		forged := plans[0]
		mutate(&forged)
		if _, ok, err := s.ClaimInterval(ctx, forged, now.Add(time.Minute)); err != nil || ok {
			t.Fatalf("changed schedule claimed: %v %v", ok, err)
		}
	}
	claim, ok, err := s.ClaimInterval(ctx, plans[0], now.Add(time.Second))
	if err != nil || !ok {
		t.Fatal("claim", err)
	}
	forged := claim
	forged.IntervalMS++
	if ok, err := s.FinishInterval(ctx, forged, now.Add(time.Second), "success"); err != nil || ok {
		t.Fatalf("changed completion accepted: %v %v", ok, err)
	}
	if ok, err := s.FinishInterval(ctx, claim, now.Add(time.Second), "success"); err != nil || !ok {
		t.Fatal("finish", err)
	}
	if _, ok, err := s.ClaimInterval(ctx, plans[0], now.Add(time.Minute)); err != nil || ok {
		t.Fatalf("old schedule reclaimed: %v %v", ok, err)
	}
}

func TestIntervalInvalidDurableClaimFailsWithoutRecoveryMutation(t *testing.T) {
	ctx := context.Background()
	s := openPluginDataCatalogStore(t)
	defer s.Close()
	installIntervalRecord(t, s, "owner", "instance")
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	if err := s.ReconcileIntervals(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE background_intervals SET claim_id='invalid',claimed_at=1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverIntervalClaims(ctx, now); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("invalid claim recovered: %v", err)
	}
	var claim string
	if err := s.db.QueryRow("SELECT claim_id FROM background_intervals").Scan(&claim); err != nil || claim != "invalid" {
		t.Fatalf("invalid state changed: %s %v", claim, err)
	}
}
