package host

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

type onlineOnlyIntervalAuthorization struct{ backgroundCalls atomic.Int32 }

func (a *onlineOnlyIntervalAuthorization) Authorize(_ context.Context, req AuthorizationRequest) error {
	if req.Session.OwnerUserHash == backgroundOwnerUserScope {
		a.backgroundCalls.Add(1)
		return ErrActionDenied
	}
	return nil
}

func TestIntervalStorageDoesNotRequireOnlineManagementAuthorization(t *testing.T) {
	runtime := newRecordingRuntimeManager()
	runtime.result = capability.Result{Data: map[string]any{}}
	authorization := &onlineOnlyIntervalAuthorization{}
	policy := intervalPolicyFunc(func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error) { return PolicyAllow, nil })
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime, authorization: authorization, backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy})
	archive := intervalFixtureWith(t, func(doc map[string]any) {
		doc["storage"] = map[string]any{"stores": []any{map[string]any{"store_id": "counter", "kind": "sqlite", "scope": "environment", "quota_bytes": 1048576, "schema_version": 1}}}
		method := doc["methods"].([]any)[0].(map[string]any)
		method["broker_access"] = map[string]any{"storage": []any{map[string]any{"store_id": "counter", "operations": []string{"query"}}}}
	})
	record := installAndEnablePlugin(t, h, archive)
	claim := claimTestInterval(t, h, record)
	if outcome, err := h.runBackgroundInterval(context.Background(), claim); outcome != "success" || err != nil {
		t.Fatalf("interval outcome=%s error=%v; online management calls=%d", outcome, err, authorization.backgroundCalls.Load())
	}
	if authorization.backgroundCalls.Load() != 0 || runtime.calls != 1 {
		t.Fatalf("management=%d runtime=%d", authorization.backgroundCalls.Load(), runtime.calls)
	}
	method, _ := backgroundWorkerMethod(record.Manifest, record.Manifest.Background.WorkerID)
	session := backgroundSessionContext(backgroundOwner(record))
	request := MintStorageHandleGrantRequest{PluginInstanceID: record.PluginInstanceID, StoreID: "counter", RuntimeInstanceID: "runtime", RuntimeGenerationID: "generation", RuntimeShardID: "shard"}
	for _, test := range []struct {
		name   string
		change func(*controlstore.IntervalPlan, *sessionctx.Context, *MintStorageHandleGrantRequest)
	}{
		{"claim", func(p *controlstore.IntervalPlan, _ *sessionctx.Context, _ *MintStorageHandleGrantRequest) {
			p.ClaimID += "-stale"
		}},
		{"revision", func(p *controlstore.IntervalPlan, _ *sessionctx.Context, _ *MintStorageHandleGrantRequest) {
			p.RevokeEpoch++
		}},
		{"session", func(_ *controlstore.IntervalPlan, s *sessionctx.Context, _ *MintStorageHandleGrantRequest) {
			s.OwnerUserHash = "online-user"
		}},
		{"instance", func(_ *controlstore.IntervalPlan, _ *sessionctx.Context, r *MintStorageHandleGrantRequest) {
			r.PluginInstanceID = "sibling"
		}},
		{"store", func(_ *controlstore.IntervalPlan, _ *sessionctx.Context, r *MintStorageHandleGrantRequest) {
			r.StoreID = "undeclared"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, s, r := claim, session, request
			test.change(&p, &s, &r)
			ctx := context.WithValue(sessionctx.WithContext(context.Background(), s), intervalExecutionKey{}, p)
			if _, err := h.mintIntervalStorageHandleGrant(ctx, record, method, r); err == nil {
				t.Fatal("accepted mismatched background authority")
			}
		})
	}
	ctx := sessionctx.WithContext(context.Background(), session)
	if _, err := h.MintStorageHandleGrant(ctx, request); err == nil {
		t.Fatal("public management accepted a background session")
	}
	if _, err := h.mintIntervalStorageHandleGrant(ctx, record, method, request); err == nil {
		t.Fatal("internal storage grant accepted an unclaimed invocation")
	}
}

func TestIntervalFailureDiagnosticPersists(t *testing.T) {
	diagnostics := observability.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, diagnostics: diagnostics, backgroundRunnerFactory: NewBackgroundWorkerRunner})
	record := installAndEnablePlugin(t, h, intervalFixture(t))
	if err := h.controlStore.ReconcileIntervals(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := h.backgroundIntervals.tick(context.Background(), time.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	waitForBackgroundDiagnostic(t, diagnostics, record.PluginInstanceID, record.OwnerEnvHash)
}
