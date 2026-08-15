package host

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/observability"
	"github.com/floegence/redevplugin/v2/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v2/pkg/sessionctx"
	"github.com/floegence/redevplugin/v2/pkg/sessionscope"
)

func TestCoreAdaptersDoNotExposeSessionLifecycleOwners(t *testing.T) {
	typeOfCore := reflect.TypeOf(CoreAdapters{})
	for _, forbidden := range []string{"SessionLifecycle", "SessionMaintenance"} {
		if _, ok := typeOfCore.FieldByName(forbidden); ok {
			t.Fatalf("CoreAdapters still exposes %s", forbidden)
		}
	}
}

func TestHostOwnedSessionCloseResumeAndFinalize(t *testing.T) {
	h := newSessionMaintenanceTestHost(t, filepath.Join(t.TempDir(), "state"))
	session := sessionctx.Context{
		OwnerSessionHash: "session", OwnerUserHash: "user",
		OwnerEnvHash: "env", SessionChannelIDHash: "channel",
	}
	result, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session, Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("CloseAuthenticatedSessionScope() error = %v", err)
	}
	if !result.Identity.Valid() || result.Status != SessionScopeTeardownComplete || !result.Teardown.Fenced || !result.Teardown.Complete {
		t.Fatalf("CloseAuthenticatedSessionScope() = %#v", result)
	}
	resumed, err := h.ResumeClosedSessionScopeTeardown(context.Background(), ResumeClosedSessionScopeTeardownRequest{Session: session, Identity: result.Identity})
	if err != nil || resumed.Status != SessionScopeTeardownComplete || !resumed.Identity.Matches(result.Identity) {
		t.Fatalf("ResumeClosedSessionScopeTeardown() = %#v, %v", resumed, err)
	}
	finalized, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{Session: session, Identity: result.Identity})
	if err != nil || finalized.Status != SessionScopeFinalized {
		t.Fatalf("FinalizeClosedSessionScope() = %#v, %v", finalized, err)
	}
	replayed, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{Session: session, Identity: result.Identity})
	if err != nil || replayed.Status != SessionScopeFinalizationAbsent {
		t.Fatalf("FinalizeClosedSessionScope(replay) = %#v, %v", replayed, err)
	}
}

func TestHostOwnedSessionIdentityBindsExactFourHashScope(t *testing.T) {
	h := newSessionMaintenanceTestHost(t, filepath.Join(t.TempDir(), "state"))
	session := sessionctx.Context{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	other := session
	other.SessionChannelIDHash = "other-channel"
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	otherScope, err := other.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.sessionTeardownIdentity(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	otherIdentity, err := h.sessionTeardownIdentity(context.Background(), otherScope)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Matches(otherIdentity) || identity.OperationID == otherIdentity.OperationID {
		t.Fatal("different session channel hashes derived the same teardown identity")
	}
	if _, err := h.ResumeClosedSessionScopeTeardown(context.Background(), ResumeClosedSessionScopeTeardownRequest{Session: other, Identity: identity}); !errors.Is(err, sessionscope.ErrTeardownIdentityMismatch) {
		t.Fatalf("cross-scope resume error = %v", err)
	}
}

func TestOpenRecoversHostOwnedIncompleteSessionFence(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state")
	h := newSessionMaintenanceTestHost(t, stateRoot)
	session := sessionctx.Context{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.sessionTeardownIdentity(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	teardown, _, err := h.sessionScopes.BeginTeardown(context.Background(), scope, identity, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := teardown.MarkIncomplete(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	teardown.Release()
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := newSessionMaintenanceTestHost(t, stateRoot)
	if _, err := reopened.sessionScopes.InspectRetained(context.Background(), scope); !errors.Is(err, sessionscope.ErrScopeNotFound) {
		t.Fatalf("retained fence after startup recovery error = %v", err)
	}
}

func TestHostOwnedSessionFinalizationSerializesConcurrentRetries(t *testing.T) {
	h := newSessionMaintenanceTestHost(t, filepath.Join(t.TempDir(), "state"))
	session := sessionctx.Context{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}

	const callers = 32
	results := make(chan SessionScopeFinalizationStatus, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{Session: session, Identity: closed.Identity})
			results <- result.Status
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("FinalizeClosedSessionScope() error = %v", err)
		}
	}
	finalized := 0
	absent := 0
	for status := range results {
		switch status {
		case SessionScopeFinalized:
			finalized++
		case SessionScopeFinalizationAbsent:
			absent++
		default:
			t.Fatalf("unexpected finalization status %q", status)
		}
	}
	if finalized != 1 || absent != callers-1 {
		t.Fatalf("finalization statuses: finalized=%d absent=%d", finalized, absent)
	}
}

func TestHostOwnedSessionFinalizationReusesFenceCapacity(t *testing.T) {
	h := newSessionMaintenanceTestHost(t, filepath.Join(t.TempDir(), "state"))
	for index := 0; index <= sessionscope.DefaultMaxScopes; index++ {
		suffix := fmt.Sprint(index)
		session := sessionctx.Context{
			OwnerSessionHash: "session_" + suffix, OwnerUserHash: "user_" + suffix,
			OwnerEnvHash: "env_" + suffix, SessionChannelIDHash: "channel_" + suffix,
		}
		closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
		if err != nil {
			t.Fatalf("CloseAuthenticatedSessionScope(%d) error = %v", index, err)
		}
		finalized, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{Session: session, Identity: closed.Identity})
		if err != nil || finalized.Status != SessionScopeFinalized {
			t.Fatalf("FinalizeClosedSessionScope(%d) = %#v, %v", index, finalized, err)
		}
	}
	if retained, err := h.sessionScopes.ListRetained(context.Background()); err != nil || len(retained) != 0 {
		t.Fatalf("remaining fences = %#v, %v", retained, err)
	}
}

func TestHostOwnedSessionMaintenanceAbsentIsNotHistoricalSuccess(t *testing.T) {
	h := newSessionMaintenanceTestHost(t, filepath.Join(t.TempDir(), "state"))
	session := sessionctx.Context{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.sessionTeardownIdentity(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := h.ResumeClosedSessionScopeTeardown(context.Background(), ResumeClosedSessionScopeTeardownRequest{Session: session, Identity: identity})
	if err != nil || resumed.Status != SessionScopeTeardownAbsent {
		t.Fatalf("ResumeClosedSessionScopeTeardown() = %#v, %v", resumed, err)
	}
	finalized, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{Session: session, Identity: identity})
	if err != nil || finalized.Status != SessionScopeFinalizationAbsent {
		t.Fatalf("FinalizeClosedSessionScope() = %#v, %v", finalized, err)
	}
}

func newSessionMaintenanceTestHost(t *testing.T, stateRoot string) *Host {
	t.Helper()
	events := observability.NewMemoryStore()
	h, err := Open(context.Background(), Config{
		StateRoot: stateRoot,
		Core: CoreAdapters{
			Policy: policyAdapter{decision: PolicyAllow}, Authorization: allowAuthorizationAdapter{},
			PackageTrustVerifier: &recordingPackageTrustVerifier{}, Audit: events, SecurityAudit: events,
			Diagnostics: events, SurfaceCatalog: &surfaceSink{}, Assets: pluginpkg.NewMemoryAssetStore(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}
