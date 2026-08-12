package host

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/testsupport/releasetrustfixture"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/releasetrust"
)

func TestReleaseLeaseRecoveryRunsDifferentSourcesConcurrently(t *testing.T) {
	firstBinding, firstAuthorize, firstValidate := preparedLeaseFixture(t, "fixture_source_a")
	secondBinding, secondAuthorize, secondValidate := preparedLeaseFixture(t, "fixture_source_b")
	leases := newReleaseLeaseRegistry()
	entered := make(chan string, 2)
	release := make(chan struct{})
	done := make(chan error, 2)

	run := func(instanceID string, binding registry.ReleaseTrustBinding, validate func(releasetrust.ActivationLease) error, authorize func() (releasetrust.ActivationLease, error)) {
		go func() {
			done <- leases.ensure(context.Background(), instanceID, binding, validate, func() (releasetrust.ActivationLease, error) {
				entered <- binding.SourceID
				<-release
				return authorize()
			})
		}()
	}
	run("plugini_source_a", firstBinding, firstValidate, firstAuthorize)
	run("plugini_source_b", secondBinding, secondValidate, secondAuthorize)

	seen := map[string]bool{}
	deadline := time.NewTimer(200 * time.Millisecond)
	for len(seen) < 2 {
		select {
		case sourceID := <-entered:
			seen[sourceID] = true
		case <-deadline.C:
			close(release)
			for range 2 {
				<-done
			}
			t.Fatalf("lease recovery entered sources = %v, want both sources before either completes", seen)
		}
	}
	if !deadline.Stop() {
		<-deadline.C
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestReleaseLeaseRecoverySingleFlightsOneSourceChannel(t *testing.T) {
	binding, authorize, validate := preparedLeaseFixture(t, "fixture_shared_source")
	leases := newReleaseLeaseRegistry()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	done := make(chan error, 2)
	var calls atomic.Int32
	wrappedAuthorize := func() (releasetrust.ActivationLease, error) {
		calls.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return authorize()
	}
	for _, instanceID := range []string{"plugini_shared_a", "plugini_shared_b"} {
		go func() {
			done <- leases.ensure(context.Background(), instanceID, binding, validate, wrappedAuthorize)
		}()
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("lease recovery did not start")
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("authorization calls = %d, want one source/channel single-flight", calls.Load())
	}
}

func TestReleaseLeaseRecoveryWaiterHonorsItsOwnCancellation(t *testing.T) {
	binding, authorize, validate := preparedLeaseFixture(t, "fixture_cancel_source")
	leases := newReleaseLeaseRegistry()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- leases.ensure(context.Background(), "plugini_cancel_owner", binding, validate, func() (releasetrust.ActivationLease, error) {
			close(entered)
			<-release
			return authorize()
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("lease recovery did not start")
	}

	waiterCtx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		waiterDone <- leases.ensure(waiterCtx, "plugini_cancel_waiter", binding, validate, authorize)
	}()
	cancel()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter error = %v, want context.Canceled", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("same-source waiter did not honor its own cancellation")
	}
	if _, ok := leases.get("plugini_cancel_waiter", binding); ok {
		t.Fatal("canceled waiter published a plugin lease association")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestReleaseLeaseRecoveryFailureDoesNotPublishPartialEntry(t *testing.T) {
	binding, _, validate := preparedLeaseFixture(t, "fixture_failed_source")
	leases := newReleaseLeaseRegistry()
	wantErr := errors.New("fixture authorization failed")
	if err := leases.ensure(context.Background(), "plugini_failed", binding, validate, func() (releasetrust.ActivationLease, error) {
		return releasetrust.ActivationLease{}, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("ensure() error = %v, want %v", err, wantErr)
	}
	if _, ok := leases.get("plugini_failed", binding); ok {
		t.Fatal("failed recovery published a plugin lease association")
	}
}

func preparedLeaseFixture(t *testing.T, sourceID string) (
	registry.ReleaseTrustBinding,
	func() (releasetrust.ActivationLease, error),
	func(releasetrust.ActivationLease) error,
) {
	t.Helper()
	fixture := newHostReleaseTrustFixtureWithOptions(t, releasetrustfixture.Options{SourceID: sourceID})
	if err := fixture.ServiceSet.BindFenceCoordinator(hostReleaseTrustNoopFence{}); err != nil {
		t.Fatal(err)
	}
	prepared, err := fixture.ServiceSet.PrepareRelease(hostTestContext(), fixture.Identity)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := fixture.ServiceSet.VerifyReleaseMetadata(
		hostTestContext(), prepared, fixture.MetadataBytes, fixture.MetadataSignature,
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := fixture.ServiceSet.VerifyPackage(hostTestContext(), metadata, fixture.PackageSignature)
	if err != nil {
		t.Fatal(err)
	}
	return *releaseTrustBinding(verified), verified.AuthorizeActivation, fixture.ServiceSet.ValidateActivationLease
}

func TestRefreshEnabledPluginsPublishesFastPluginBeforeSlowPluginCompletes(t *testing.T) {
	ctx := hostTestContext()
	sink := newBlockingSurfaceSink("plugini_a_slow")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		surfaceCatalog: sink,
	})

	slow, err := ImportLocalPackageBytes(ctx, h, "plugini_a_slow", buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	fast, err := ImportLocalPackageBytes(ctx, h, "plugini_b_fast", buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []struct {
		instanceID string
		revision   uint64
	}{
		{slow.PluginInstanceID, slow.ManagementRevision},
		{fast.PluginInstanceID, fast.ManagementRevision},
	} {
		if _, err := h.EnablePlugin(ctx, EnableRequest{
			PluginInstanceID: record.instanceID, ExpectedManagementRevision: record.revision,
		}); err != nil {
			t.Fatal(err)
		}
	}
	sink.reset()
	sink.block("plugini_a_slow")
	refreshDone := make(chan []RefreshEnabledPluginResult, 1)
	go func() {
		results, err := h.RefreshEnabledPlugins(ctx)
		if err != nil {
			t.Errorf("RefreshEnabledPlugins() error = %v", err)
			return
		}
		refreshDone <- results
	}()

	fastReady := false
	select {
	case snapshot := <-sink.published:
		if snapshot.PluginInstanceID != "plugini_b_fast" {
			t.Fatalf("first refresh publication = %q, want fast plugin", snapshot.PluginInstanceID)
		}
		fastReady = true
	case <-time.After(150 * time.Millisecond):
	}

	sink.releaseSlow()
	select {
	case results := <-refreshDone:
		if len(results) != 2 {
			t.Fatalf("refresh results = %#v, want two plugins", results)
		}
		if results[0].PluginInstanceID != "plugini_a_slow" || results[1].PluginInstanceID != "plugini_b_fast" {
			t.Fatalf("refresh results are not stable sorted: %#v", results)
		}
	case <-time.After(time.Second):
		t.Fatal("RefreshEnabledPlugins did not finish after slow plugin was released")
	}
	if !fastReady {
		t.Fatal("fast plugin did not become ready while slow plugin was still recovering")
	}
}

func TestRefreshEnabledPluginsBoundsSlowPluginWithoutBlockingFastPlugin(t *testing.T) {
	ctx := hostTestContext()
	sink := newBlockingSurfaceSink("plugini_a_slow")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		surfaceCatalog: sink,
	})
	h.refreshPluginTimeout = 100 * time.Millisecond

	slow, err := ImportLocalPackageBytes(ctx, h, "plugini_a_slow", buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	fast, err := ImportLocalPackageBytes(ctx, h, "plugini_b_fast", buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []struct {
		instanceID string
		revision   uint64
	}{
		{slow.PluginInstanceID, slow.ManagementRevision},
		{fast.PluginInstanceID, fast.ManagementRevision},
	} {
		if _, err := h.EnablePlugin(ctx, EnableRequest{
			PluginInstanceID: record.instanceID, ExpectedManagementRevision: record.revision,
		}); err != nil {
			t.Fatal(err)
		}
	}
	sink.reset()
	sink.block("plugini_a_slow")
	refreshDone := make(chan []RefreshEnabledPluginResult, 1)
	go func() {
		results, err := h.RefreshEnabledPlugins(ctx)
		if err != nil {
			t.Errorf("RefreshEnabledPlugins() error = %v", err)
			return
		}
		refreshDone <- results
	}()
	select {
	case snapshot := <-sink.published:
		if snapshot.PluginInstanceID != "plugini_b_fast" {
			t.Fatalf("first refresh publication = %q, want fast plugin", snapshot.PluginInstanceID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("fast plugin did not publish before the slow plugin deadline")
	}
	select {
	case results := <-refreshDone:
		if len(results) != 2 || results[0].PluginInstanceID != "plugini_a_slow" || results[1].PluginInstanceID != "plugini_b_fast" {
			t.Fatalf("refresh results = %#v, want stable slow/fast order", results)
		}
		if results[0].Status != RefreshEnabledPluginStatusFailed || results[1].Status != RefreshEnabledPluginStatusRefreshed {
			t.Fatalf("refresh statuses = %#v, want slow failed and fast refreshed", results)
		}
		if results[0].Error == nil || results[0].Error.Reason != RefreshFailureReasonRecoveryTimeout {
			t.Fatalf("slow plugin failure = %#v, want recovery timeout", results[0])
		}
	case <-time.After(time.Second):
		t.Fatal("slow plugin was not bounded by its per-plugin deadline")
	}
}

type blockingSurfaceSink struct {
	mu        sync.Mutex
	blocked   map[string]bool
	release   chan struct{}
	published chan SurfaceSnapshot
}

func newBlockingSurfaceSink(pluginInstanceID string) *blockingSurfaceSink {
	sink := &blockingSurfaceSink{blocked: map[string]bool{}, published: make(chan SurfaceSnapshot, 16)}
	sink.blocked[pluginInstanceID] = false
	return sink
}

func (s *blockingSurfaceSink) PublishSurfaces(ctx context.Context, snapshot SurfaceSnapshot) error {
	s.mu.Lock()
	isBlocked := s.blocked[snapshot.PluginInstanceID]
	release := s.release
	s.mu.Unlock()
	if isBlocked {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.published <- snapshot
	return nil
}

func (s *blockingSurfaceSink) reset() {
	for {
		select {
		case <-s.published:
		default:
			return
		}
	}
}

func (s *blockingSurfaceSink) block(pluginInstanceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked[pluginInstanceID] = true
	s.release = make(chan struct{})
}

func (s *blockingSurfaceSink) releaseSlow() {
	s.mu.Lock()
	release := s.release
	s.mu.Unlock()
	close(release)
}
