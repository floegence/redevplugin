package host

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/redevplugin/pkg/registry"
)

type failingReleaseInstallProgressRegistry struct {
	registry.Store
	err error
}

func (store failingReleaseInstallProgressRegistry) UpdateReleaseInstallOperation(context.Context, registry.UpdateReleaseInstallOperationRequest) (registry.ReleaseInstallOperation, error) {
	return registry.ReleaseInstallOperation{}, store.err
}

func TestReleaseInstallProgressTrackerPreservesPersistenceFailure(t *testing.T) {
	persistErr := errors.New("operation journal unavailable")
	h := &Host{adapters: normalizedAdapters{Registry: failingReleaseInstallProgressRegistry{Store: registry.NewMemoryStore(), err: persistErr}}}
	tracker := &releaseInstallProgressTracker{
		host: h,
		ctx:  context.Background(),
		current: registry.ReleaseInstallOperation{
			OperationID: "operation_install_example", Revision: 1,
		},
	}

	tracker.observe(ReleaseArtifactProgress{Phase: "download", ArtifactRole: "package", Completed: 1, Total: 2, Attempt: 1})
	operation, err := tracker.snapshot()
	if operation.OperationID != "operation_install_example" || !errors.Is(err, persistErr) {
		t.Fatalf("snapshot = %#v, %v; want original operation and persistence error", operation, err)
	}
}
