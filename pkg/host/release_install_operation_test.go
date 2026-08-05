package host

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/releasetrust"
	"github.com/floegence/redevplugin/pkg/security"
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

func TestReleaseInstallFailureClassifiesReleaseTrustErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code security.ErrorCode
	}{
		{name: "verification", err: releasetrust.ErrReleaseTrustVerification, code: security.ErrReleaseRefVerificationFailed},
		{name: "expired", err: releasetrust.ErrReleaseTrustExpired, code: security.ErrReleaseRefVerificationFailed},
		{name: "rollback", err: releasetrust.ErrReleaseTrustRollback, code: security.ErrReleaseRefVerificationFailed},
		{name: "revoked", err: releasetrust.ErrReleaseTrustRevoked, code: security.ErrReleaseRefVerificationFailed},
		{name: "policy", err: releasetrust.ErrReleasePolicyDenied, code: security.ErrReleaseRefPolicyDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			boundaryErr := releaseTrustBoundaryError(test.err)
			if code := releaseInstallFailureCode(boundaryErr); code != string(test.code) {
				t.Fatalf("releaseInstallFailureCode() = %q, want %q", code, test.code)
			}
			if releaseInstallFailureRetryable(boundaryErr) {
				t.Fatal("release trust failure was marked retryable")
			}
		})
	}
}

func TestReleaseTrustBoundaryPreservesTransportAndDeadlineIdentity(t *testing.T) {
	networkErr := externalsource.NewHTTPStatusError("fetch", "https://example.test/asset", 503, 0)
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "deadline", err: errors.Join(releasetrust.ErrReleaseTrustVerification, context.DeadlineExceeded), want: context.DeadlineExceeded},
		{name: "network", err: errors.Join(releasetrust.ErrReleaseTrustVerification, networkErr), want: networkErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := releaseTrustBoundaryError(test.err)
			if !errors.Is(got, test.want) {
				t.Fatalf("releaseTrustBoundaryError() = %v, want identity %v", got, test.want)
			}
		})
	}
}
