package host

import (
	"context"
	"regexp"
	"sync"

	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

var packageTransferIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,96}$`)

type PackageTransferRequest struct {
	TransferID string `json:"transfer_id"`
}
type PackageTransferProgress struct {
	Stage         string `json:"stage"`
	ReceivedBytes int64  `json:"received_bytes"`
	TotalBytes    int64  `json:"total_bytes,omitempty"`
}

type transferKey struct {
	scope sessionctx.SessionScope
	id    string
}
type packageTransfer struct {
	mu       sync.Mutex
	progress PackageTransferProgress
	cancel   context.CancelFunc
}

func (transfer *packageTransfer) observe(received, total int64) {
	transfer.mu.Lock()
	transfer.progress = PackageTransferProgress{Stage: "downloading", ReceivedBytes: received, TotalBytes: total}
	transfer.mu.Unlock()
}

func (store *externalPackageInspectionStore) beginTransfer(ctx context.Context, scope sessionctx.SessionScope, id string) (context.Context, *packageTransfer, func(), error) {
	if !packageTransferIDPattern.MatchString(id) {
		return nil, nil, nil, ErrExternalPackageRequestInvalid
	}
	key := transferKey{scope, id}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.transfers[key] != nil {
		return nil, nil, nil, ErrExternalPackageInstallInProgress
	}
	ctx, cancel := context.WithCancel(ctx)
	transfer := &packageTransfer{progress: PackageTransferProgress{Stage: "connecting"}, cancel: cancel}
	store.transfers[key] = transfer
	return ctx, transfer, func() { cancel(); store.mu.Lock(); delete(store.transfers, key); store.mu.Unlock() }, nil
}

func (store *externalPackageInspectionStore) verifyingTransfer(scope sessionctx.SessionScope, id string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if transfer := store.transfers[transferKey{scope, id}]; transfer != nil {
		transfer.mu.Lock()
		transfer.progress.Stage = "verifying"
		transfer.mu.Unlock()
	}
}

func (h *Host) PackageTransferProgress(ctx context.Context, req PackageTransferRequest) (PackageTransferProgress, error) {
	return h.accessPackageTransfer(ctx, req, false)
}

func (h *Host) CancelPackageTransfer(ctx context.Context, req PackageTransferRequest) (PackageTransferProgress, error) {
	return h.accessPackageTransfer(ctx, req, true)
}

func (h *Host) accessPackageTransfer(ctx context.Context, req PackageTransferRequest, cancel bool) (PackageTransferProgress, error) {
	if !packageTransferIDPattern.MatchString(req.TransferID) {
		return PackageTransferProgress{}, ErrExternalPackageRequestInvalid
	}
	release, err := h.ensureOpen()
	if err != nil {
		return PackageTransferProgress{}, err
	}
	defer release()
	if err = h.requireFeature(FeatureExternalPackage); err != nil {
		return PackageTransferProgress{}, err
	}
	session, err := requireUserSession(ctx)
	if err != nil {
		return PackageTransferProgress{}, err
	}
	scope, err := session.SessionScope()
	if err != nil {
		return PackageTransferProgress{}, err
	}
	if _, err = h.authorizeManagementSession(ctx, session, ManagementActionInspectExternalPackage, scopedAuthorizationTargetOrCollection(ResourcePlugin, "", sessionctx.ScopeEnvironment)); err != nil {
		return PackageTransferProgress{}, err
	}
	store := h.externalInspections
	store.mu.Lock()
	defer store.mu.Unlock()
	transfer := store.transfers[transferKey{scope, req.TransferID}]
	if transfer == nil {
		return PackageTransferProgress{Stage: "inactive"}, nil
	}
	transfer.mu.Lock()
	defer transfer.mu.Unlock()
	if cancel {
		transfer.cancel()
	}
	return transfer.progress, nil
}
