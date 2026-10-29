package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

var ErrFileResourceUnavailable = fmt.Errorf("%w: selected file resource is unavailable; select it again", os.ErrPermission)
var ErrFileSelectionCanceled = errors.New("file selection was canceled")

// FileSelectionAdapter provides product selection UI, never file authority.
// Paths cross only this trusted adapter boundary and are never serialized.
type FileSelectionAdapter interface {
	SelectFile(context.Context, FileSelectionRequest) (FileSelectionResult, error)
}
type FileSelectionRequest struct {
	Session   sessionctx.Context
	Plugin    PluginRef
	Kind      string
	Recursive bool
	Writable  bool
}
type FileSelectionResult struct {
	Path     string `json:"-"`
	Canceled bool
}
type FilesModule struct{ Picker FileSelectionAdapter }

type SelectFileResourceRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	Kind             string `json:"kind"`
	Recursive        bool   `json:"recursive"`
	Writable         bool   `json:"writable"`
}
type FileResourceReview struct {
	ReviewID          string    `json:"review_id"`
	PluginInstanceID  string    `json:"plugin_instance_id"`
	Name              string    `json:"name"`
	Kind              string    `json:"kind"`
	Recursive         bool      `json:"recursive"`
	Writable          bool      `json:"writable"`
	ReviewExpiresAt   time.Time `json:"review_expires_at"`
	ResourceExpiresAt time.Time `json:"resource_expires_at"`
}
type ApproveFileResourceRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	ReviewID         string `json:"review_id"`
}
type CancelFileResourceRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	ReviewID         string `json:"review_id"`
}
type ListFileResourcesRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
}
type RevokeFileResourceRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	ResourceID       string `json:"resource_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
}
type FileResource struct {
	ResourceID string    `json:"resource_id"`
	URI        string    `json:"uri"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Recursive  bool      `json:"recursive"`
	Writable   bool      `json:"writable"`
	Revision   uint64    `json:"revision"`
	ExpiresAt  time.Time `json:"expires_at"`
	Status     string    `json:"status"`
}

type fileResourceEvidence struct {
	Path      string                    `json:"path"`
	Identity  resourceio.ObjectIdentity `json:"identity"`
	Name      string                    `json:"name"`
	Kind      string                    `json:"kind"`
	Recursive bool                      `json:"recursive"`
	Writable  bool                      `json:"writable"`
}

func decodeFileResourceEvidence(raw json.RawMessage) (fileResourceEvidence, error) {
	var e fileResourceEvidence
	if err := validateRuntimeIOJSON(raw); err != nil {
		return e, ErrFileResourceUnavailable
	}
	if err := decodeRuntimeIOJSON(raw, &e); err != nil {
		return e, ErrFileResourceUnavailable
	}
	if !filepath.IsAbs(e.Path) || filepath.Clean(e.Path) != e.Path || e.Name != filepath.Base(e.Path) || e.Kind != "file" && e.Kind != "directory" || e.Kind == "file" && e.Recursive || e.Identity.Directory != (e.Kind == "directory") || e.Identity.Object == 0 || e.Identity.CreatedSeconds == 0 || e.Identity.CreatedNanos < 0 || e.Identity.CreatedNanos >= 1_000_000_000 {
		return e, ErrFileResourceUnavailable
	}
	return e, nil
}

type fileReview struct {
	surfaceID   string
	public      FileResourceReview
	owner       sessionctx.SessionScope
	expected    registry.AuthorizationRevisions
	fingerprint string
	evidence    fileResourceEvidence
	selection   *resourceio.Selection
}
type selectedFileAuthority struct {
	mu      sync.Mutex
	host    *Host
	picker  FileSelectionAdapter
	reviews map[string]*fileReview
	objects map[controlstore.SelectedResourceKey]*resourceio.Selection
	closed  bool
}

func newSelectedFileAuthority(h *Host, picker FileSelectionAdapter) *selectedFileAuthority {
	return &selectedFileAuthority{host: h, picker: picker, reviews: map[string]*fileReview{}, objects: map[controlstore.SelectedResourceKey]*resourceio.Selection{}}
}

func (a *selectedFileAuthority) reap(ctx context.Context, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, r := range a.reviews {
		if !r.public.ReviewExpiresAt.After(now) {
			_ = r.selection.Close()
			delete(a.reviews, id)
		}
	}
	for key, object := range a.objects {
		err := a.host.controlStore.WithSelectedResource(ctx, key, now, func(controlstore.SelectedResource) error { return object.Validate() })
		if err != nil {
			_ = object.Close()
			delete(a.objects, key)
		}
	}
}

func (a *selectedFileAuthority) revokePlugin(env, plugin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var err error
	for id, r := range a.reviews {
		if r.owner.OwnerEnvHash == env && r.public.PluginInstanceID == plugin {
			err = errors.Join(err, r.selection.Close())
			delete(a.reviews, id)
		}
	}
	for key, object := range a.objects {
		if key.OwnerEnvHash == env && key.PluginInstanceID == plugin {
			err = errors.Join(err, object.Close())
			delete(a.objects, key)
		}
	}
	return err
}

func (h *Host) startSelectedFileMaintenance() {
	// Maintenance lives until Host.Close, independently of finite startup jobs.
	h.selectedFilesWG.Add(1)
	go func() {
		defer h.selectedFilesWG.Done()
		ctx := h.lifecycleCtx
		timer := time.NewTicker(time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-timer.C:
				h.selectedFiles.reap(ctx, now)
			}
		}
	}()
}
func (a *selectedFileAuthority) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	var err error
	for id, r := range a.reviews {
		err = errors.Join(err, r.selection.Close())
		delete(a.reviews, id)
	}
	for key, s := range a.objects {
		err = errors.Join(err, s.Close())
		delete(a.objects, key)
	}
	return err
}

func (h *Host) fileResourceAction(ctx context.Context, action ManagementAction, id string) (context.Context, sessionctx.Context, func(), error) {
	release, err := h.ensureOpen()
	if err != nil {
		return ctx, sessionctx.Context{}, nil, err
	}
	authorized, err := h.authorizeManagement(ctx, action, scopedAuthorizationTarget(ResourcePlugin, id, sessionctx.ScopeEnvironment))
	if err != nil {
		release()
		return ctx, sessionctx.Context{}, nil, err
	}
	ctx, unreserve, err := h.reserveAuthorizedAction(ctx, authorized)
	if err != nil {
		release()
		return ctx, sessionctx.Context{}, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(h.lifecycleCtx, cancel)
	return ctx, authorized.session, func() { stop(); cancel(); unreserve(); release() }, nil
}
func (h *Host) fileResourceCeiling(ctx context.Context, id string, writable bool) (registry.PluginRecord, error) {
	record, err := h.getPluginRecord(ctx, id)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.canRun(ctx, record); err != nil {
		return registry.PluginRecord{}, err
	}
	if record.EnableState != registry.EnableEnabled {
		return registry.PluginRecord{}, ErrFileResourceUnavailable
	}
	permission := manifest.PermissionFSSelectedRead
	if writable {
		permission = manifest.PermissionFSSelectedWrite
	}
	declared := false
	for _, p := range record.Manifest.Permissions {
		if p == permission || !writable && p == manifest.PermissionFSSelectedWrite {
			declared = true
			permission = p
			break
		}
	}
	if !declared {
		return registry.PluginRecord{}, permissions.ErrPermissionDenied
	}
	snapshot, err := h.getAuthorizationSnapshot(ctx, id)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	policy, err := security.EvaluatePermissionCeiling(snapshot.Policy, id, []string{string(permission)})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if !policy.Allowed {
		return registry.PluginRecord{}, security.ErrPolicyDenied
	}
	return record, nil
}

func (h *Host) SelectFileResource(ctx context.Context, req SelectFileResourceRequest) (FileResourceReview, error) {
	ctx, session, release, err := h.fileResourceAction(ctx, ManagementActionSelectFileResource, req.PluginInstanceID)
	if err != nil {
		return FileResourceReview{}, err
	}
	defer release()
	if (req.Kind != "file" && req.Kind != "directory") || req.Kind == "file" && req.Recursive || !session.CanRead || req.Writable && !session.CanWrite {
		return FileResourceReview{}, permissions.ErrPermissionDenied
	}
	record, err := h.fileResourceCeiling(ctx, req.PluginInstanceID, req.Writable)
	if err != nil {
		return FileResourceReview{}, err
	}
	a := h.selectedFiles
	if a.picker == nil {
		return FileResourceReview{}, FeatureNotConfiguredError{Features: []Feature{FeatureFiles}}
	}
	selected, err := a.picker.SelectFile(ctx, FileSelectionRequest{Session: session, Plugin: pluginRefFromRecord(record), Kind: req.Kind, Recursive: req.Recursive, Writable: req.Writable})
	if ctx.Err() != nil {
		return FileResourceReview{}, ctx.Err()
	}
	if err != nil {
		return FileResourceReview{}, ErrFileResourceUnavailable
	}
	if selected.Canceled {
		return FileResourceReview{}, ErrFileSelectionCanceled
	}
	object, err := resourceio.OpenSelection(selected.Path, req.Recursive, req.Writable)
	if err != nil {
		return FileResourceReview{}, ErrFileResourceUnavailable
	}
	keep := false
	defer func() {
		if !keep {
			object.Close()
		}
	}()
	if object.Directory() != (req.Kind == "directory") {
		return FileResourceReview{}, ErrFileResourceUnavailable
	}
	identity, err := object.Identity()
	if err != nil {
		return FileResourceReview{}, ErrFileResourceUnavailable
	}
	id, err := randomWebToken()
	if err != nil {
		return FileResourceReview{}, err
	}
	scope, err := session.SessionScope()
	if err != nil {
		return FileResourceReview{}, err
	}
	now := time.Now().UTC()
	review := FileResourceReview{ReviewID: id, PluginInstanceID: record.PluginInstanceID, Name: object.Name(), Kind: req.Kind, Recursive: req.Recursive, Writable: req.Writable, ReviewExpiresAt: now.Add(5 * time.Minute), ResourceExpiresAt: now.Add(24 * time.Hour)}
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, r := range a.reviews {
		if !r.public.ReviewExpiresAt.After(now) {
			r.selection.Close()
			delete(a.reviews, key)
		}
	}
	if a.closed || len(a.reviews) >= 128 {
		return FileResourceReview{}, ErrFileResourceUnavailable
	}
	a.reviews[id] = &fileReview{public: review, owner: scope, expected: registry.AuthorizationRevisionsFromRecord(record), fingerprint: record.ActiveFingerprint, evidence: fileResourceEvidence{Path: selected.Path, Identity: identity, Name: object.Name(), Kind: req.Kind, Recursive: req.Recursive, Writable: req.Writable}, selection: object}
	keep = true
	return review, nil
}

func (h *Host) ApproveFileResource(ctx context.Context, req ApproveFileResourceRequest) (result FileResource, retErr error) {
	ctx, session, release, err := h.fileResourceAction(ctx, ManagementActionApproveFileResource, req.PluginInstanceID)
	if err != nil {
		return result, err
	}
	defer release()
	// canRun may revoke surfaces and selections; it must run outside their locks.
	if !h.featureConfigured(FeatureFiles) {
		return result, FeatureNotConfiguredError{Features: []Feature{FeatureFiles}}
	}
	record, err := h.getPluginRecord(ctx, req.PluginInstanceID)
	if err != nil {
		return result, err
	}
	if err := h.canRun(ctx, record); err != nil {
		return result, err
	}
	h.webSurfaces.fileMu.RLock()
	defer h.webSurfaces.fileMu.RUnlock()
	scope, _ := session.SessionScope()
	a := h.selectedFiles
	a.mu.Lock()
	defer a.mu.Unlock()
	review, ok := a.reviews[req.ReviewID]
	if !ok || a.closed || !review.owner.Matches(scope) || review.public.PluginInstanceID != req.PluginInstanceID || !review.public.ReviewExpiresAt.After(time.Now()) {
		return result, ErrFileResourceUnavailable
	}
	if review.surfaceID != "" && !h.liveFileSurface(review.surfaceID, req.PluginInstanceID, scope) {
		return result, ErrFileResourceUnavailable
	}
	if !session.CanRead || review.evidence.Writable && !session.CanWrite {
		return result, permissions.ErrPermissionDenied
	}
	if err := review.selection.Validate(); err != nil {
		return result, ErrFileResourceUnavailable
	}
	id, err := randomWebToken()
	if err != nil {
		return result, err
	}
	id = "selected-" + id
	raw, err := json.Marshal(review.evidence)
	if err != nil {
		return result, err
	}
	resource := controlstore.SelectedResource{OwnerEnvHash: scope.OwnerEnvHash, OwnerUserHash: scope.OwnerUserHash, PluginInstanceID: req.PluginInstanceID, ResourceID: id, ActiveFingerprint: review.fingerprint, RevokeEpoch: review.expected.RevokeEpoch, Revision: 1, ExpiresAt: review.public.ResourceExpiresAt.UnixNano(), RawJSON: raw}
	if len(a.objects) >= 1024 {
		return result, resourceio.ErrResourceLimit
	}
	audit, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.file_resource.approved", PluginInstanceID: req.PluginInstanceID})
	if err != nil {
		return result, err
	}
	defer func() { retErr = audit.complete(context.WithoutCancel(ctx), retErr) }()
	// A persistence attempt consumes this review, including an uncertain commit.
	// Query the resource inventory to reconcile; never issue another grant by replay.
	delete(a.reviews, req.ReviewID)
	if err := h.controlStore.CreateSelectedResource(ctx, resource, review.expected, time.Now()); err != nil {
		_ = review.selection.Close()
		if errors.Is(err, controlstore.ErrSelectedResourceLimit) {
			return result, resourceio.ErrResourceLimit
		}
		return result, err
	}
	a.objects[resource.Key()] = review.selection
	return projectFileResource(resource, review.evidence, time.Now()), nil
}

func (h *Host) CancelFileResource(ctx context.Context, req CancelFileResourceRequest) error {
	_, session, release, err := h.fileResourceAction(ctx, ManagementActionCancelFileResource, req.PluginInstanceID)
	if err != nil {
		return err
	}
	defer release()
	scope, _ := session.SessionScope()
	a := h.selectedFiles
	a.mu.Lock()
	defer a.mu.Unlock()
	review, ok := a.reviews[req.ReviewID]
	if !ok {
		return nil
	}
	if !review.owner.Matches(scope) || review.public.PluginInstanceID != req.PluginInstanceID {
		return ErrFileResourceUnavailable
	}
	delete(a.reviews, req.ReviewID)
	return review.selection.Close()
}
func (h *Host) ListFileResources(ctx context.Context, req ListFileResourcesRequest) ([]FileResource, error) {
	ctx, session, release, err := h.fileResourceAction(ctx, ManagementActionListFileResources, req.PluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer release()
	record, err := h.getPluginRecord(ctx, req.PluginInstanceID)
	if err != nil {
		return nil, err
	}
	stored, err := h.controlStore.ListSelectedResources(ctx, session.OwnerEnvHash, session.OwnerUserHash, req.PluginInstanceID)
	if err != nil {
		return nil, err
	}
	result := make([]FileResource, 0, len(stored))
	for _, r := range stored {
		e, err := decodeFileResourceEvidence(r.RawJSON)
		if err != nil {
			return nil, ErrFileResourceUnavailable
		}
		item := projectFileResource(r, e, time.Now())
		if r.ActiveFingerprint != record.ActiveFingerprint || r.RevokeEpoch != record.RevokeEpoch || record.EnableState != registry.EnableEnabled {
			item.Status = "unavailable"
		}
		if item.Status == "active" {
			object, err := resourceio.ValidateSelectionIdentity(e.Path, e.Recursive, e.Writable, e.Identity)
			if err != nil {
				item.Status = "unavailable"
			} else {
				_ = object.Close()
			}
		}
		result = append(result, item)
	}
	return result, nil
}
func projectFileResource(r controlstore.SelectedResource, e fileResourceEvidence, now time.Time) FileResource {
	status := "active"
	if r.RevokedAt != nil {
		status = "revoked"
	} else if r.ExpiresAt <= now.UnixNano() {
		status = "expired"
	}
	return FileResource{ResourceID: r.ResourceID, URI: (resourceio.URI{MountID: r.ResourceID, Path: "."}).String(), Name: e.Name, Kind: e.Kind, Recursive: e.Recursive, Writable: e.Writable, Revision: r.Revision, ExpiresAt: time.Unix(0, r.ExpiresAt).UTC(), Status: status}
}
func (h *Host) RevokeFileResource(ctx context.Context, req RevokeFileResourceRequest) (retErr error) {
	ctx, session, release, err := h.fileResourceAction(ctx, ManagementActionRevokeFileResource, req.PluginInstanceID)
	if err != nil {
		return err
	}
	defer release()
	audit, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.file_resource.revoked", PluginInstanceID: req.PluginInstanceID})
	if err != nil {
		return err
	}
	defer func() { retErr = audit.complete(context.WithoutCancel(ctx), retErr) }()
	key := controlstore.SelectedResourceKey{OwnerEnvHash: session.OwnerEnvHash, OwnerUserHash: session.OwnerUserHash, PluginInstanceID: req.PluginInstanceID, ResourceID: req.ResourceID}
	a := h.selectedFiles
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := h.controlStore.RevokeSelectedResource(ctx, key, req.ExpectedRevision, time.Now()); err != nil {
		return err
	}
	if object := a.objects[key]; object != nil {
		delete(a.objects, key)
		return mutation.Committed(object.Close())
	}
	return nil
}

func (a *selectedFileAuthority) WithSelection(ctx context.Context, inv resourceio.Invocation, uri resourceio.URI, write bool, use func(*resourceio.Selection) error) error {
	scope := sessionctx.ResourceScope{Kind: inv.Owner.Scope.Kind, OwnerEnvHash: inv.Owner.Session.OwnerEnvHash}
	if scope.Kind == sessionctx.ScopeUser {
		scope.OwnerUserHash = inv.Owner.Session.OwnerUserHash
	}
	if !scope.Matches(inv.Owner.Scope) || !inv.CanRead || write && !inv.CanWrite || write && !inv.Permissions[resourceio.PermissionFSSelectedWrite] || !write && !inv.Permissions[resourceio.PermissionFSSelectedRead] && !inv.Permissions[resourceio.PermissionFSSelectedWrite] {
		return ErrFileResourceUnavailable
	}
	held, alreadyReserved := ctx.Value(sessionReservationContextKey{}).(sessionReservationContext)
	if !alreadyReserved || held.host != a.host || held.scope != inv.Owner.Session {
		reservation, err := a.host.sessionScopes.Reserve(ctx, inv.Owner.Session)
		if err != nil {
			return ErrFileResourceUnavailable
		}
		defer reservation.Release()
	}
	key := controlstore.SelectedResourceKey{OwnerEnvHash: inv.Owner.Session.OwnerEnvHash, OwnerUserHash: inv.Owner.Session.OwnerUserHash, PluginInstanceID: inv.Owner.PluginInstanceID, ResourceID: uri.MountID}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrFileResourceUnavailable
	}
	err := a.host.controlStore.WithSelectedResource(ctx, key, time.Now(), func(r controlstore.SelectedResource) error {
		if r.ActiveFingerprint != inv.Owner.ActiveFingerprint || r.RevokeEpoch != inv.Owner.RevokeEpoch || r.CurrentManagementRevision != inv.Owner.ManagementRevision {
			return ErrFileResourceUnavailable
		}
		evidence, err := decodeFileResourceEvidence(r.RawJSON)
		if err != nil {
			return ErrFileResourceUnavailable
		}
		if write && !evidence.Writable {
			return os.ErrPermission
		}
		object := a.objects[key]
		if object == nil {
			if len(a.objects) >= 1024 {
				return resourceio.ErrResourceLimit
			}
			var err error
			object, err = resourceio.ValidateSelectionIdentity(evidence.Path, evidence.Recursive, evidence.Writable, evidence.Identity)
			if err != nil {
				return ErrFileResourceUnavailable
			}
			a.objects[key] = object
		}
		if err := object.Validate(); err != nil {
			_ = object.Close()
			delete(a.objects, key)
			return ErrFileResourceUnavailable
		}
		return use(object)
	})
	if errors.Is(err, controlstore.ErrRecordNotFound) || errors.Is(err, controlstore.ErrStateConflict) {
		if object := a.objects[key]; object != nil {
			_ = object.Close()
			delete(a.objects, key)
		}
		return ErrFileResourceUnavailable
	}
	return err
}
