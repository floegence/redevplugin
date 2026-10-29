package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

type selectedPickerFixture struct {
	path     string
	canceled bool
}

func TestSelectedFilesSurfaceHandlesAreWindowBound(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, filePicker: selectedPickerFixture{canceled: true}})
	installed := installAndEnablePlugin(t, h, buildSelectedFileFixture(t))
	session, _ := sessionctx.FromContext(hostTestContext())
	session.CanRead, session.CanWrite = true, true
	ctx := sessionctx.WithContext(context.Background(), session)
	path := filepath.Join(t.TempDir(), "document.txt")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	h.selectedFiles.picker = selectedPickerFixture{path: path}
	open := func(id string) (SurfaceFileRequest, bridge.SurfaceBootstrap) {
		t.Helper()
		now := time.Now()
		b, err := h.OpenSurface(ctx, OpenSurfaceRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceID: "lifecycle.view", SurfaceInstanceID: id, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.PrepareSurface(ctx, exchangeAssetTicketRequestForBootstrap(b, now)); err != nil {
			t.Fatal(err)
		}
		handshake := bridge.Handshake{PluginID: b.PluginID, SurfaceID: b.SurfaceID, SurfaceInstanceID: b.SurfaceInstanceID, ActiveFingerprint: b.ActiveFingerprint, BridgeNonce: b.BridgeNonce, AssetSessionNonce: b.AssetSessionNonce, ManagementRevision: b.ManagementRevision, RevokeEpoch: b.RevokeEpoch}
		channel := "bridge_" + id
		token, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{Handshake: handshake, BridgeChannelID: channel, HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, channel), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		return SurfaceFileRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: id, BridgeChannelID: channel, GatewayToken: token.GatewayToken}, b
	}
	first, b := open("surface_selected_first")
	second, _ := open("surface_selected_second")
	first.Operation, first.Arguments = "select", json.RawMessage(`{"kind":"file","recursive":false,"writable":true}`)
	choice, err := h.SurfaceFile(ctx, first)
	if err != nil || choice.Review == nil {
		t.Fatalf("select: %+v %v", choice, err)
	}
	grant, err := h.ApproveFileResource(ctx, ApproveFileResourceRequest{PluginInstanceID: installed.PluginInstanceID, ReviewID: choice.Review.ReviewID})
	if err != nil {
		t.Fatal(err)
	}
	first.Operation, first.Arguments = "fs.open", json.RawMessage(`{"uri":`+strconv.Quote(grant.URI)+`,"options":{"read":true,"write":true}}`)
	requestContext, cancel := context.WithCancel(ctx)
	handle, err := h.SurfaceFile(requestContext, first)
	cancel()
	if err != nil || handle.Handle == "" {
		t.Fatalf("open: %+v %v", handle, err)
	}
	first.Operation, first.Arguments = "read", json.RawMessage(`{"handle":`+strconv.Quote(handle.Handle)+`,"length":8}`)
	read, err := h.SurfaceFile(ctx, first)
	if err != nil || read.Data == nil || *read.Data != base64.StdEncoding.EncodeToString([]byte("original")) {
		t.Fatalf("read: %+v %v", read, err)
	}
	second.Operation, second.Arguments = first.Operation, first.Arguments
	if _, err := h.SurfaceFile(ctx, second); err == nil {
		t.Fatal("sibling reused file handle")
	}
	if err := h.DisposeSurface(ctx, DisposeSurfaceRequest{SurfaceInstanceID: b.SurfaceInstanceID, BridgeNonce: b.BridgeNonce, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SurfaceFile(ctx, first); err == nil {
		t.Fatal("closed surface read")
	}
	second.Operation, second.Arguments = "fs.open", json.RawMessage(`{"uri":`+strconv.Quote(grant.URI)+`,"options":{"read":true}}`)
	if _, err := h.SurfaceFile(ctx, second); err != nil {
		t.Fatalf("sibling lost resource: %v", err)
	}
	second.Operation, second.Arguments = "select", json.RawMessage(`{"kind":"file","writable":true}`)
	pending, err := h.SurfaceFile(ctx, second)
	if err != nil || pending.Review == nil {
		t.Fatalf("pending review: %+v %v", pending, err)
	}
	h.adapters.Policy = policyAdapter{developerMode: false, localGenerated: true, decision: PolicyAllow}
	if _, err := h.ApproveFileResource(ctx, ApproveFileResourceRequest{PluginInstanceID: installed.PluginInstanceID, ReviewID: pending.Review.ReviewID}); err == nil {
		t.Fatal("changed host policy still permitted approval")
	}
	if _, err := h.SurfaceFile(ctx, second); err == nil {
		t.Fatal("changed host policy still permitted file access")
	}
}

func (p selectedPickerFixture) SelectFile(context.Context, FileSelectionRequest) (FileSelectionResult, error) {
	return FileSelectionResult{Path: p.path, Canceled: p.canceled}, nil
}

func TestSelectedFilesReviewApprovalAndRevocation(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, filePicker: selectedPickerFixture{canceled: true}})
	installed := installAndEnablePlugin(t, h, buildSelectedFileFixture(t))
	ctx := hostTestContext()
	session, _ := sessionctx.FromContext(ctx)
	session.CanRead, session.CanWrite = true, true
	ctx = sessionctx.WithContext(ctx, session)
	record, err := h.getPluginRecord(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "chosen.txt")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	h.selectedFiles.picker = selectedPickerFixture{path: path}
	review, err := h.SelectFileResource(ctx, SelectFileResourceRequest{PluginInstanceID: record.PluginInstanceID, Kind: "file", Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(review)
	if len(raw) == 0 || review.ReviewID == "" || strings.Contains(string(raw), path) || strings.Contains(string(raw), filepath.Dir(path)) {
		t.Fatalf("review=%s", raw)
	}
	resources, err := h.ListFileResources(ctx, ListFileResourcesRequest{PluginInstanceID: record.PluginInstanceID})
	if err != nil || len(resources) != 0 {
		t.Fatalf("selection granted authority: %v %v", resources, err)
	}
	approved, err := h.ApproveFileResource(ctx, ApproveFileResourceRequest{PluginInstanceID: record.PluginInstanceID, ReviewID: review.ReviewID})
	if err != nil {
		t.Fatal(err)
	}
	after, err := h.getPluginRecord(ctx, record.PluginInstanceID)
	if err != nil || registry.AuthorizationRevisionsFromRecord(after) != registry.AuthorizationRevisionsFromRecord(record) {
		t.Fatalf("approval reloaded plugin: %v", err)
	}
	if _, err := h.ApproveFileResource(ctx, ApproveFileResourceRequest{PluginInstanceID: record.PluginInstanceID, ReviewID: review.ReviewID}); err == nil {
		t.Fatal("review replay accepted")
	}
	scope, _ := session.ResourceScope(sessionctx.ScopeUser)
	sessionScope, _ := session.SessionScope()
	invocation := resourceio.Invocation{Owner: resourceio.Owner{PluginInstanceID: record.PluginInstanceID, ActiveFingerprint: record.ActiveFingerprint, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch, Scope: scope, Session: sessionScope, RuntimeGeneration: "selected-test", InvocationID: "selected-invoke", Lifetime: resourceio.LifetimeInvocation}, Plugin: resourceio.Plugin{ID: record.PluginID, InstanceID: record.PluginInstanceID, Version: record.Version}, Permissions: map[string]bool{resourceio.PermissionFSSelectedRead: true, resourceio.PermissionFSSelectedWrite: true}, CanRead: true, CanWrite: true}
	uri, err := resourceio.ParseURI(approved.URI)
	if err != nil {
		t.Fatal(err)
	}
	var file resourceio.SelectedFile
	if err := h.selectedFiles.WithSelection(ctx, invocation, uri, true, func(s *resourceio.Selection) error {
		var e error
		file, e = s.OpenFile(uri, resourceio.OpenOptions{Write: true})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := h.RevokeFileResource(ctx, RevokeFileResourceRequest{PluginInstanceID: record.PluginInstanceID, ResourceID: approved.ResourceID, ExpectedRevision: approved.Revision}); err != nil {
		t.Fatal(err)
	}
	if err := h.selectedFiles.WithSelection(ctx, invocation, uri, true, func(*resourceio.Selection) error { t.Fatal("revoked authority"); return nil }); !errors.Is(err, ErrFileResourceUnavailable) {
		t.Fatalf("revoked: %v", err)
	}
}

func buildSelectedFileFixture(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	var manifest map[string]any
	if err := json.Unmarshal([]byte(fixtureManifestJSON()), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["permissions"] = append(manifest["permissions"].([]any), "fs.selected.read", "fs.selected.write")
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "manifest.json"), string(raw))
	writeSurfaceFixture(t, dir, "Selected files")
	var output bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &output, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestSelectedFileApprovalAttemptConsumesReview(t *testing.T) {
	for _, auditFailure := range []bool{false, true} {
		t.Run(strconv.FormatBool(auditFailure), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "selected.txt")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, filePicker: selectedPickerFixture{path: path}})
			installed := installAndEnablePlugin(t, h, buildSelectedFileFixture(t))
			session, _ := sessionctx.FromContext(hostTestContext())
			session.CanRead = true
			ctx := sessionctx.WithContext(context.Background(), session)
			review, err := h.SelectFileResource(ctx, SelectFileResourceRequest{PluginInstanceID: installed.PluginInstanceID, Kind: "file"})
			if err != nil {
				t.Fatal(err)
			}
			if auditFailure {
				h.securityJournal = &hostFailingSecurityJournal{completeErr: errors.New("audit completion unavailable")}
			} else {
				// A stale approval must not survive a failed persistence attempt.
				h.selectedFiles.reviews[review.ReviewID].expected.ManagementRevision++
			}
			req := ApproveFileResourceRequest{PluginInstanceID: installed.PluginInstanceID, ReviewID: review.ReviewID}
			if _, err := h.ApproveFileResource(ctx, req); err == nil || auditFailure && mutation.ForError(err) != mutation.OutcomeUnknown {
				t.Fatalf("approval: %v", err)
			}
			if _, exists := h.selectedFiles.reviews[review.ReviewID]; exists {
				t.Fatal("failed approval retained replayable review")
			}
			if _, err := h.ApproveFileResource(ctx, req); err == nil {
				t.Fatal("approval replayed")
			}
			resources, err := h.ListFileResources(ctx, ListFileResourcesRequest{PluginInstanceID: installed.PluginInstanceID})
			want := 0
			if auditFailure {
				want = 1
			}
			if err != nil || len(resources) != want {
				t.Fatalf("reconcile: %v %v", resources, err)
			}
		})
	}
}

type blockingFilePicker struct{ started chan struct{} }

func (p blockingFilePicker) SelectFile(ctx context.Context, _ FileSelectionRequest) (FileSelectionResult, error) {
	close(p.started)
	<-ctx.Done()
	return FileSelectionResult{}, ctx.Err()
}

func TestSelectedFilesHostCloseCancelsPendingPicker(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, filePicker: selectedPickerFixture{canceled: true}})
	installed := installAndEnablePlugin(t, h, buildSelectedFileFixture(t))
	session, _ := sessionctx.FromContext(hostTestContext())
	session.CanRead = true
	picker := blockingFilePicker{started: make(chan struct{})}
	h.selectedFiles.picker = picker
	ctx, cancel := context.WithCancel(sessionctx.WithContext(context.Background(), session))
	defer cancel()
	selected := make(chan error, 1)
	go func() {
		_, err := h.SelectFileResource(ctx, SelectFileResourceRequest{PluginInstanceID: installed.PluginInstanceID, Kind: "file"})
		selected <- err
	}()
	<-picker.started
	closed := make(chan error, 1)
	go func() { closed <- h.Close() }()
	select {
	case err := <-selected:
		if err == nil {
			t.Error("canceled picker succeeded")
		}
	case <-time.After(time.Second):
		cancel()
		if err := <-selected; err == nil {
			t.Error("canceled picker succeeded")
		}
		if err := <-closed; err != nil {
			t.Error(err)
		}
		t.Fatal("Host close did not cancel pending file picker")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

type selectedTeardownWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (ctx *selectedTeardownWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

func TestSelectedFilesReuseCurrentSessionReservationDuringTeardown(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, filePicker: selectedPickerFixture{canceled: true}})
	session, _ := sessionctx.FromContext(hostTestContext())
	session.CanRead, session.CanWrite = true, true
	ctx := sessionctx.WithContext(context.Background(), session)
	reserved, release, err := h.reserveAuthorizedAction(ctx, authorizedAction{session: session})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	scope, _ := session.SessionScope()
	identity, err := h.sessionTeardownIdentity(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	waitContext := &selectedTeardownWaitContext{Context: ctx, waiting: make(chan struct{})}
	go func() {
		teardown, _, err := h.sessionScopes.BeginTeardown(waitContext, scope, identity, time.Now())
		if teardown != nil {
			teardown.Release()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("teardown passed held reservation: %v", err)
	case <-waitContext.waiting:
	}
	bounded, cancel := context.WithTimeout(reserved, 5*time.Second)
	defer cancel()
	owner, _ := session.ResourceScope(sessionctx.ScopeUser)
	inv := resourceio.Invocation{Owner: resourceio.Owner{Scope: owner, Session: scope, PluginInstanceID: "plugini_absent"}, CanRead: true, CanWrite: true, Permissions: map[string]bool{resourceio.PermissionFSSelectedRead: true}}
	err = h.selectedFiles.WithSelection(bounded, inv, resourceio.URI{MountID: "selected-absent", Path: "."}, false, func(*resourceio.Selection) error { t.Error("missing resource authorized"); return nil })
	release()
	if teardownErr := <-done; teardownErr != nil {
		t.Fatal(teardownErr)
	}
	if !errors.Is(err, ErrFileResourceUnavailable) {
		t.Fatalf("nested reservation waited for its own release: %v", err)
	}
	if bounded.Err() != nil {
		t.Fatal("selected file operation waited for its own outer reservation")
	}
}

func TestSelectedFilesPersistAcrossHostRestartAndRejectReplacement(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state")
	assetsPath := filepath.Join(t.TempDir(), "assets")
	assets, err := pluginpkg.NewFileAssetStore(assetsPath)
	if err != nil {
		t.Fatal(err)
	}
	opts := testHostOptions{filePicker: selectedPickerFixture{canceled: true}, stateRoot: stateRoot, assets: assets, developerMode: true, localGenerated: true}
	h, _, _ := newTestHostWithOptions(t, opts)
	installed := installAndEnablePlugin(t, h, buildSelectedFileFixture(t))
	session, _ := sessionctx.FromContext(hostTestContext())
	session.CanRead, session.CanWrite = true, true
	ctx := sessionctx.WithContext(context.Background(), session)
	path := filepath.Join(t.TempDir(), "persistent.txt")
	if err := os.WriteFile(path, []byte("persistent"), 0600); err != nil {
		t.Fatal(err)
	}
	h.selectedFiles.picker = selectedPickerFixture{path: path}
	review, err := h.SelectFileResource(ctx, SelectFileResourceRequest{PluginInstanceID: installed.PluginInstanceID, Kind: "file", Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := h.ApproveFileResource(ctx, ApproveFileResourceRequest{PluginInstanceID: installed.PluginInstanceID, ReviewID: review.ReviewID})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedAssets, err := pluginpkg.NewFileAssetStore(assetsPath)
	if err != nil {
		t.Fatal(err)
	}
	opts.assets = reopenedAssets
	reopened, _, _ := newTestHostWithOptions(t, opts)
	resources, err := reopened.ListFileResources(ctx, ListFileResourcesRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil || len(resources) != 1 || resources[0].ResourceID != resource.ResourceID || resources[0].Status != "active" {
		t.Fatalf("reopen: %+v %v", resources, err)
	}
	record, err := reopened.getPluginRecord(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := session.ResourceScope(sessionctx.ScopeUser)
	owner, _ := session.SessionScope()
	inv := resourceio.Invocation{Owner: resourceio.Owner{PluginInstanceID: record.PluginInstanceID, ActiveFingerprint: record.ActiveFingerprint, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch, Scope: scope, Session: owner}, CanRead: true, CanWrite: true, Permissions: map[string]bool{resourceio.PermissionFSSelectedRead: true}}
	uri, _ := resourceio.ParseURI(resource.URI)
	calls := 0
	if err := reopened.selectedFiles.WithSelection(ctx, inv, uri, false, func(s *resourceio.Selection) error { calls++; _, err := s.Stat(uri); return err }); err != nil || calls != 1 {
		t.Fatalf("read after restart: %d %v", calls, err)
	}
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reopened.selectedFiles.WithSelection(ctx, inv, uri, false, func(*resourceio.Selection) error { t.Error("replacement authorized"); return nil }); err == nil {
		t.Fatal("replacement accepted")
	}
}
