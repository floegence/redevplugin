package host

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"path/filepath"
	"testing"
	"time"
)

type connectionPolicyLockProbe struct {
	PolicyAdapter
	authority *connectionAuthority
	called    bool
	unlocked  bool
}

func (p *connectionPolicyLockProbe) DeveloperModeEnabled(ctx context.Context, s sessionctx.Context) (bool, error) {
	p.called = true
	p.unlocked = p.authority.mu.TryLock()
	if p.unlocked {
		p.authority.mu.Unlock()
	}
	return p.PolicyAdapter.DeveloperModeEnabled(ctx, s)
}
func networkInvocation(t *testing.T, record registry.PluginRecord, session sessionctx.Context) resourceio.Invocation {
	t.Helper()
	scope, err := session.ResourceScope(sessionctx.ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	return resourceio.Invocation{Owner: resourceio.Owner{PluginInstanceID: record.PluginInstanceID, ActiveFingerprint: record.ActiveFingerprint, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch, Scope: scope, Session: owner, InvocationID: "connection-test", RuntimeGeneration: "connection-test", Lifetime: resourceio.LifetimeInvocation}, Plugin: resourceio.Plugin{ID: record.PluginID, InstanceID: record.PluginInstanceID, Version: record.Version}, PolicyRevision: record.PolicyRevision, Permissions: map[string]bool{resourceio.PermissionNetworkClient: true}, CanRead: true, CanWrite: true}
}
func TestConnectionAdmissionCallsPolicyOutsideAuthorityLock(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	record := installAndEnablePlugin(t, h, buildWorkerNetworkFixturePackage(t))
	probe := &connectionPolicyLockProbe{PolicyAdapter: h.adapters.Policy, authority: h.connections}
	h.adapters.Policy = probe
	session, _ := sessionctx.FromContext(hostTestContext())
	lease, err := h.connections.acquire(hostTestContext(), networkInvocation(t, record, session), "api", "GET")
	if err == nil {
		lease.release()
	}
	if !probe.called || !probe.unlocked {
		t.Fatalf("policy called=%v without authority lock=%v", probe.called, probe.unlocked)
	}
}

func configuredNetworkFixture(t *testing.T) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(workerNetworkFixtureManifestJSON()), &m); err != nil {
		t.Fatal(err)
	}
	c := m["network_access"].(map[string]any)["connectors"].([]any)[0].(map[string]any)
	c["configurable"] = true
	delete(c, "destinations")
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), string(raw))
	writeSurfaceFixture(t, dir, "Connections")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var out bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &out, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func connectionFixture(t *testing.T, packages ...[]byte) (*Host, context.Context, registry.PluginRecord, resourceio.Invocation) {
	t.Helper()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	fixture := configuredNetworkFixture(t)
	if len(packages) > 0 {
		fixture = packages[0]
	}
	record := installAndEnablePlugin(t, h, fixture)
	s, _ := sessionctx.FromContext(hostTestContext())
	s.CanRead, s.CanWrite = true, true
	ctx := sessionctx.WithContext(context.Background(), s)
	revisions := registry.AuthorizationRevisionsFromRecord(record)
	if _, err := h.GrantPermission(ctx, GrantPermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: revisions.PolicyRevision, ExpectedManagementRevision: revisions.ManagementRevision, ExpectedRevokeEpoch: revisions.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	record, err := h.getPluginRecord(ctx, record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	return h, ctx, record, networkInvocation(t, record, s)
}
func TestConnectionReviewApprovalReplacementAndRevocation(t *testing.T) {
	h, ctx, record, inv := connectionFixture(t)
	if _, err := h.connections.acquire(ctx, inv, "api", "GET"); err == nil {
		t.Fatal("unconfigured connection admitted")
	}
	approve := func(revision uint64, destination string) ConnectionInfo {
		t.Helper()
		review, err := h.ReviewConnection(ctx, ReviewConnectionRequest{PluginInstanceID: record.PluginInstanceID, ConnectorID: "api", Destination: destination, HTTPMethods: []string{"GET"}, ExpectedRevision: revision})
		if err != nil {
			t.Fatal(err)
		}
		req := ConnectionReviewRequest{PluginInstanceID: record.PluginInstanceID, ReviewID: review.ReviewID}
		other, _ := sessionctx.FromContext(ctx)
		other.OwnerSessionHash = "other-session"
		if _, err := h.ApproveConnection(sessionctx.WithContext(ctx, other), req); err == nil {
			t.Fatal("sibling session approved review")
		}
		info, err := h.ApproveConnection(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.ApproveConnection(ctx, req); err == nil {
			t.Fatal("approval replayed")
		}
		return info
	}
	first := approve(0, "https://api.example.com")
	lease, err := h.connections.acquire(ctx, inv, "api", "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.release()
	if _, err := h.connections.acquire(ctx, inv, "api", "POST"); err == nil {
		t.Fatal("method outside approval accepted")
	}
	other := inv
	other.Owner.Session.OwnerUserHash = "other-user"
	if _, err := h.connections.acquire(ctx, other, "api", "GET"); err == nil {
		t.Fatal("cross-owner connection accepted")
	}
	second := approve(first.Revision, "https://new.example.com")
	select {
	case <-lease.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("replacement did not cancel old stream")
	}
	replacement, err := h.connections.acquire(ctx, inv, "api", "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.release()
	if replacement.binding.ConnectionID != second.ConnectionID || replacement.binding.Revision != second.Revision {
		t.Fatal("replacement binding differs")
	}
	if err := h.RevokeConnection(ctx, RevokeConnectionRequest{PluginInstanceID: record.PluginInstanceID, ConnectorID: "api", ExpectedRevision: second.Revision}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-replacement.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("revoke did not cancel stream")
	}
	if _, err := h.connections.acquire(ctx, inv, "api", "GET"); err == nil {
		t.Fatal("revoked connection admitted")
	}
	info, err := h.ListConnections(ctx, ConnectionListRequest{PluginInstanceID: record.PluginInstanceID})
	if err != nil || len(info) != 1 || info[0].Status != "revoked" {
		t.Fatalf("inventory: %+v %v", info, err)
	}
}
func TestConnectionPolicyDenialReturnsWithoutDrainingItsOwnInvocation(t *testing.T) {
	h, ctx, record, inv := connectionFixture(t)
	registration, err := newHostRuntimeIORegistration(inv, workerBrokerAccess{Network: []workerNetworkBrokerAccess{{ConnectorID: "api", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.runtimeIO.register(ctx, inv.Owner.InvocationID, registration); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.runtimeIO.release(inv.Owner.InvocationID) }()
	h.adapters.Policy = policyAdapter{developerMode: false, localGenerated: true, decision: PolicyAllow}
	done := make(chan error, 1)
	go func() {
		op, registered, release, err := h.runtimeIO.acquire(ctx, inv.Owner.InvocationID)
		if err != nil {
			done <- err
			return
		}
		defer release()
		_, err = h.connections.acquire(op, registered.resource, "api", "GET")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("denied policy accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("policy denial waited for its own invocation")
	}
	info, err := h.getPluginRecord(ctx, record.PluginInstanceID)
	if err != nil || info.EnableState != registry.EnableEnabled {
		t.Fatal("policy denial changed explicit enable state")
	}
}

func TestConnectionReviewReturnedSlicesCannotChangeApprovedAuthority(t *testing.T) {
	h, ctx, record, inv := connectionFixture(t)
	review, err := h.ReviewConnection(ctx, ReviewConnectionRequest{PluginInstanceID: record.PluginInstanceID, ConnectorID: "api", Destination: "https://api.example.com", HTTPMethods: []string{"GET"}})
	if err != nil {
		t.Fatal(err)
	}
	review.HTTPMethods[0] = "POST"
	info, err := h.ApproveConnection(ctx, ConnectionReviewRequest{PluginInstanceID: record.PluginInstanceID, ReviewID: review.ReviewID})
	if err != nil {
		t.Fatal(err)
	}
	if len(info.HTTPMethods) != 1 || info.HTTPMethods[0] != "GET" {
		t.Fatalf("caller changed approval: %+v", info)
	}
	if _, err := h.connections.acquire(ctx, inv, "api", "POST"); err == nil {
		t.Fatal("modified caller slice granted POST")
	}
}

func TestConnectionStaleRevokeDoesNotCancelCurrentStream(t *testing.T) {
	h, ctx, record, inv := connectionFixture(t)
	review, err := h.ReviewConnection(ctx, ReviewConnectionRequest{PluginInstanceID: record.PluginInstanceID, ConnectorID: "api", Destination: "https://api.example.com", HTTPMethods: []string{"GET"}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := h.ApproveConnection(ctx, ConnectionReviewRequest{PluginInstanceID: record.PluginInstanceID, ReviewID: review.ReviewID})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.connections.acquire(ctx, inv, "api", "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.release()
	if err := h.RevokeConnection(ctx, RevokeConnectionRequest{PluginInstanceID: record.PluginInstanceID, ConnectorID: "api", ExpectedRevision: info.Revision + 1}); err == nil {
		t.Fatal("stale revoke accepted")
	}
	if lease.ctx.Err() != nil {
		t.Fatal("stale revoke canceled the current stream")
	}
}

func TestConnectionReadOnlySessionCannotSendMutation(t *testing.T) {
	h, ctx, record, inv := connectionFixture(t)
	review, err := h.ReviewConnection(ctx, ReviewConnectionRequest{PluginInstanceID: record.PluginInstanceID, ConnectorID: "api", Destination: "https://api.example.com", HTTPMethods: []string{"GET"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ApproveConnection(ctx, ConnectionReviewRequest{PluginInstanceID: record.PluginInstanceID, ReviewID: review.ReviewID}); err != nil {
		t.Fatal(err)
	}
	inv.CanRead = false
	if lease, err := h.connections.acquire(ctx, inv, "api", "GET"); err == nil {
		lease.release()
		t.Fatal("unreadable session opened GET")
	}
}

func TestConnectionReadOnlySessionDeniesFixedMutations(t *testing.T) {
	h, ctx, _, inv := connectionFixture(t, buildWorkerNetworkFixturePackage(t))
	inv.CanWrite = false
	for _, method := range []string{"POST", "PUT", "DELETE", ""} {
		if lease, err := h.connections.acquire(ctx, inv, "api", method); err == nil {
			lease.release()
			t.Fatalf("read-only session admitted %q", method)
		}
	}
	lease, err := h.connections.acquire(ctx, inv, "api", "GET")
	if err != nil {
		t.Fatal(err)
	}
	lease.release()
}
func TestConnectionSessionRevocationCancelsOnlyItsRequestsAndReviews(t *testing.T) {
	h, ctx, record, inv := connectionFixture(t)
	review, err := h.ReviewConnection(ctx, ReviewConnectionRequest{PluginInstanceID: record.PluginInstanceID, ConnectorID: "api", Destination: "https://api.example.com", HTTPMethods: []string{"GET"}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := h.ApproveConnection(ctx, ConnectionReviewRequest{PluginInstanceID: record.PluginInstanceID, ReviewID: review.ReviewID})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := h.ReviewConnection(ctx, ReviewConnectionRequest{PluginInstanceID: record.PluginInstanceID, ConnectorID: "api", Destination: "https://api.example.com", HTTPMethods: []string{"GET"}, ExpectedRevision: info.Revision})
	if err != nil {
		t.Fatal(err)
	}
	first, err := h.connections.acquire(ctx, inv, "api", "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer first.release()
	sibling := inv
	sibling.Owner.Session.OwnerSessionHash = "sibling"
	second, err := h.connections.acquire(ctx, sibling, "api", "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer second.release()
	if _, err := h.RevokeSessionScope(ctx, RevokeSessionScopeRequest{Now: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if first.ctx.Err() == nil {
		t.Fatal("closed session retained connection")
	}
	if second.ctx.Err() != nil {
		t.Fatal("sibling connection canceled")
	}
	h.connections.mu.Lock()
	_, present := h.connections.reviews[pending.ReviewID]
	h.connections.mu.Unlock()
	if present {
		t.Fatal("closed session retained pending review")
	}
	if lease, err := h.connections.acquire(ctx, inv, "api", "GET"); err == nil {
		lease.release()
		t.Fatal("closed session reopened connection")
	}
}
