package host

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/http/httpguts"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

var ErrConnectionUnavailable = fmt.Errorf("%w: connection is unavailable; review its configuration", connectivity.ErrConnectorDenied)

type ReviewConnectionRequest struct {
	PrivatePrefixes  []string `json:"private_prefixes,omitempty"`
	PluginInstanceID string   `json:"plugin_instance_id"`
	ConnectorID      string   `json:"connector_id"`
	Destination      string   `json:"destination"`
	HTTPMethods      []string `json:"http_methods,omitempty"`
	SecretRef        string   `json:"secret_ref,omitempty"`
	ExpectedRevision uint64   `json:"expected_revision"`
}
type ConnectionReview struct {
	ReviewID string `json:"review_id"`
	ReviewConnectionRequest
	Scope           string    `json:"scope"`
	ReviewExpiresAt time.Time `json:"review_expires_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}
type ConnectionReviewRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	ReviewID         string `json:"review_id"`
}
type ConnectionListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
}
type RevokeConnectionRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	ConnectorID      string `json:"connector_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
}
type ConnectionInfo struct {
	PrivatePrefixes []string   `json:"private_prefixes,omitempty"`
	ConnectorID     string     `json:"connector_id"`
	ConnectionID    string     `json:"connection_id,omitempty"`
	Scope           string     `json:"scope"`
	Destination     string     `json:"destination,omitempty"`
	HTTPMethods     []string   `json:"http_methods,omitempty"`
	SecretRef       string     `json:"secret_ref,omitempty"`
	Revision        uint64     `json:"revision"`
	Status          string     `json:"status"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}
type connectionEvidence struct {
	PrivatePrefixes []string
	Destination     string
	HTTPMethods     []string
	SecretRef       string
}
type pendingConnection struct {
	review      ConnectionReview
	owner       sessionctx.SessionScope
	fingerprint string
	revisions   registry.AuthorizationRevisions
}
type activeNetworkConnection struct {
	session sessionctx.SessionScope
	cancel  context.CancelFunc
}

type connectionAuthority struct {
	mu      sync.Mutex
	host    *Host
	reviews map[string]pendingConnection
	active  map[controlstore.ConnectionKey]map[string]activeNetworkConnection
}

func newConnectionAuthority(h *Host) *connectionAuthority {
	return &connectionAuthority{host: h, reviews: map[string]pendingConnection{}, active: map[controlstore.ConnectionKey]map[string]activeNetworkConnection{}}
}

func (h *Host) connectionAction(ctx context.Context, action ManagementAction, id, connectorID string) (context.Context, sessionctx.Context, func(), error) {
	target := scopedAuthorizationTarget(ResourcePlugin, id, sessionctx.ScopeEnvironment)
	if connectorID == "" {
		if action != ManagementActionListConnections {
			return ctx, sessionctx.Context{}, nil, ErrConnectionUnavailable
		}
		return h.resourceAction(ctx, action, target)
	}
	record, err := h.getPluginRecord(ctx, id)
	if err != nil {
		return ctx, sessionctx.Context{}, nil, err
	}
	connector, err := connectorByID(record.Manifest, connectorID)
	if err != nil {
		return ctx, sessionctx.Context{}, nil, err
	}
	return h.resourceAction(ctx, action, target, scopedAuthorizationTarget(ResourceConnector, connectorID, sessionctx.ScopeKind(connector.Scope)))
}
func (h *Host) connectionReviewConnector(ctx context.Context, req ConnectionReviewRequest) string {
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return ""
	}
	scope, err := session.SessionScope()
	if err != nil {
		return ""
	}
	a := h.connections
	a.mu.Lock()
	defer a.mu.Unlock()
	pending, ok := a.reviews[req.ReviewID]
	if !ok || pending.review.PluginInstanceID != req.PluginInstanceID || !pending.owner.Matches(scope) {
		return ""
	}
	return pending.review.ConnectorID
}

func connectorByID(m manifest.Manifest, id string) (manifest.NetworkConnectorSpec, error) {
	if m.NetworkAccess != nil {
		for _, c := range m.NetworkAccess.Connectors {
			if c.ConnectorID == id {
				return c, nil
			}
		}
	}
	return manifest.NetworkConnectorSpec{}, connectivity.ErrConnectorDenied
}
func connectionKey(session sessionctx.Context, id string, c manifest.NetworkConnectorSpec) (controlstore.ConnectionKey, error) {
	scope, err := session.ResourceScope(sessionctx.ScopeKind(c.Scope))
	if err != nil {
		return controlstore.ConnectionKey{}, err
	}
	return controlstore.ConnectionKey{OwnerEnvHash: scope.OwnerEnvHash, OwnerUserHash: scope.OwnerUserHash, PluginInstanceID: id, ConnectorID: c.ConnectorID}, nil
}
func (h *Host) connectionCeiling(ctx context.Context, id string) (registry.PluginRecord, error) {
	if err := h.requireFeature(FeatureConnectivity); err != nil {
		return registry.PluginRecord{}, err
	}
	record, err := h.getPluginRecord(ctx, id)
	if err != nil {
		return record, err
	}
	if _, err = h.checkRunnable(ctx, record); err != nil {
		h.connections.revokePlugin(record.OwnerEnvHash, record.PluginInstanceID)
		return record, err
	}
	if record.EnableState != registry.EnableEnabled || !slices.Contains(record.Manifest.Permissions, manifest.PermissionNetworkClient) {
		return record, permissions.ErrPermissionDenied
	}
	snapshot, err := h.getAuthorizationSnapshot(ctx, id)
	if err != nil {
		return record, err
	}
	policy, err := security.EvaluatePermissionCeiling(snapshot.Policy, id, []string{string(manifest.PermissionNetworkClient)})
	if err != nil {
		return record, err
	}
	if !policy.Allowed {
		return record, security.ErrPolicyDenied
	}
	return record, nil
}
func connectorHTTPMethods(m manifest.Manifest, id string) []string {
	methods := map[string]bool{}
	for _, method := range m.Methods {
		if method.BrokerAccess != nil {
			for _, access := range method.BrokerAccess.Network {
				if access.ConnectorID == id {
					for _, name := range access.HTTPMethods {
						methods[name] = true
					}
				}
			}
		}
	}
	for _, surface := range m.Surfaces {
		for _, access := range surface.Web.Network {
			if access.ConnectorID == id {
				for _, name := range access.HTTPMethods {
					methods[name] = true
				}
			}
		}
	}
	result := make([]string, 0, len(methods))
	for name := range methods {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
func (h *Host) ReviewConnection(ctx context.Context, req ReviewConnectionRequest) (ConnectionReview, error) {
	ctx, session, done, err := h.connectionAction(ctx, ManagementActionReviewConnection, req.PluginInstanceID, req.ConnectorID)
	if err != nil {
		return ConnectionReview{}, err
	}
	defer done()
	record, err := h.connectionCeiling(ctx, req.PluginInstanceID)
	if err != nil {
		return ConnectionReview{}, err
	}
	connector, err := connectorByID(record.Manifest, req.ConnectorID)
	if err != nil || !connector.Configurable {
		return ConnectionReview{}, connectivity.ErrConnectorDenied
	}
	if !session.CanWrite {
		return ConnectionReview{}, permissions.ErrPermissionDenied
	}
	destination, err := connectivity.ParseDestination(connectivity.Transport(connector.Transport), req.Destination)
	if err != nil {
		return ConnectionReview{}, err
	}
	if err := h.authorizePrivateConnection(ctx, session, record, connector, destination, req.PrivatePrefixes); err != nil {
		return ConnectionReview{}, err
	}
	if connector.Transport == "http" {
		allowed := connectorHTTPMethods(record.Manifest, connector.ConnectorID)
		if len(req.HTTPMethods) == 0 {
			return ConnectionReview{}, connectivity.ErrConnectorDenied
		}
		seen := map[string]bool{}
		for _, method := range req.HTTPMethods {
			if !slices.Contains(allowed, method) || seen[method] {
				return ConnectionReview{}, connectivity.ErrConnectorDenied
			}
			seen[method] = true
		}
	} else if len(req.HTTPMethods) != 0 {
		return ConnectionReview{}, connectivity.ErrConnectorDenied
	}
	if req.SecretRef != "" {
		if connector.Transport != "http" && connector.Transport != "websocket" {
			return ConnectionReview{}, connectivity.ErrConnectorDenied
		}
		if h.networkSecrets == nil || !slices.Contains(manifestSecretRefs(record.Manifest, connector.Scope), req.SecretRef) {
			return ConnectionReview{}, permissions.ErrPermissionDenied
		}
	}
	key, err := connectionKey(session, req.PluginInstanceID, connector)
	if err != nil {
		return ConnectionReview{}, err
	}
	current, err := h.controlStore.GetConnection(ctx, key)
	if err != nil && !errors.Is(err, controlstore.ErrRecordNotFound) {
		return ConnectionReview{}, err
	}
	if current.Revision != req.ExpectedRevision {
		return ConnectionReview{}, controlstore.ErrRevisionConflict
	}
	token, err := randomWebToken()
	if err != nil {
		return ConnectionReview{}, err
	}
	now := time.Now().UTC()
	scope, _ := session.SessionScope()
	req.PrivatePrefixes = slices.Clone(req.PrivatePrefixes)
	sort.Strings(req.PrivatePrefixes)
	req.HTTPMethods = append([]string(nil), req.HTTPMethods...)
	sort.Strings(req.HTTPMethods)
	review := ConnectionReview{ReviewID: token, ReviewConnectionRequest: req, Scope: connector.Scope, ReviewExpiresAt: now.Add(5 * time.Minute), ExpiresAt: now.Add(30 * 24 * time.Hour)}
	a := h.connections
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, r := range a.reviews {
		if !r.review.ReviewExpiresAt.After(now) {
			delete(a.reviews, id)
		}
	}
	if len(a.reviews) >= 128 {
		return ConnectionReview{}, ErrConnectionUnavailable
	}
	storedReview := review
	storedReview.HTTPMethods = slices.Clone(review.HTTPMethods)
	storedReview.PrivatePrefixes = slices.Clone(review.PrivatePrefixes)
	a.reviews[token] = pendingConnection{review: storedReview, owner: scope, fingerprint: record.ActiveFingerprint, revisions: registry.AuthorizationRevisionsFromRecord(record)}
	return review, nil
}
func manifestSecretRefs(m manifest.Manifest, scope string) []string {
	var refs []string
	if m.Settings != nil {
		for _, f := range m.Settings.Fields {
			if f.Type == "secret" && f.Scope == scope {
				refs = append(refs, f.SecretRef)
			}
		}
	}
	if m.NetworkAccess != nil {
		for _, c := range m.NetworkAccess.Connectors {
			if c.Scope == scope {
				if ref, ok := c.Auth["secret_ref"].(string); ok {
					refs = append(refs, ref)
				}
			}
		}
	}
	return refs
}
func (h *Host) ApproveConnection(ctx context.Context, req ConnectionReviewRequest) (result ConnectionInfo, retErr error) {
	ctx, session, done, err := h.connectionAction(ctx, ManagementActionApproveConnection, req.PluginInstanceID, h.connectionReviewConnector(ctx, req))
	if err != nil {
		return result, err
	}
	defer done()
	if !session.CanWrite {
		return result, permissions.ErrPermissionDenied
	}
	record, err := h.connectionCeiling(ctx, req.PluginInstanceID)
	if err != nil {
		return result, err
	}
	scope, _ := session.SessionScope()
	a := h.connections
	a.mu.Lock()
	pending, ok := a.reviews[req.ReviewID]
	if !ok || pending.review.PluginInstanceID != req.PluginInstanceID || !pending.owner.Matches(scope) || !pending.review.ReviewExpiresAt.After(time.Now()) || pending.fingerprint != record.ActiveFingerprint || pending.revisions != registry.AuthorizationRevisionsFromRecord(record) {
		a.mu.Unlock()
		return result, ErrConnectionUnavailable
	}
	// Consume before audit or durable mutation. An uncertain result is resolved
	// by ListConnections, never by replaying an approval.
	delete(a.reviews, req.ReviewID)
	a.mu.Unlock()
	connector, err := connectorByID(record.Manifest, pending.review.ConnectorID)
	if err != nil {
		return result, err
	}
	destination, err := connectivity.ParseDestination(connectivity.Transport(connector.Transport), pending.review.Destination)
	if err != nil {
		return result, err
	}
	if err := h.authorizePrivateConnection(ctx, session, record, connector, destination, pending.review.PrivatePrefixes); err != nil {
		return result, err
	}
	key, err := connectionKey(session, req.PluginInstanceID, connector)
	if err != nil {
		return result, err
	}
	id, err := randomWebToken()
	if err != nil {
		return result, err
	}
	evidence := connectionEvidence{Destination: pending.review.Destination, HTTPMethods: pending.review.HTTPMethods, SecretRef: pending.review.SecretRef, PrivatePrefixes: slices.Clone(pending.review.PrivatePrefixes)}
	raw, _ := json.Marshal(evidence)
	audit, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.connection.approved", PluginInstanceID: req.PluginInstanceID})
	if err != nil {
		return result, err
	}
	defer func() { retErr = audit.complete(context.WithoutCancel(ctx), retErr) }()
	connection := controlstore.Connection{ConnectionKey: key, ConnectionID: id, ActiveFingerprint: record.ActiveFingerprint, RevokeEpoch: record.RevokeEpoch, Revision: pending.review.ExpectedRevision + 1, ExpiresAt: pending.review.ExpiresAt.UnixNano(), Evidence: raw}
	a.mu.Lock()
	defer a.mu.Unlock()
	err = h.controlStore.PutConnection(ctx, connection, pending.review.ExpectedRevision, pending.revisions, time.Now())
	if err == nil || mutation.ForError(err) == mutation.OutcomeUnknown {
		a.cancelLocked(key)
	}
	if err != nil {
		return result, err
	}
	return projectConnection(connector, connection, evidence, record, time.Now()), nil
}
func (a *connectionAuthority) cancelLocked(key controlstore.ConnectionKey) {
	for _, active := range a.active[key] {
		active.cancel()
	}
	delete(a.active, key)
}
func (h *Host) CancelConnectionReview(ctx context.Context, req ConnectionReviewRequest) error {
	_, session, done, err := h.connectionAction(ctx, ManagementActionCancelConnectionReview, req.PluginInstanceID, h.connectionReviewConnector(ctx, req))
	if err != nil {
		return err
	}
	defer done()
	scope, _ := session.SessionScope()
	a := h.connections
	a.mu.Lock()
	defer a.mu.Unlock()
	pending, ok := a.reviews[req.ReviewID]
	if ok && pending.owner.Matches(scope) && pending.review.PluginInstanceID == req.PluginInstanceID {
		delete(a.reviews, req.ReviewID)
		return nil
	}
	return ErrConnectionUnavailable
}
func (h *Host) ListConnections(ctx context.Context, req ConnectionListRequest) ([]ConnectionInfo, error) {
	ctx, session, done, err := h.connectionAction(ctx, ManagementActionListConnections, req.PluginInstanceID, "")
	if err != nil {
		return nil, err
	}
	defer done()
	record, err := h.getPluginRecord(ctx, req.PluginInstanceID)
	if err != nil {
		return nil, err
	}
	result := []ConnectionInfo{}
	if record.Manifest.NetworkAccess == nil {
		return result, nil
	}
	for _, connector := range record.Manifest.NetworkAccess.Connectors {
		key, err := connectionKey(session, record.PluginInstanceID, connector)
		if err != nil {
			return nil, err
		}
		if !connector.Configurable {
			result = append(result, ConnectionInfo{ConnectorID: connector.ConnectorID, Scope: connector.Scope, Status: "fixed"})
			continue
		}
		c, err := h.controlStore.GetConnection(ctx, key)
		if errors.Is(err, controlstore.ErrRecordNotFound) {
			result = append(result, ConnectionInfo{ConnectorID: connector.ConnectorID, Scope: connector.Scope, Status: "unconfigured"})
			continue
		}
		if err != nil {
			return nil, err
		}
		e, err := decodeConnectionEvidence(c.Evidence)
		if err != nil {
			return nil, err
		}
		result = append(result, projectConnection(connector, c, e, record, time.Now()))
	}
	return result, nil
}
func decodeConnectionEvidence(raw json.RawMessage) (connectionEvidence, error) {
	var e connectionEvidence
	if err := decodeRuntimeIOJSON(raw, &e); err != nil || e.Destination == "" {
		return e, ErrConnectionUnavailable
	}
	return e, nil
}
func projectConnection(connector manifest.NetworkConnectorSpec, c controlstore.Connection, e connectionEvidence, record registry.PluginRecord, now time.Time) ConnectionInfo {
	status := "active"
	if c.RevokedAt != nil {
		status = "revoked"
	} else if c.ExpiresAt <= now.UnixNano() {
		status = "expired"
	} else if c.ActiveFingerprint != record.ActiveFingerprint || c.RevokeEpoch != record.RevokeEpoch {
		status = "stale"
	}
	expires := time.Unix(0, c.ExpiresAt).UTC()
	return ConnectionInfo{PrivatePrefixes: slices.Clone(e.PrivatePrefixes), ConnectorID: connector.ConnectorID, Scope: connector.Scope, ConnectionID: c.ConnectionID, Destination: e.Destination, HTTPMethods: e.HTTPMethods, SecretRef: e.SecretRef, Revision: c.Revision, Status: status, ExpiresAt: &expires}
}
func (h *Host) RevokeConnection(ctx context.Context, req RevokeConnectionRequest) (retErr error) {
	ctx, session, done, err := h.connectionAction(ctx, ManagementActionRevokeConnection, req.PluginInstanceID, req.ConnectorID)
	if err != nil {
		return err
	}
	defer done()
	if !session.CanWrite {
		return permissions.ErrPermissionDenied
	}
	record, err := h.getPluginRecord(ctx, req.PluginInstanceID)
	if err != nil {
		return err
	}
	connector, err := connectorByID(record.Manifest, req.ConnectorID)
	if err != nil {
		return err
	}
	key, err := connectionKey(session, req.PluginInstanceID, connector)
	if err != nil {
		return err
	}
	audit, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.connection.revoked", PluginInstanceID: req.PluginInstanceID})
	if err != nil {
		return err
	}
	defer func() { retErr = audit.complete(context.WithoutCancel(ctx), retErr) }()
	a := h.connections
	a.mu.Lock()
	defer a.mu.Unlock()
	err = h.controlStore.RevokeConnection(ctx, key, req.ExpectedRevision, time.Now())
	if err == nil || mutation.ForError(err) == mutation.OutcomeUnknown {
		a.cancelLocked(key)
	}
	return err
}

// NetworkSecretResolver returns credential headers only to the trusted Host.
// Values never enter manifest, bridge, Worker payload, inventory, or audit data.
type NetworkSecretResolver interface {
	ResolveNetworkSecret(context.Context, NetworkSecretRequest) (http.Header, error)
}
type NetworkSecretRequest struct {
	Session                sessionctx.Context
	Plugin                 PluginRef
	ConnectorID, SecretRef string
	Destination            connectivity.Destination
}

type connectionLease struct {
	tlsDeclaration map[string]any
	ctx            context.Context
	binding        *connectivity.ApprovedBinding
	secretRef      string
	release        func()
}

func (a *connectionAuthority) acquire(ctx context.Context, inv resourceio.Invocation, connectorID, method string) (connectionLease, error) {
	session := resourceInvocationSession(inv)
	if !session.CanRead || (!session.CanWrite && method != "GET" && method != "HEAD" && method != "OPTIONS") {
		return connectionLease{}, permissions.ErrPermissionDenied
	}
	var releaseReservation func()
	var err error
	ctx, releaseReservation, err = a.host.reserveAuthorizedAction(ctx, authorizedAction{session: session})
	if err != nil {
		return connectionLease{}, err
	}
	defer releaseReservation()
	ctx = sessionctx.WithContext(ctx, session)
	record, err := a.host.connectionCeiling(ctx, inv.Plugin.InstanceID)
	if err != nil {
		return connectionLease{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Re-read durable authority after policy callbacks and under the same lock
	// used to replace or revoke connections. No adapter runs in this section.
	record, err = a.host.getPluginRecord(ctx, inv.Plugin.InstanceID)
	if err != nil {
		return connectionLease{}, err
	}
	if ctx.Err() != nil {
		return connectionLease{}, ctx.Err()
	}
	if record.EnableState != registry.EnableEnabled || record.ActiveFingerprint != inv.Owner.ActiveFingerprint || record.PolicyRevision != inv.PolicyRevision || record.ManagementRevision != inv.Owner.ManagementRevision || record.RevokeEpoch != inv.Owner.RevokeEpoch {
		return connectionLease{}, ErrConnectionUnavailable
	}
	snapshot, err := a.host.getAuthorizationSnapshot(ctx, inv.Plugin.InstanceID)
	if err != nil {
		return connectionLease{}, err
	}
	if snapshot.Plugin.ActiveFingerprint != record.ActiveFingerprint || registry.AuthorizationRevisionsFromRecord(snapshot.Plugin) != registry.AuthorizationRevisionsFromRecord(record) {
		return connectionLease{}, ErrConnectionUnavailable
	}
	allowed, _, err := permissions.Evaluate(snapshot.Grants, permissions.CheckRequest{PluginInstanceID: inv.Plugin.InstanceID, PermissionIDs: []string{string(manifest.PermissionNetworkClient)}, Now: time.Now()})
	if err != nil {
		return connectionLease{}, err
	}
	if !allowed {
		return connectionLease{}, permissions.ErrPermissionDenied
	}
	connector, err := connectorByID(record.Manifest, connectorID)
	if err != nil {
		return connectionLease{}, err
	}
	key, err := connectionKey(session, inv.Plugin.InstanceID, connector)
	if err != nil {
		return connectionLease{}, err
	}
	lease := connectionLease{tlsDeclaration: connector.TLS}
	if len(connector.TLS) > 0 && a.host.networkTLS == nil {
		return lease, ErrConnectionUnavailable
	}
	if len(connector.Auth) > 0 {
		secret, ok := connector.Auth["secret_ref"].(string)
		if !ok || secret == "" || len(connector.Auth) != 1 || (connector.Transport != "http" && connector.Transport != "websocket") {
			return lease, ErrConnectionUnavailable
		}
	}
	if connector.Configurable {
		c, err := a.host.controlStore.GetConnection(ctx, key)
		if err != nil {
			return lease, ErrConnectionUnavailable
		}
		if c.RevokedAt != nil || c.ExpiresAt <= time.Now().UnixNano() || c.ActiveFingerprint != record.ActiveFingerprint || c.RevokeEpoch != record.RevokeEpoch {
			return lease, ErrConnectionUnavailable
		}
		evidence, err := decodeConnectionEvidence(c.Evidence)
		if err != nil {
			return lease, err
		}
		if connector.Transport == "http" && !slices.Contains(evidence.HTTPMethods, method) {
			return lease, permissions.ErrPermissionDenied
		}
		lease.binding = &connectivity.ApprovedBinding{PrivatePrefixes: slices.Clone(evidence.PrivatePrefixes), ConnectionID: c.ConnectionID, Revision: c.Revision, Destination: evidence.Destination, HTTPMethods: append([]string(nil), evidence.HTTPMethods...), ExpiresAt: time.Unix(0, c.ExpiresAt)}
		lease.secretRef = evidence.SecretRef
	} else if secret, ok := connector.Auth["secret_ref"].(string); ok {
		lease.secretRef = secret
	}
	token, err := randomWebToken()
	if err != nil {
		return lease, err
	}
	activeCount := 0
	for _, requests := range a.active {
		activeCount += len(requests)
	}
	if len(a.active[key]) >= 128 || activeCount >= 1024 {
		return lease, ErrConnectionUnavailable
	}
	request, cancel := context.WithCancel(ctx)
	stopHost := context.AfterFunc(a.host.lifecycleCtx, cancel)
	if a.host.lifecycleCtx.Err() != nil {
		cancel()
	}
	lease.ctx = request
	if a.active[key] == nil {
		a.active[key] = map[string]activeNetworkConnection{}
	}
	a.active[key][token] = activeNetworkConnection{session: inv.Owner.Session, cancel: cancel}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cancel()
			stopHost()
			a.mu.Lock()
			delete(a.active[key], token)
			if len(a.active[key]) == 0 {
				delete(a.active, key)
			}
			a.mu.Unlock()
		})
	}
	stop := context.AfterFunc(request, cleanup)
	lease.release = func() { stop(); cleanup() }
	return lease, nil
}
func (a *connectionAuthority) revokePlugin(env, plugin string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for key := range a.active {
		if key.OwnerEnvHash == env && key.PluginInstanceID == plugin {
			a.cancelLocked(key)
		}
	}
	for id, r := range a.reviews {
		if r.owner.OwnerEnvHash == env && r.review.PluginInstanceID == plugin {
			delete(a.reviews, id)
		}
	}
}

// PrivateNetworkPolicy is the product's explicit private-target approval cap.
// The platform still validates every address and pins actual outbound sockets.
type PrivateNetworkPolicy interface {
	AuthorizePrivateNetwork(context.Context, PrivateNetworkRequest) error
}
type PrivateNetworkRequest struct {
	Session         sessionctx.Context
	Plugin          PluginRef
	ConnectorID     string
	Destination     connectivity.Destination
	PrivatePrefixes []string
}

func (h *Host) authorizePrivateConnection(ctx context.Context, session sessionctx.Context, record registry.PluginRecord, connector manifest.NetworkConnectorSpec, destination connectivity.Destination, prefixes []string) error {
	if err := connectivity.ValidateApprovedDestination(destination, prefixes); err != nil {
		return err
	}
	if len(prefixes) == 0 {
		return nil
	}
	if h.privateNetworkPolicy == nil {
		return permissions.ErrPermissionDenied
	}
	return h.privateNetworkPolicy.AuthorizePrivateNetwork(ctx, PrivateNetworkRequest{Session: session, Plugin: PluginRef{PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID, Version: record.Version, ActiveFingerprint: record.ActiveFingerprint}, ConnectorID: connector.ConnectorID, Destination: destination, PrivatePrefixes: slices.Clone(prefixes)})
}

func validateCredentialHeaders(headers http.Header) error {
	if len(headers) == 0 || len(headers) > 32 {
		return permissions.ErrPermissionDenied
	}
	total := 0
	for name, values := range headers {
		if !httpguts.ValidHeaderFieldName(name) || len(values) == 0 {
			return permissions.ErrPermissionDenied
		}
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "sec-") || strings.HasPrefix(lower, "proxy-") || strings.HasPrefix(lower, "x-forwarded-") {
			return permissions.ErrPermissionDenied
		}
		switch lower {
		case "host", "connection", "upgrade", "transfer-encoding", "content-length", "te", "trailer", "keep-alive", "origin", "referer", "forwarded", "accept-encoding":
			return permissions.ErrPermissionDenied
		}
		for _, value := range values {
			total += len(name) + len(value)
			if total > 16<<10 || !httpguts.ValidHeaderFieldValue(value) {
				return permissions.ErrPermissionDenied
			}
		}
	}
	return nil
}

// NetworkTLSResolver resolves the signed TLS declaration inside the trusted Host.
// The executor enforces hostname verification and TLS 1.2 or newer regardless
// of adapter settings. Certificate and root bytes never cross into the plugin.
type NetworkTLSResolver interface {
	ResolveNetworkTLS(context.Context, NetworkTLSRequest) (*tls.Config, error)
}
type NetworkTLSRequest struct {
	Session     sessionctx.Context
	Plugin      PluginRef
	ConnectorID string
	Destination connectivity.Destination
	Declaration map[string]any
}

func (b *hostRuntimeIOBroker) resolveNetworkTLS(ctx context.Context, inv resourceio.Invocation, connector string, grant connectivity.ConnectionGrant, lease connectionLease) (*tls.Config, error) {
	if len(lease.tlsDeclaration) == 0 {
		return nil, nil
	}
	if b.connections == nil || b.connections.host.networkTLS == nil {
		return nil, ErrConnectionUnavailable
	}
	raw, err := json.Marshal(lease.tlsDeclaration)
	if err != nil {
		return nil, ErrConnectionUnavailable
	}
	var declaration map[string]any
	if json.Unmarshal(raw, &declaration) != nil {
		return nil, ErrConnectionUnavailable
	}
	config, err := b.connections.host.networkTLS.ResolveNetworkTLS(ctx, NetworkTLSRequest{Session: resourceInvocationSession(inv), Plugin: resourceInvocationPlugin(inv), ConnectorID: connector, Destination: grant.Destination, Declaration: declaration})
	if err != nil || config == nil {
		return nil, ErrConnectionUnavailable
	}
	return config, nil
}

func (a *connectionAuthority) revokeSession(scope sessionctx.SessionScope) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, requests := range a.active {
		for token, active := range requests {
			if active.session == scope {
				active.cancel()
				delete(requests, token)
			}
		}
		if len(requests) == 0 {
			delete(a.active, key)
		}
	}
	for token, pending := range a.reviews {
		if pending.owner == scope {
			delete(a.reviews, token)
		}
	}
}
