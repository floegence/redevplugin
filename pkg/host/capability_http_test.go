package host

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
)

func capabilityHTTPFixture(t *testing.T, grant bool, executor connectivity.NetworkExecutor) (*Host, capability.ExecutionBinding) {
	t.Helper()
	contract, err := fixtureCapabilityContract("example.capability.echo")
	if err != nil {
		t.Fatal(err)
	}
	empty := map[string]any{"type": "object", "additionalProperties": false}
	contract.Methods = []capabilitycontract.Method{fixtureContractMethod("agent.begin", "execute", "sync", nil, nil, empty, empty)}
	known := verifyFixtureCapabilityContract(t, contract)
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{capabilityContract: &known, capabilityAdapter: adapter, networkExecutor: executor})
	pkg := surfaceMethodsFixtureWith(t, func(m map[string]any) {
		m["network_access"] = map[string]any{"connectors": []any{map[string]any{"connector_id": "api", "transport": "http", "scope": "user", "destinations": []string{"https://api.example.com"}}}}
		api := m["api"].(map[string]any)
		api["required_features"] = append(api["required_features"].([]any), "net.http.v1")
		m["permissions"] = append(m["permissions"].([]any), "network.client")
	}, known)
	installed := installAndEnablePlugin(t, h, pkg)
	if grant {
		rev := mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
		if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{PluginInstanceID: installed.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: rev.PolicyRevision, ExpectedManagementRevision: rev.ManagementRevision, ExpectedRevokeEpoch: rev.RevokeEpoch}); err != nil {
			t.Fatal(err)
		}
	}
	receiver := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "network_surface")
	if _, err := h.CallPluginMethod(surfaceMethodTestContext(), CallMethodRequest{PluginInstanceID: receiver.PluginInstanceID, SurfaceInstanceID: receiver.SurfaceInstanceID, BridgeChannelID: receiver.BridgeChannelID, GatewayToken: receiver.GatewayToken, Method: "agent.begin"}); err != nil {
		t.Fatal(err)
	}
	return h, adapter.last.Execution.ExecutionBinding
}

func TestCapabilityHTTPUsesExactConnectorAndCurrentGrant(t *testing.T) {
	for _, granted := range []bool{false, true} {
		t.Run(map[bool]string{false: "ungranted", true: "granted"}[granted], func(t *testing.T) {
			observer := &webNetworkObserver{}
			h, source := capabilityHTTPFixture(t, granted, observer)
			request, _ := http.NewRequestWithContext(t.Context(), "POST", "https://api.example.com/mcp?session=a%2fb", strings.NewReader(`{"jsonrpc":"2.0"}`))
			response, err := h.OpenCapabilityHTTP(surfaceMethodTestContext(), source, "api", request)
			if !granted {
				if err == nil {
					response.Body.Close()
					t.Fatal("ungranted connector opened")
				}
				if len(observer.requests) != 0 {
					t.Fatal("ungranted request reached executor")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(data) != "stream" || len(observer.requests) != 1 || observer.requests[0].RequestURI != "/mcp?session=a%2fb" {
				t.Fatalf("response: %s %v %+v", data, err, observer.requests)
			}
			for _, target := range []string{"https://other.example.com/mcp", "https://api.example.com/mcp#fragment", "https://user@api.example.com/mcp"} {
				denied, _ := http.NewRequestWithContext(t.Context(), "POST", target, nil)
				if r, err := h.OpenCapabilityHTTP(surfaceMethodTestContext(), source, "api", denied); err == nil {
					r.Body.Close()
					t.Fatalf("unreviewed target opened: %s", target)
				}
			}
			if r, err := h.OpenCapabilityHTTP(surfaceMethodTestContext(), source, "sibling", request); err == nil {
				r.Body.Close()
				t.Fatal("unknown connector opened")
			}
			if len(observer.requests) != 1 {
				t.Fatal("denied target reached executor")
			}
		})
	}
}

type capabilityHTTPIdleBody struct {
	closed chan struct{}
	once   sync.Once
}

func (b *capabilityHTTPIdleBody) Read([]byte) (int, error) { <-b.closed; return 0, io.EOF }
func (b *capabilityHTTPIdleBody) Close() error             { b.once.Do(func() { close(b.closed) }); return nil }

type capabilityHTTPIdleExecutor struct {
	connectivity.NetworkExecutor
	body     *capabilityHTTPIdleBody
	redirect bool
}

func (e *capabilityHTTPIdleExecutor) OpenHTTP(context.Context, connectivity.HTTPRequest) (connectivity.HTTPBodyResponse, error) {
	status := 200
	headers := make(http.Header)
	if e.redirect {
		status = 307
		headers.Set("Location", "https://other.example.com/mcp")
	}
	return connectivity.HTTPBodyResponse{StatusCode: status, Headers: headers, Body: e.body}, nil
}

func TestCapabilityHTTPClosesIdleBodiesOnAuthorityLoss(t *testing.T) {
	for _, mode := range []string{"cancel", "expiry", "revoke", "host-close", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			body := &capabilityHTTPIdleBody{closed: make(chan struct{})}
			h, source := capabilityHTTPFixture(t, true, &capabilityHTTPIdleExecutor{body: body, redirect: mode == "redirect"})
			ctx, cancel := context.WithCancel(surfaceMethodTestContext())
			defer cancel()
			if mode == "expiry" {
				source.Quota.ExpiresAt = time.Now().UTC().Add(2 * time.Second).Truncate(time.Second)
			}
			request, _ := http.NewRequestWithContext(ctx, "POST", "https://api.example.com/mcp", nil)
			response, err := h.OpenCapabilityHTTP(ctx, source, "api", request)
			if mode == "redirect" {
				if err == nil {
					response.Body.Close()
					t.Fatal("redirect followed")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
			}
			switch mode {
			case "cancel":
				cancel()
			case "host-close":
				if err := h.Close(); err != nil {
					t.Fatal(err)
				}
			case "revoke":
				rev := mustAuthorizationRevisions(t, h, source.PluginInstanceID)
				if _, err := h.RevokePermission(surfaceMethodTestContext(), RevokePermissionRequest{PluginInstanceID: source.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: rev.PolicyRevision, ExpectedManagementRevision: rev.ManagementRevision, ExpectedRevokeEpoch: rev.RevokeEpoch}); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-body.closed:
			case <-time.After(3 * time.Second):
				t.Fatal("idle response body remained open")
			}
		})
	}
}
