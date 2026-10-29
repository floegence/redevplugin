package connectivity

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

func TestPrivateConnectionPinsAllResolvedAddressesAndKeepsPublicDefault(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		_, _ = io.WriteString(w, r.URL.RequestURI())
	}))
	defer server.Close()
	policy, err := CompilePolicy(CompileRequest{PluginInstanceID: "plugin", ActiveFingerprint: "fingerprint", PolicyRevision: 1, ManagementRevision: 1, RevokeEpoch: 1, Manifest: manifest.Manifest{NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{{ConnectorID: "service", Transport: "http", Scope: "user", Configurable: true}}}}})
	if err != nil {
		t.Fatal(err)
	}
	req := GrantRequest{PluginInstanceID: "plugin", ActiveFingerprint: "fingerprint", PolicyRevision: 1, ManagementRevision: 1, RevokeEpoch: 1, ResourceScope: userResourceScope(), ConnectorID: "service", Transport: TransportHTTP, Destination: server.URL, HTTPMethod: "GET", Binding: &ApprovedBinding{ConnectionID: "connection", Revision: 1, Destination: server.URL, HTTPMethods: []string{"GET"}, ExpiresAt: time.Now().Add(time.Hour)}}
	if _, err := MintConnectionGrant(connectivityTestContext("env_hash", "user_hash"), policy, req); !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("unapproved loopback: %v", err)
	}
	req.Binding.PrivatePrefixes = []string{"127.0.0.1/32"}
	grant, err := MintConnectionGrant(connectivityTestContext("env_hash", "user_hash"), policy, req)
	if err != nil {
		t.Fatal(err)
	}
	executor := NewExecutor(ExecutorOptions{})
	defer executor.Close(context.Background())
	response, err := executor.OpenHTTP(context.Background(), HTTPRequest{Grant: grant, Method: "GET", RequestURI: "/signed%2fpath?q=%2f"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "/signed%2fpath?q=%2f" || received.Load() != 1 {
		t.Fatalf("response %q %v, received %d", body, err, received.Load())
	}
	grant.Destination.Host = "private.example.com"
	mixed := NewExecutor(ExecutorOptions{LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("8.8.8.8")}}, nil
	}})
	defer mixed.Close(context.Background())
	if _, err := mixed.OpenHTTP(context.Background(), HTTPRequest{Grant: grant, Method: "GET"}); !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("mixed DNS accepted: %v", err)
	}
	if received.Load() != 1 {
		t.Fatal("rejected DNS answer still reached receiver")
	}
	if _, err := guardedResolveAddresses(nil)(context.Background(), "tcp", server.Listener.Addr().String()); !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("public resolver widened: %v", err)
	}
}
func TestPrivateApprovalRejectsBroadMetadataAndAmbiguousPrefixes(t *testing.T) {
	for _, values := range [][]string{{"0.0.0.0/0"}, {"169.254.0.0/16"}, {"::/0"}, {"fe80::/10"}, {"10.0.0.1/8"}, {"127.0.0.1/32", "127.0.0.1/32"}, {"8.8.8.8/32"}} {
		if err := ValidatePrivatePrefixes(values); err == nil {
			t.Errorf("accepted %v", values)
		}
	}
	for _, values := range [][]string{{"127.0.0.1/32"}, {"10.0.0.0/8"}, {"::1/128"}, {"fd00::/64"}} {
		if err := ValidatePrivatePrefixes(values); err != nil {
			t.Errorf("denied %v: %v", values, err)
		}
	}
}
