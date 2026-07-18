package connectivity

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
)

func TestStressGateConnectivityClassifierEvidence(t *testing.T) {
	if os.Getenv("REDEVPLUGIN_STRESS_EVIDENCE_PATH") == "" {
		t.Skip("connectivity stress evidence is collected by scripts/check_redevplugin_stress.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	policy, err := CompilePolicy(CompileRequest{
		PluginInstanceID:   "plugini_stress_net",
		PluginID:           "com.example.stress.net",
		ActiveFingerprint:  "sha256:stress",
		PolicyRevision:     7,
		ManagementRevision: 11,
		RevokeEpoch:        3,
		Manifest: manifest.Manifest{NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{
			{ConnectorID: "api", Transport: "http", Scope: "user", Destinations: []string{"https://api.example.com"}},
			{ConnectorID: "api_plain", Transport: "http", Scope: "user", Destinations: []string{"http://api.example.com"}},
			{ConnectorID: "stream_plain", Transport: "websocket", Scope: "user", Destinations: []string{"ws://stream.example.com"}},
			{ConnectorID: "mysql", Transport: "tcp", Scope: "environment", Destinations: []string{"db.example.com:3306"}},
			{ConnectorID: "metrics", Transport: "udp", Scope: "environment", Destinations: []string{"metrics.example.com:8125"}},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := NewMemoryBroker()
	if err := broker.InstallPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	minted := 0
	stale := 0
	for i := 0; i < 64; i++ {
		revokeEpoch := policy.RevokeEpoch
		if i%5 == 0 {
			revokeEpoch++
		}
		_, err := broker.MintConnectionGrant(ctx, GrantRequest{
			PluginInstanceID:   policy.PluginInstanceID,
			ActiveFingerprint:  policy.ActiveFingerprint,
			ResourceScope:      userResourceScope(),
			PolicyRevision:     policy.PolicyRevision,
			ManagementRevision: policy.ManagementRevision,
			RevokeEpoch:        revokeEpoch,
			ConnectorID:        "api",
			Transport:          TransportHTTP,
			Destination:        "https://api.example.com",
			Now:                time.Date(2026, 7, 17, 16, 0, i, 0, time.UTC),
		})
		switch {
		case err == nil:
			minted++
		case errors.Is(err, ErrConnectorDenied):
			stale++
		default:
			t.Fatal(err)
		}
	}
	blocked := 0
	for _, fixture := range []string{"10.0.0.1", "100.64.0.1", "169.254.169.254", "fd00::1"} {
		addr, err := netip.ParseAddr(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if err := DefaultClassifier().EvaluateResolvedAddress(Destination{Transport: TransportTCP, Host: "db.example.com", Port: 3306}, addr); !errors.Is(err, ErrTargetDenied) {
			t.Fatalf("EvaluateResolvedAddress(%s) error = %v", fixture, err)
		}
		blocked++
	}

	runConnectivityEvidenceTest(t, "redirect", TestExecutorRejectsHTTPRedirectAndOversizedResponse)
	runConnectivityEvidenceTest(t, "dns-rebinding", TestExecutorRejectsDNSRebindingResolvedAddresses)
	runConnectivityEvidenceTest(t, "proxy-defense", TestExecutorHTTPDisablesProxyAndConnect)
	runConnectivityEvidenceTest(t, "header-validation", TestExecutorRejectsUnsafeForwardHeadersBeforeDial)
	runConnectivityEvidenceTest(t, "http-stream", TestExecutorHTTPStreamResponseChunks)
	runConnectivityEvidenceTest(t, "http-stream-request-limit", TestExecutorHTTPStreamRejectsOversizedRequestBeforeDial)
	runConnectivityEvidenceTest(t, "http-stream-response-limit", TestExecutorHTTPStreamRejectsOversizedResponse)
	runConnectivityEvidenceTest(t, "http-stream-cancel", TestExecutorHTTPStreamStopsWhenContextIsCanceled)
	runConnectivityEvidenceTest(t, "tcp", TestExecutorTCPRoundTripUsesGrantEndpoint)
	runConnectivityEvidenceTest(t, "tcp-request-limit", TestExecutorTCPRoundTripRejectsOversizedRequestBeforeDial)
	runConnectivityEvidenceTest(t, "tcp-response-limit", TestExecutorTCPRoundTripRejectsOversizedResponse)
	runConnectivityEvidenceTest(t, "tcp-cancel", TestExecutorTCPRoundTripStopsWhenContextIsCanceled)
	runConnectivityEvidenceTest(t, "udp", TestExecutorUDPRoundTripUsesConnectedDestination)
	runConnectivityEvidenceTest(t, "udp-source-pin", TestExecutorUDPRoundTripIgnoresMismatchedSource)
	runConnectivityEvidenceTest(t, "udp-rate-limit", TestExecutorUDPRoundTripRateLimitsEndpointBeforeDial)
	runConnectivityEvidenceTest(t, "websocket", TestExecutorWebSocketRoundTripUsesGrantEndpoint)
	runConnectivityEvidenceTest(t, "websocket-request-limit", TestExecutorWebSocketRoundTripRejectsOversizedRequestBeforeDial)
	runConnectivityEvidenceTest(t, "websocket-response-limit", TestExecutorWebSocketRoundTripRejectsOversizedResponse)
	runConnectivityEvidenceTest(t, "websocket-cancel", TestExecutorWebSocketRoundTripStopsWhenContextIsCanceled)

	writeConnectivityStressEvidence(t, map[string]int{
		"minted_grants":                minted,
		"stale_grant_denials":          stale,
		"blocked_resolved_ips":         blocked,
		"connector_policy_count":       len(policy.Connectors),
		"http_redirects_not_followed":  1,
		"dns_rebinding_denials":        1,
		"http_proxy_env_ignored":       1,
		"http_connect_denials":         1,
		"alt_svc_headers_dropped":      1,
		"proxy_auth_headers_dropped":   1,
		"http_stream_cancelled_reads":  1,
		"http_stream_chunks":           1,
		"http_stream_request_denials":  1,
		"http_stream_response_denials": 1,
		"http_stream_round_trips":      1,
		"tcp_cancelled_reads":          1,
		"tcp_database_round_trips":     1,
		"tcp_request_denials":          1,
		"tcp_response_denials":         1,
		"udp_round_trips":              1,
		"udp_source_mismatch_dropped":  1,
		"udp_rate_limit_denials":       1,
		"websocket_round_trips":        1,
		"websocket_request_denials":    1,
		"websocket_response_denials":   1,
		"websocket_cancelled_reads":    1,
	})
}

func runConnectivityEvidenceTest(t *testing.T, name string, test func(*testing.T)) {
	t.Helper()
	if !t.Run(name, test) {
		t.Fatalf("connectivity evidence test %s failed", name)
	}
}

func writeConnectivityStressEvidence(t *testing.T, counters map[string]int) {
	t.Helper()
	path := os.Getenv("REDEVPLUGIN_STRESS_EVIDENCE_PATH")
	if path == "" {
		return
	}
	raw, err := json.Marshal(struct {
		Category string         `json:"category"`
		Counters map[string]int `json:"counters"`
	}{Category: "connectivity_classifier", Counters: counters})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
}
