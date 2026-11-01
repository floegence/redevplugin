package connectivity

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHostHTTPSUsesNormalRoutingAfterGrantValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			t.Errorf("host = %s", r.Host)
		}
		_, _ = io.WriteString(w, "weather")
	}))
	defer server.Close()
	var dnsCalls, factoryCalls atomic.Int32
	factory := func(destination Destination, config *tls.Config) (HTTPTransport, error) {
		factoryCalls.Add(1)
		if destination.Host != "example.com" {
			t.Errorf("destination = %v", destination)
		}
		transport := server.Client().Transport.(*http.Transport).Clone()
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
		return transport, nil
	}
	executor := NewExecutor(ExecutorOptions{HostHTTPTransport: factory, LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
		dnsCalls.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("198.18.0.66")}}, nil
	}})
	defer func() { _ = executor.Close(context.Background()) }()
	grant := testGrant(t, TransportHTTP, "https://example.com", time.Minute)
	response, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: grant})
	if err != nil || string(response.Body) != "weather" {
		t.Fatalf("host HTTPS = %q %v", response.Body, err)
	}
	if dnsCalls.Load() != 0 || factoryCalls.Load() != 1 {
		t.Fatalf("DNS %d factory %d", dnsCalls.Load(), factoryCalls.Load())
	}
	invalid := grant
	invalid.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: invalid}); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("expired grant = %v", err)
	}
	grant.HTTPMethods = []string{"GET"}
	if _, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: grant, Method: "POST"}); !errors.Is(err, ErrConnectorDenied) {
		t.Fatalf("method grant = %v", err)
	}
	if factoryCalls.Load() != 1 {
		t.Fatal("invalid authority reached host transport")
	}
}

type observedHTTPTransport struct {
	call   func(*http.Request) (*http.Response, error)
	closed atomic.Int32
}

func (transport *observedHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport.call(request)
}
func (transport *observedHTTPTransport) CloseIdleConnections() { transport.closed.Add(1) }
func httpResult(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestHostHTTPSKeepsPoolIdentityRetirementAndLimits(t *testing.T) {
	var transports []*observedHTTPTransport
	executor := NewExecutor(ExecutorOptions{MaxResponseBytes: 4, HostHTTPTransport: func(Destination, *tls.Config) (HTTPTransport, error) {
		transport := &observedHTTPTransport{call: func(*http.Request) (*http.Response, error) { return httpResult("abc"), nil }}
		transports = append(transports, transport)
		return transport, nil
	}})
	grant := testGrant(t, TransportHTTP, "https://example.com", time.Minute)
	for i := 0; i < 2; i++ {
		if _, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: grant}); err != nil {
			t.Fatal(err)
		}
	}
	if len(transports) != 1 {
		t.Fatal("same grant did not reuse pool")
	}
	grant.ManagementRevision++
	if _, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: grant}); err != nil {
		t.Fatal(err)
	}
	if len(transports) != 2 || transports[0].closed.Load() == 0 {
		t.Fatal("stale grant pool survived revision")
	}
	sibling := grant
	sibling.PluginInstanceID = "plugini_sibling"
	if _, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: sibling}); err != nil {
		t.Fatal(err)
	}
	if len(transports) != 3 || transports[1].closed.Load() != 0 {
		t.Fatal("sibling affected another live pool")
	}
	transports[1].call = func(*http.Request) (*http.Response, error) { return httpResult("12345"), nil }
	if _, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: grant}); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("response quota = %v", err)
	}
	if err := executor.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transports[1].closed.Load() == 0 || transports[2].closed.Load() == 0 {
		t.Fatal("host transport idle connections not released")
	}
}

func TestHostHTTPSPreservesPrivateAddressBinding(t *testing.T) {
	calls := 0
	executor := NewExecutor(ExecutorOptions{HostHTTPTransport: func(Destination, *tls.Config) (HTTPTransport, error) {
		calls++
		return nil, errors.New("unexpected host route")
	}, LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("198.18.0.66")}}, nil
	}})
	defer func() { _ = executor.Close(context.Background()) }()
	grant := testGrant(t, TransportHTTP, "https://example.com", time.Minute)
	grant.ConnectionID = "connection_approved"
	grant.ConnectionRevision = 1
	grant.PrivatePrefixes = []string{"10.0.0.0/8"}
	if _, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: grant}); !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("private binding = %v", err)
	}
	if calls != 0 {
		t.Fatal("host routing bypassed exact private prefixes")
	}
}

func TestHostHTTPSCancellationTLSAndRedirectBoundary(t *testing.T) {
	factoryCalls := 0
	transport := &observedHTTPTransport{call: func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	}}
	executor := NewExecutor(ExecutorOptions{HostHTTPTransport: func(Destination, *tls.Config) (HTTPTransport, error) { factoryCalls++; return transport, nil }})
	defer func() { _ = executor.Close(context.Background()) }()
	grant := testGrant(t, TransportHTTP, "https://example.com", time.Minute)
	if _, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: grant, TLSConfig: &tls.Config{InsecureSkipVerify: true}}); !errors.Is(err, ErrConnectorDenied) {
		t.Fatalf("TLS bypass = %v", err)
	}
	if factoryCalls != 0 {
		t.Fatal("invalid TLS reached factory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := executor.DoHTTP(ctx, HTTPRequest{Grant: grant}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel = %v", err)
	}
	transport.call = func(request *http.Request) (*http.Response, error) {
		result := httpResult("redirect")
		result.Request, _ = http.NewRequest("GET", "https://other.example", nil)
		return result, nil
	}
	if _, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: grant}); !errors.Is(err, ErrConnectorDenied) {
		t.Fatalf("hidden redirect = %v", err)
	}
}

func TestDefaultHTTPSStillUsesExplicitAddressPolicy(t *testing.T) {
	executor := NewExecutor(ExecutorOptions{LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.IP(netip.MustParseAddr("198.18.0.66").AsSlice())}}, nil
	}})
	defer func() { _ = executor.Close(context.Background()) }()
	_, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: testGrant(t, TransportHTTP, "https://example.com", time.Minute)})
	if !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("default address policy = %v", err)
	}
}

func TestHostHTTPSRejectsInvalidTransportConfiguration(t *testing.T) {
	var typedNil *observedHTTPTransport
	for _, transport := range []HTTPTransport{nil, typedNil, &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} {
		executor := NewExecutor(ExecutorOptions{HostHTTPTransport: func(Destination, *tls.Config) (HTTPTransport, error) { return transport, nil }})
		_, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: testGrant(t, TransportHTTP, "https://example.com", time.Minute)})
		_ = executor.Close(context.Background())
		if !errors.Is(err, ErrConnectorDenied) {
			t.Fatalf("invalid transport = %v", err)
		}
	}
}
