package externalsource

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type noLocalDNS struct{ calls atomic.Int32 }

func (r *noLocalDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls.Add(1)
	return nil, errors.New("host transport owns DNS")
}

func TestHostTransportUsesHostDNSAndPrivateHTTPS(t *testing.T) {
	content := []byte("verified plugin bytes")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("encoding = %q", r.Header.Get("Accept-Encoding"))
		}
		_, _ = w.Write(content)
	}))
	defer server.Close()
	stage, err := NewStageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	dns := &noLocalDNS{}
	fetcher, err := NewFetcher(FetcherOptions{Stage: stage, Resolver: dns, Transport: server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	result, err := fetcher.FetchArtifact(context.Background(), ArtifactFetchRequest{URL: server.URL + "/plugin", AllowedHosts: []string{"127.0.0.1"}, MaxBytes: 1024, ExpectedSize: int64(len(content)), ExpectedSHA256: hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Bytes) != string(content) || dns.calls.Load() != 0 {
		t.Fatalf("bytes=%q DNS calls=%d", result.Bytes, dns.calls.Load())
	}
}

func TestHostTransportPreservesProxyDNSAndTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "package") }))
	defer origin.Close()
	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "example.com:443" {
			t.Errorf("proxy request = %s %s", r.Method, r.Host)
			http.Error(w, "invalid CONNECT", 400)
			return
		}
		connects.Add(1)
		upstream, err := net.Dial("tcp", origin.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			http.Error(w, "dial", 502)
			return
		}
		downstream, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			t.Error(err)
			return
		}
		defer downstream.Close()
		defer upstream.Close()
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffer.Flush()
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffer); upstream.Close(); close(done) }()
		_, _ = io.Copy(downstream, upstream)
		downstream.Close()
		<-done
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := origin.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	dns := &noLocalDNS{}
	stage, err := NewStageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	fetcher, err := NewFetcher(FetcherOptions{Stage: stage, Resolver: dns, Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	result, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://example.com/plugin"})
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Remove(result.Artifact)
	if connects.Load() != 1 || dns.calls.Load() != 0 {
		t.Fatalf("CONNECTs=%d local DNS=%d", connects.Load(), dns.calls.Load())
	}
	fetcher.transport.(*http.Transport).CloseIdleConnections()
}

func TestHostTransportKeepsRedirectAndCredentialOwnership(t *testing.T) {
	stage, err := NewStageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	credentials := &recordingCredentials{}
	var calls int
	transport := githubRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+r.URL.Hostname() || r.Header.Get("Cookie") != "" {
			t.Fatalf("credentials = %v", r.Header)
		}
		if calls == 1 {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://mirror.corp/plugin?secret=temporary"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("package"))}, nil
	})
	fetcher, err := NewFetcher(FetcherOptions{Stage: stage, Transport: transport, Credentials: credentials, Resolver: &noLocalDNS{}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.corp/plugin"})
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Remove(result.Artifact)
	if calls != 2 || len(credentials.origins) != 2 || strings.Contains(result.Final, "temporary") {
		t.Fatalf("result = %#v calls=%d", result, calls)
	}
	calls = 0
	digest := sha256.Sum256([]byte("package"))
	_, err = fetcher.FetchArtifact(context.Background(), ArtifactFetchRequest{URL: "https://source.corp/plugin", AllowedHosts: []string{"source.corp"}, MaxBytes: 1024, ExpectedSize: 7, ExpectedSHA256: hex.EncodeToString(digest[:])})
	if CodeOf(err) != ErrorTargetBlocked || calls != 1 {
		t.Fatalf("undeclared redirect err=%v calls=%d", err, calls)
	}
}

func TestHostTransportRejectsTLSBypassAndHiddenRedirects(t *testing.T) {
	stage, err := NewStageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if _, err := NewFetcher(FetcherOptions{Stage: stage, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}); CodeOf(err) != ErrorInvalidSource {
		t.Fatalf("TLS bypass error=%v", err)
	}
	other, _ := http.NewRequest(http.MethodGet, "https://other.example/plugin", nil)
	fetcher, err := NewFetcher(FetcherOptions{Stage: stage, Transport: githubRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Request: other, Body: io.NopCloser(strings.NewReader("package"))}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.example/plugin"})
	if CodeOf(err) != ErrorRedirectDenied {
		t.Fatalf("hidden redirect error=%v", err)
	}
}

func TestHostTransportHonorsCancellationAndStreamingLimit(t *testing.T) {
	stage, err := NewStageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	started := make(chan struct{})
	fetcher, err := NewFetcher(FetcherOptions{Stage: stage, Transport: githubRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := fetcher.FetchPackage(ctx, FetchRequest{URL: "https://source.example/plugin"})
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
	fetcher.transport = githubRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("12345")), ContentLength: -1}, nil
	})
	fetcher.maxBytes = 4
	_, err = fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.example/plugin"})
	if CodeOf(err) != ErrorArtifactTooLarge {
		t.Fatalf("limit error=%v", err)
	}
}

func TestHostTransportRejectsTypedNilAndPreservesCallerOwnership(t *testing.T) {
	stage, err := NewStageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	var absent githubRoundTripFunc
	if _, err := NewFetcher(FetcherOptions{Stage: stage, Transport: absent}); CodeOf(err) != ErrorInvalidSource {
		t.Fatalf("nil adapter error = %v", err)
	}
	caller := &ownedHostTransport{}
	fetcher, err := NewFetcher(FetcherOptions{Stage: stage, Transport: caller})
	if err != nil {
		t.Fatal(err)
	}
	fetcher.CloseIdleConnections()
	if caller.closed {
		t.Fatal("fetcher closed caller transport")
	}
	base := &http.Transport{}
	fetcher, err = NewFetcher(FetcherOptions{Stage: stage, Transport: base})
	if err != nil {
		t.Fatal(err)
	}
	defer fetcher.CloseIdleConnections()
	configured := fetcher.transport.(*http.Transport)
	if configured == base || configured.IdleConnTimeout <= 0 || base.IdleConnTimeout != 0 || (base.TLSClientConfig != nil && base.TLSClientConfig.MinVersion != 0) || base.DisableCompression {
		t.Fatalf("transport clone: same=%v idle=%v callerIdle=%v callerTLS=%+v callerCompression=%v", configured == base, configured.IdleConnTimeout, base.IdleConnTimeout, base.TLSClientConfig, base.DisableCompression)
	}
}

type ownedHostTransport struct{ closed bool }

func (*ownedHostTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}
func (transport *ownedHostTransport) CloseIdleConnections() { transport.closed = true }

func TestHostTransportStillVerifiesCertificatesAndArtifactHashes(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "package") }))
	defer server.Close()
	stage, err := NewStageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	fetcher, err := NewFetcher(FetcherOptions{Stage: stage, Transport: &http.Transport{}})
	if err != nil {
		t.Fatal(err)
	}
	defer fetcher.CloseIdleConnections()
	if _, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: server.URL + "/plugin"}); CodeOf(err) != ErrorTransport {
		t.Fatalf("untrusted certificate error = %v", err)
	}
	trusted, err := NewFetcher(FetcherOptions{Stage: stage, Transport: server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	defer trusted.CloseIdleConnections()
	_, err = trusted.FetchArtifact(context.Background(), ArtifactFetchRequest{URL: server.URL + "/plugin", AllowedHosts: []string{"127.0.0.1"}, MaxBytes: 1024, ExpectedSize: 7, ExpectedSHA256: strings.Repeat("0", 64)})
	if CodeOf(err) != ErrorStageIntegrity {
		t.Fatalf("changed package hash error = %v", err)
	}
}
