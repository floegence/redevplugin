package externalsource

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
)

type recordingCredentials struct {
	origins []Origin
}

func (provider *recordingCredentials) CredentialFor(_ context.Context, request CredentialRequest) (http.Header, error) {
	provider.origins = append(provider.origins, request.Origin)
	return http.Header{"Authorization": {"Bearer " + request.Origin.Host}}, nil
}

func newTestFetcher(t *testing.T, resolver AddressResolver) (*Fetcher, string) {
	t.Helper()
	directory := t.TempDir()
	stage, err := NewStageStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stage.Close() })
	fetcher, err := NewFetcher(FetcherOptions{Stage: stage, Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	return fetcher, directory
}

func TestFetcherRevalidatesRedirectAndScopesCredentials(t *testing.T) {
	resolver := staticResolver{
		"source.example": {netip.MustParseAddr("1.1.1.1")},
		"cdn.example":    {netip.MustParseAddr("8.8.8.8")},
	}
	fetcher, _ := newTestFetcher(t, resolver)
	credentials := &recordingCredentials{}
	fetcher.credentials = credentials
	var calls int
	fetcher.roundTrip = func(_ context.Context, locator PackageURL, _ []netip.Addr, headers http.Header) (*http.Response, error) {
		calls++
		if got, want := headers.Get("Accept-Encoding"), "identity"; got != want {
			t.Fatalf("Accept-Encoding = %q, want %q", got, want)
		}
		if got, want := headers.Get("Authorization"), "Bearer "+locator.Origin().Host; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		if calls == 1 {
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": {"https://cdn.example/plugin.redevplugin?token=redirect-secret"}},
				Body:       io.NopCloser(strings.NewReader("redirect")),
			}, nil
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("package-bytes")),
			ContentLength: -1,
		}, nil
	}

	result, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.example/plugin.redevplugin"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fetcher.stage.Remove(result.Artifact) })
	if calls != 2 || len(credentials.origins) != 2 || credentials.origins[0].Host == credentials.origins[1].Host {
		t.Fatalf("calls=%d credential origins=%v", calls, credentials.origins)
	}
	if strings.Contains(result.Final, "redirect-secret") || strings.Contains(result.Source, "redirect-secret") {
		t.Fatalf("result leaked signed query: %#v", result)
	}
	if len(result.Redirects) != 1 || strings.Contains(result.Redirects[0].To, "redirect-secret") {
		t.Fatalf("redirect provenance leaked signed query: %#v", result.Redirects)
	}
}

func TestFetcherBlocksRedirectBeforeSecondRequest(t *testing.T) {
	resolver := staticResolver{
		"source.example":  {netip.MustParseAddr("1.1.1.1")},
		"private.example": {netip.MustParseAddr("10.0.0.1")},
	}
	fetcher, _ := newTestFetcher(t, resolver)
	var calls int
	fetcher.roundTrip = func(_ context.Context, _ PackageURL, _ []netip.Addr, _ http.Header) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": {"https://private.example/plugin.redevplugin"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
		}, nil
	}
	_, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.example/plugin.redevplugin"})
	if CodeOf(err) != ErrorTargetBlocked || calls != 1 {
		t.Fatalf("code=%q calls=%d err=%v", CodeOf(err), calls, err)
	}
}

func TestFetcherEnforcesStreamingLimitAndCleansStage(t *testing.T) {
	fetcher, directory := newTestFetcher(t, staticResolver{"source.example": {netip.MustParseAddr("1.1.1.1")}})
	fetcher.maxBytes = 4
	fetcher.roundTrip = func(_ context.Context, _ PackageURL, _ []netip.Addr, _ http.Header) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("12345")), ContentLength: -1}, nil
	}
	_, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.example/plugin.redevplugin"})
	if CodeOf(err) != ErrorArtifactTooLarge {
		t.Fatalf("code=%q err=%v", CodeOf(err), err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("stage entries=%v readErr=%v", entries, readErr)
	}
}

func TestFetcherEnforcesOwnerAndGlobalConcurrencyQuotas(t *testing.T) {
	stage, err := NewStageStoreWithOptions(t.TempDir(), StageStoreOptions{
		MaxConcurrentFetches: 2, MaxOwnerConcurrentFetches: 1,
		MaxStagedBytes: defaultMaxStagedBytes, MaxOwnerStagedBytes: defaultMaxOwnerStagedBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stage.Close() })
	fetcher, err := NewFetcher(FetcherOptions{Stage: stage, Resolver: staticResolver{"source.example": {netip.MustParseAddr("1.1.1.1")}}})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	fetcher.roundTrip = func(_ context.Context, _ PackageURL, _ []netip.Addr, _ http.Header) (*http.Response, error) {
		started <- struct{}{}
		<-release
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("x")), ContentLength: 1}, nil
	}

	type fetchOutcome struct {
		result FetchResult
		err    error
	}
	results := make(chan fetchOutcome, 2)
	var callers sync.WaitGroup
	start := func(owner string) {
		callers.Add(1)
		go func() {
			defer callers.Done()
			result, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.example/plugin.redevplugin", QuotaKey: owner})
			results <- fetchOutcome{result: result, err: err}
		}()
	}
	start("owner-a")
	<-started
	if _, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.example/plugin.redevplugin", QuotaKey: "owner-a"}); CodeOf(err) != ErrorQuotaExceeded {
		t.Fatalf("owner concurrency code = %q, err = %v", CodeOf(err), err)
	}
	start("owner-b")
	<-started
	if _, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.example/plugin.redevplugin", QuotaKey: "owner-c"}); CodeOf(err) != ErrorQuotaExceeded {
		t.Fatalf("global concurrency code = %q, err = %v", CodeOf(err), err)
	}
	close(release)
	callers.Wait()
	close(results)
	for outcome := range results {
		if outcome.err != nil {
			t.Fatal(outcome.err)
		}
		if err := stage.Remove(outcome.result.Artifact); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFetcherRejectsEncodedResponseAndRedactsTransportCause(t *testing.T) {
	fetcher, _ := newTestFetcher(t, staticResolver{"source.example": {netip.MustParseAddr("1.1.1.1")}})
	fetcher.roundTrip = func(_ context.Context, _ PackageURL, _ []netip.Addr, _ http.Header) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Encoding": {"gzip"}},
			Body:       io.NopCloser(strings.NewReader("encoded")),
		}, nil
	}
	_, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.example/plugin.redevplugin"})
	if CodeOf(err) != ErrorUnsupportedEncoding {
		t.Fatalf("code=%q err=%v", CodeOf(err), err)
	}

	fetcher.roundTrip = func(_ context.Context, _ PackageURL, _ []netip.Addr, _ http.Header) (*http.Response, error) {
		return nil, fmt.Errorf("transport included token=super-secret")
	}
	_, err = fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://source.example/plugin.redevplugin"})
	if CodeOf(err) != ErrorTransport || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("transport error was not redacted: %v", err)
	}
}

func TestCredentialHeadersRejectTransportOverrides(t *testing.T) {
	fetcher, _ := newTestFetcher(t, staticResolver{})
	fetcher.credentials = credentialProviderFunc(func(context.Context, CredentialRequest) (http.Header, error) {
		return http.Header{"Host": {"attacker.example"}}, nil
	})
	_, err := fetcher.credentialHeaders(context.Background(), Origin{Scheme: "https", Host: "example.com", Port: 443})
	if CodeOf(err) != ErrorCredentialDenied {
		t.Fatalf("code=%q err=%v", CodeOf(err), err)
	}
}

func TestSecureRoundTripPinsAddressAndVerifiesOriginalHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	fetcher, _ := newTestFetcher(t, nil)
	fetcher.rootCAs = pool
	locator, err := ParseDirectPackageURL("https://example.com:" + port + "/plugin.redevplugin")
	if err != nil {
		t.Fatal(err)
	}
	response, err := fetcher.secureRoundTrip(context.Background(), locator, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, http.Header{"Accept-Encoding": {"identity"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()

	wrongHost, err := ParseDirectPackageURL("https://wrong.example:" + port + "/plugin.redevplugin")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fetcher.secureRoundTrip(context.Background(), wrongHost, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, http.Header{"Accept-Encoding": {"identity"}})
	if err == nil {
		t.Fatal("TLS handshake unexpectedly accepted a certificate for a different hostname")
	}
}

type credentialProviderFunc func(context.Context, CredentialRequest) (http.Header, error)

func (function credentialProviderFunc) CredentialFor(ctx context.Context, request CredentialRequest) (http.Header, error) {
	return function(ctx, request)
}

func TestCodeOfFindsWrappedTypedError(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", externalError(ErrorDNS, "resolve", "", errors.New("dns")))
	if CodeOf(err) != ErrorDNS {
		t.Fatalf("CodeOf() = %q", CodeOf(err))
	}
}
