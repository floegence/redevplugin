package connectivity

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOpenHTTPReturnsHeadersBeforeBodyAndCancels(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Streaming", "yes")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = w.Write([]byte("body"))
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)
	executor := newTestExecutor(ExecutorOptions{}, mapDialer(server.Listener.Addr().String()))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := executor.OpenHTTP(ctx, HTTPRequest{Grant: testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.Headers.Get("X-Streaming") != "yes" {
		t.Fatal("headers were not available before body")
	}
	cancel()
	if _, err := io.ReadAll(response.Body); err == nil {
		t.Fatal("canceled body remained readable")
	}
}

func TestOpenHTTPBoundsStreamingBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("12345")) }))
	defer server.Close()
	executor := newTestExecutor(ExecutorOptions{MaxResponseBytes: 4}, mapDialer(server.Listener.Addr().String()))
	response, err := executor.OpenHTTP(context.Background(), HTTPRequest{Grant: testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if !errors.Is(err, ErrResponseTooLarge) || len(data) > 4 {
		t.Fatalf("bounded read = %q, %v", data, err)
	}
}

func TestOpenHTTPPreservesEscapedPathAndRawQuery(t *testing.T) {
	expected := "/a%2fb/%E4%B8%AD?x=a+b&x=a%20b&flag&signature=abc%2fdef"
	observed := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.RequestURI
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	executor := newTestExecutor(ExecutorOptions{}, mapDialer(server.Listener.Addr().String()))
	response, err := executor.OpenHTTP(context.Background(), HTTPRequest{Grant: testGrant(t, TransportHTTP, "http://api.example.com", time.Minute), RequestURI: expected})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if got := <-observed; got != expected {
		t.Fatalf("request URI %q, want %q", got, expected)
	}
}
