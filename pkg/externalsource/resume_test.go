package externalsource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

func TestInterruptedPackageResumesExactBytes(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		status       int
		contentRange string
		etag         string
		body         string
		want         string
	}{
		{"remaining bytes", 206, "bytes 5-9/10", `"first"`, "56789", "0123456789"},
		{"server restarts", 200, "", `"second"`, "replacement", "replacement"},
		{"wrong offset", 206, "bytes 4-8/10", `"first"`, "45678", ""},
		{"changed entity", 206, "bytes 5-9/10", `"second"`, "other", ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if calls.Add(1) == 1 {
					w.Header().Set("ETag", `"first"`)
					w.Header().Set("Content-Length", "10")
					_, _ = io.WriteString(w, "01234")
					return
				}
				if req.Header.Get("Range") != "bytes=5-" || req.Header.Get("If-Range") != `"first"` {
					t.Errorf("resume headers = %v", req.Header)
				}
				w.Header().Set("ETag", scenario.etag)
				if scenario.contentRange != "" {
					w.Header().Set("Content-Range", scenario.contentRange)
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(scenario.body)))
				w.WriteHeader(scenario.status)
				_, _ = io.WriteString(w, scenario.body)
			}))
			defer server.Close()
			fetcher, directory := newTestFetcher(t, nil)
			fetcher.transport = server.Client().Transport
			result, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: server.URL + "/package"})
			if calls.Load() != 2 {
				t.Fatalf("expected an exact range retry, requests=%d, err=%v", calls.Load(), err)
			}
			if scenario.want == "" {
				if CodeOf(err) != ErrorStageIntegrity {
					t.Fatalf("range validation returned %v", err)
				}
				if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
					t.Fatalf("partial files: %v, %v", entries, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := fetcher.stage.ReadArtifact(context.Background(), result.Artifact, 100)
			if err != nil || string(data) != scenario.want {
				t.Fatalf("staged %q, %v", data, err)
			}
		})
	}
}

func TestPackageResumeCancellationAndWeakValidators(t *testing.T) {
	for _, validator := range []string{`W/"weak"`, "", `"strong"`} {
		t.Run(validator, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				writer.Header().Set("Content-Length", "10")
				writer.Header().Set("ETag", validator)
				_, _ = io.WriteString(writer, "01234")
			}))
			defer server.Close()
			fetcher, directory := newTestFetcher(t, nil)
			fetcher.transport = server.Client().Transport
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var reconnects int
			_, err := fetcher.FetchPackage(ctx, FetchRequest{URL: server.URL + "/package", Reconnecting: func(received, total int64) {
				reconnects++
				if received != 5 || total != 10 {
					t.Errorf("reconnecting at %d/%d", received, total)
				}
				cancel()
			}})
			if err == nil || calls.Load() != 1 {
				t.Fatalf("err=%v, requests=%d", err, calls.Load())
			}
			if validator == `"strong"` {
				if reconnects != 1 || !errors.Is(err, context.Canceled) {
					t.Fatalf("reconnects=%d, err=%v", reconnects, err)
				}
			} else if reconnects != 0 {
				t.Fatalf("retried without a strong validator")
			}
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
				t.Fatalf("partial files: %v, %v", entries, err)
			}
		})
	}
}
