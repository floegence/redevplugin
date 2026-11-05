package httpadapter

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/floegence/redevplugin/v3/pkg/host"
)

func TestWebSocketRelayPreservesMessagesAndCancels(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		c.SetReadLimit(2 << 20)
		for {
			kind, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if c.Write(r.Context(), kind, data) != nil {
				return
			}
		}
	}))
	defer remote.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan struct{})
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(ended)
		upstream, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(remote.URL, "http"), nil)
		if err != nil {
			return
		}
		defer func() { _ = upstream.CloseNow() }()
		upstream.SetReadLimit(1 << 20)
		local, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = local.CloseNow() }()
		local.SetReadLimit(1 << 20)
		relayWebSocket(ctx, local, upstream)
	}))
	defer relay.Close()
	bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	client, _, err := websocket.Dial(bounded, "ws"+strings.TrimPrefix(relay.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.CloseNow() }()
	client.SetReadLimit(1 << 20)
	for _, kind := range []websocket.MessageType{websocket.MessageText, websocket.MessageBinary} {
		data := bytes.Repeat([]byte("test"), 20000)
		if err = client.Write(bounded, kind, data); err != nil {
			t.Fatal(err)
		}
		gotKind, reader, err := client.Reader(bounded)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(reader)
		if err != nil || gotKind != kind || !bytes.Equal(got, data) {
			t.Fatalf("relay changed message: %v", err)
		}
	}
	cancel()
	select {
	case <-ended:
	case <-bounded.Done():
		t.Fatal("revoked relay did not stop")
	}
}

func TestWebSocketDiscoveryRejectsUnconfinedFetch(t *testing.T) {
	r := httptest.NewRequest("GET", "https://app.example/_redevplugin_web/websocket", nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	r.Header.Set("Sec-Fetch-Mode", "no-cors")
	w := httptest.NewRecorder()
	serveWebSocket(nil, w, r, host.WebSurfaceRequest{Origin: "https://app.example"}, "websocket")
	if w.Code != http.StatusForbidden {
		t.Fatal(w.Code)
	}
}
