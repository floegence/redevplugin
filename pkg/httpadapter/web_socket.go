package httpadapter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/coder/websocket"
	"github.com/floegence/redevplugin/v3/pkg/host"
)

func serveWebSocket(platform *host.Host, w http.ResponseWriter, r *http.Request, session host.WebSurfaceRequest, route string) {
	if r.Method != http.MethodGet || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != session.Origin {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	index := 0
	if value := r.URL.Query().Get("destination_index"); value != "" {
		var err error
		index, err = strconv.Atoi(value)
		if err != nil || index < 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	req := host.WebConnectionRequest{WebSurfaceRequest: session, ConnectorID: r.URL.Query().Get("connector_id"), DestinationIndex: index}
	if route == "websocket" {
		if r.Header.Get("Sec-Fetch-Site") != "same-origin" || r.Header.Get("Sec-Fetch-Dest") != "empty" || (r.Header.Get("Sec-Fetch-Mode") != "cors" && r.Header.Get("Sec-Fetch-Mode") != "same-origin") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		id, err := platform.GetWebSocketConnection(r.Context(), req)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"connection_id": id})
		return
	}
	// Chromium WebSocket handshakes omit Fetch Metadata. Exact Origin and the
	// authenticated, generation-bound Surface cookie remain mandatory.
	if r.Header.Get("Origin") != session.Origin || (r.Header.Get("Sec-Fetch-Mode") != "" && r.Header.Get("Sec-Fetch-Mode") != "websocket") || (r.Header.Get("Sec-Fetch-Dest") != "" && r.Header.Get("Sec-Fetch-Dest") != "empty") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	protocols := []string{}
	for _, header := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(header, ",") {
			protocols = append(protocols, strings.TrimSpace(protocol))
		}
	}
	for _, p := range protocols {
		if len(p) > 128 || strings.ContainsAny(p, "\r\n") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	remote, err := platform.OpenWebSocketConnection(ctx, host.WebSocketConnectionRequest{WebConnectionRequest: req, ConnectionID: r.URL.Query().Get("connection_id"), RequestURI: r.URL.Query().Get("path"), Subprotocols: protocols})
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	defer func() { _ = remote.Close() }()
	selected := []string{}
	if p := remote.Channel.Subprotocol(); p != "" {
		selected = []string{p}
	}
	local, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: selected})
	if err != nil {
		return
	}
	defer func() { _ = local.CloseNow() }()
	local.SetReadLimit(1 << 20)
	relayWebSocket(ctx, local, remote.Channel)
}

func relayWebSocket(parent context.Context, local *websocket.Conn, remote host.WebSocketChannel) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{}, 2)
	copyMessages := func(source host.WebSocketChannel, destination host.WebSocketChannel) {
		for {
			kind, reader, err := source.Reader(ctx)
			if err != nil {
				done <- struct{}{}
				return
			}
			writer, err := destination.Writer(ctx, kind)
			if err != nil {
				done <- struct{}{}
				return
			}
			n, err := io.CopyBuffer(writer, io.LimitReader(reader, (1<<20)+1), make([]byte, 32<<10))
			if err == nil && n > 1<<20 {
				err = io.ErrShortBuffer
			}
			if err != nil {
				done <- struct{}{}
				return
			}
			if err := writer.Close(); err != nil {
				done <- struct{}{}
				return
			}
		}
	}
	go copyMessages(local, remote)
	go copyMessages(remote, local)
	<-done
	cancel()
	_ = local.CloseNow()
	<-done
}
