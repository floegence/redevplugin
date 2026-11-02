package host

import (
	"context"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
)

// WebSocketChannel exposes messages with bounded streaming readers and writers.
type WebSocketChannel interface {
	Reader(context.Context) (websocket.MessageType, io.Reader, error)
	Writer(context.Context, websocket.MessageType) (io.WriteCloser, error)
	Subprotocol() string
}
type WebSocketConnection struct {
	Channel WebSocketChannel
	Close   func() error
}
type WebSocketConnectionRequest struct {
	WebConnectionRequest
	ConnectionID string
	RequestURI   string
	Subprotocols []string
}

func (h *Host) GetWebSocketConnection(ctx context.Context, req WebConnectionRequest) (string, error) {
	done, err := h.ensureOpen()
	if err != nil {
		return "", err
	}
	defer done()
	inv, connector, ctx, cancel, err := h.webNetworkInvocation(ctx, req)
	if err != nil {
		return "", err
	}
	defer cancel()
	if connector.Transport != "websocket" {
		return "", connectivity.ErrConnectorDenied
	}
	_, id, err := h.webConnectionTarget(ctx, inv, connector, req.DestinationIndex, "")
	return id, err
}
func (h *Host) OpenWebSocketConnection(ctx context.Context, req WebSocketConnectionRequest) (WebSocketConnection, error) {
	done, err := h.ensureOpen()
	if err != nil {
		return WebSocketConnection{}, err
	}
	binding, _, err := h.webSurface(ctx, req.WebSurfaceRequest)
	if err != nil {
		done()
		return WebSocketConnection{}, err
	}
	releaseResource, err := h.reserveWebResource(req.WebSurfaceRequest, binding.ctx)
	if err != nil {
		done()
		return WebSocketConnection{}, err
	}
	inv, connector, ctx, cancel, err := h.webNetworkInvocation(ctx, req.WebConnectionRequest)
	if err != nil {
		releaseResource()
		done()
		return WebSocketConnection{}, err
	}
	if !inv.CanRead || !inv.CanWrite {
		cancel()
		releaseResource()
		done()
		return WebSocketConnection{}, permissions.ErrPermissionDenied
	}
	var once sync.Once
	cleanup := func() { once.Do(func() { cancel(); releaseResource(); done() }) }
	if connector.Transport != "websocket" {
		cleanup()
		return WebSocketConnection{}, connectivity.ErrConnectorDenied
	}
	target, id, err := h.webConnectionTarget(ctx, inv, connector, req.DestinationIndex, "")
	if err != nil || id != req.ConnectionID {
		cleanup()
		return WebSocketConnection{}, ErrConnectionUnavailable
	}
	path, err := url.ParseRequestURI(req.RequestURI)
	if err != nil || !strings.HasPrefix(req.RequestURI, "/") || strings.HasPrefix(req.RequestURI, "//") || path.IsAbs() || path.Host != "" || path.Fragment != "" || len(req.RequestURI) > 8192 || len(req.Subprotocols) > 16 {
		cleanup()
		return WebSocketConnection{}, connectivity.ErrInvalidConnector
	}
	destination, err := connectivity.ParseDestination(connectivity.TransportWebSocket, target)
	if err != nil {
		cleanup()
		return WebSocketConnection{}, err
	}
	endpoint := (&url.URL{Scheme: destination.Scheme, Host: net.JoinHostPort(destination.Host, strconv.Itoa(destination.Port))}).String() + req.RequestURI
	expected := ""
	if connector.Configurable {
		expected = req.ConnectionID
	}
	channel, _, closeChannel, err := h.runtimeIO.openWebSocket(ctx, inv, connector.ConnectorID, resourceio.WebSocketOpen{URL: endpoint, Subprotocols: req.Subprotocols}, expected)
	if err != nil {
		cleanup()
		return WebSocketConnection{}, err
	}
	var closeOnce sync.Once
	close := func() (err error) { closeOnce.Do(func() { err = closeChannel(); cleanup() }); return }
	// Release Host ownership even when an embedding caller abandons the channel.
	context.AfterFunc(ctx, func() { _ = close() })
	return WebSocketConnection{Channel: channel, Close: close}, nil
}
