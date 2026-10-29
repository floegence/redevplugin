package connectivity

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// SocketRequest binds one persistent connection to a previously admitted target.
// Timeout bounds the complete connection, including reads and writes.
type SocketRequest struct {
	TLSConfig        *tls.Config
	Grant            ConnectionGrant
	Timeout          time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int64
	NoDelay          bool
	KeepAlive        time.Duration
}

// DatagramConnection retains message truncation information across the broker.
type DatagramConnection interface {
	net.Conn
	ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error)
}

func (e *Executor) connectionContext(ctx context.Context, grant ConnectionGrant, timeout time.Duration) (context.Context, context.CancelFunc) {
	duration := timeoutOrDefault(timeout, e.defaultTimeout)
	if remaining := grant.ExpiresAt.Sub(e.now()); remaining < duration {
		duration = remaining
	}
	return context.WithTimeout(ctx, duration)
}

func (e *Executor) OpenTCP(ctx context.Context, req SocketRequest) (net.Conn, error) {
	return e.openSocket(ctx, req, TransportTCP)
}

func (e *Executor) OpenUDP(ctx context.Context, req SocketRequest) (DatagramConnection, error) {
	conn, err := e.openSocket(ctx, req, TransportUDP)
	if err != nil {
		return nil, err
	}
	return conn.(*boundedConnection), nil
}

func (e *Executor) openSocket(ctx context.Context, req SocketRequest, transport Transport) (net.Conn, error) {
	if e == nil {
		return nil, ErrConnectionClosed
	}
	if err := validateGrantForTransport(req.Grant, transport, time.Time{}, e.now); err != nil {
		return nil, err
	}
	config, err := validatedTLSConfig(req.TLSConfig, req.Grant.Destination)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := e.connectionContext(ctx, req.Grant, req.Timeout)
	conn, err := e.dialContext(grantNetworkContext(lifetime, req.Grant), string(transport), grantEndpoint(req.Grant))
	if err != nil {
		cancel()
		return nil, err
	}
	if transport == TransportTCP {
		if tcp, ok := conn.(*net.TCPConn); ok {
			if err := tcp.SetNoDelay(req.NoDelay); err != nil {
				cancel()
				_ = conn.Close()
				return nil, err
			}
			if req.KeepAlive > 0 {
				if err := tcp.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: req.KeepAlive}); err != nil {
					cancel()
					_ = conn.Close()
					return nil, err
				}
			}
		}
	}
	if config != nil {
		encrypted := tls.Client(conn, config)
		if err := encrypted.HandshakeContext(lifetime); err != nil {
			cancel()
			_ = conn.Close()
			return nil, err
		}
		conn = encrypted
	}
	result := &boundedConnection{Conn: conn, cancel: cancel, readLeft: responseLimit(req.MaxResponseBytes, e.maxResponseBytes), writeLeft: responseLimit(req.MaxRequestBytes, e.maxRequestBytes)}
	if transport == TransportUDP {
		result.allowPacket = func() bool { return e.udpRateLimiter.AllowUDPRoundTrip(e.now(), udpRateLimitKey(req.Grant)) }
	}
	result.stop = context.AfterFunc(lifetime, func() { _ = conn.Close() })
	return result, nil
}

type boundedConnection struct {
	net.Conn
	cancel      context.CancelFunc
	stop        func() bool
	once        sync.Once
	readMu      sync.Mutex
	writeMu     sync.Mutex
	readLeft    int64
	writeLeft   int64
	allowPacket func() bool
}

func (c *boundedConnection) Close() error {
	var err error
	c.once.Do(func() { c.stop(); c.cancel(); err = c.Conn.Close() })
	return err
}
func (c *boundedConnection) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.readLeft <= 0 {
		_ = c.Close()
		return 0, ErrResponseTooLarge
	}
	if int64(len(p)) > c.readLeft {
		p = p[:c.readLeft]
	}
	n, err := c.Conn.Read(p)
	c.readLeft -= int64(n)
	return n, err
}
func (c *boundedConnection) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if int64(len(p)) > c.writeLeft {
		return 0, ErrRequestTooLarge
	}
	if c.allowPacket != nil && !c.allowPacket() {
		return 0, ErrRateLimited
	}
	n, err := c.Conn.Write(p)
	c.writeLeft -= int64(n)
	return n, err
}
func (c *boundedConnection) ReadMsgUDP(p, oob []byte) (int, int, int, *net.UDPAddr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	udp, ok := c.Conn.(DatagramConnection)
	if !ok {
		return 0, 0, 0, nil, errors.New("UDP connection does not retain datagram boundaries")
	}
	if c.readLeft <= 0 {
		_ = c.Close()
		return 0, 0, 0, nil, ErrResponseTooLarge
	}
	if int64(len(p)) > c.readLeft {
		p = p[:c.readLeft]
	}
	n, o, flags, addr, err := udp.ReadMsgUDP(p, oob)
	c.readLeft -= int64(n)
	return n, o, flags, addr, err
}
func (c *boundedConnection) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return errors.New("connection does not support half-close")
}
func (c *boundedConnection) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.New("connection does not support half-close")
}

// WebSocketOpenRequest keeps the URL path and query intact. The origin must
// match Grant; redirects never change connection authority.
type WebSocketOpenRequest struct {
	SocketRequest
	URL          string
	Headers      http.Header
	Subprotocols []string
}
type WebSocketConnection struct {
	Connection *WebSocketStream
	Headers    http.Header
	Close      func() error
}

func (e *Executor) OpenWebSocket(ctx context.Context, req WebSocketOpenRequest) (WebSocketConnection, error) {
	if e == nil {
		return WebSocketConnection{}, ErrConnectionClosed
	}
	if err := validateGrantForTransport(req.Grant, TransportWebSocket, time.Time{}, e.now); err != nil {
		return WebSocketConnection{}, err
	}
	parsed, err := url.Parse(req.URL)
	if err != nil || parsed.User != nil || parsed.Fragment != "" {
		return WebSocketConnection{}, ErrInvalidConnector
	}
	destination, err := ParseDestination(TransportWebSocket, (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String())
	if err != nil || destination != req.Grant.Destination {
		return WebSocketConnection{}, ErrConnectorDenied
	}
	if _, err := url.ParseRequestURI(req.URL); err != nil {
		return WebSocketConnection{}, ErrInvalidConnector
	}
	headers, err := validateForwardHeaders(req.Headers)
	if err != nil {
		return WebSocketConnection{}, err
	}
	lifetime, cancel := e.connectionContext(ctx, req.Grant, req.Timeout)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return e.dialContext(grantNetworkContext(ctx, req.Grant), network, address)
	}, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 64 << 10}
	if req.TLSConfig != nil {
		config, err := validatedTLSConfig(req.TLSConfig, req.Grant.Destination)
		if err != nil {
			cancel()
			return WebSocketConnection{}, err
		}
		transport.TLSClientConfig = config
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	conn, response, err := websocket.Dial(lifetime, req.URL, &websocket.DialOptions{HTTPClient: client, HTTPHeader: headers, Subprotocols: append([]string(nil), req.Subprotocols...)})
	if err != nil {
		cancel()
		transport.CloseIdleConnections()
		return WebSocketConnection{}, err
	}
	conn.SetReadLimit(responseLimit(req.MaxResponseBytes, e.maxResponseBytes))
	stop := context.AfterFunc(lifetime, func() { _ = conn.CloseNow() })
	var once sync.Once
	closeConnection := func() error {
		var closeErr error
		once.Do(func() { stop(); cancel(); closeErr = conn.CloseNow(); transport.CloseIdleConnections() })
		return closeErr
	}
	result := WebSocketConnection{Connection: &WebSocketStream{conn: conn, maxWrite: responseLimit(req.MaxRequestBytes, e.maxRequestBytes)}, Close: closeConnection}
	if response != nil {
		result.Headers = cloneHTTPHeader(response.Header)
	}
	return result, nil
}

var _ io.ReadWriteCloser = (*boundedConnection)(nil)

// WebSocketStream preserves native messages while enforcing the executor's
// request budget. Reader message limits are enforced by the protocol library.
type WebSocketStream struct {
	conn     *websocket.Conn
	maxWrite int64
}

func (s *WebSocketStream) Subprotocol() string { return s.conn.Subprotocol() }
func (s *WebSocketStream) Reader(ctx context.Context) (websocket.MessageType, io.Reader, error) {
	return s.conn.Reader(ctx)
}
func (s *WebSocketStream) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	return s.conn.Read(ctx)
}
func (s *WebSocketStream) Write(ctx context.Context, kind websocket.MessageType, p []byte) error {
	if int64(len(p)) > s.maxWrite {
		return ErrRequestTooLarge
	}
	return s.conn.Write(ctx, kind, p)
}
func (s *WebSocketStream) Writer(ctx context.Context, kind websocket.MessageType) (io.WriteCloser, error) {
	writer, err := s.conn.Writer(ctx, kind)
	if err != nil {
		return nil, err
	}
	return &webSocketWriter{WriteCloser: writer, remaining: s.maxWrite, abort: s.conn.CloseNow}, nil
}
func (s *WebSocketStream) Ping(ctx context.Context) error { return s.conn.Ping(ctx) }
func (s *WebSocketStream) Close(code websocket.StatusCode, reason string) error {
	return s.conn.Close(code, reason)
}
func (s *WebSocketStream) CloseNow() error { return s.conn.CloseNow() }

type webSocketWriter struct {
	io.WriteCloser
	remaining int64
	abort     func() error
}

func (w *webSocketWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		_ = w.abort()
		return 0, ErrRequestTooLarge
	}
	n, err := w.WriteCloser.Write(p)
	w.remaining -= int64(n)
	return n, err
}
