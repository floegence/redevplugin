package resourceio

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const MaxIOChunkBytes = 64 << 10

var ErrRedirectRequiresReplay = errors.New("redirect requires request body replay")

type RedirectMode string

const (
	RedirectFollow RedirectMode = "follow"
	RedirectManual RedirectMode = "manual"
	RedirectError  RedirectMode = "error"
)

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HTTPRequest struct {
	Method    string
	URL       string
	Headers   []Header
	Redirect  RedirectMode
	Timeout   time.Duration
	Authorize func(context.Context, *http.Request) error
	Transport http.RoundTripper
}

type HTTPResponse struct {
	Status   int
	Headers  []Header
	FinalURL string
	Body     io.ReadCloser
}

type HTTPUpload struct {
	mu          sync.Mutex
	writer      *io.PipeWriter
	result      <-chan httpResult
	resultOnce  sync.Once
	terminal    httpResult
	cancel      context.CancelFunc
	closed      bool
	transferred bool
	aborted     bool
}

type httpResult struct {
	response *HTTPResponse
	err      error
}

func BeginHTTP(ctx context.Context, request HTTPRequest) (*HTTPUpload, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	parsed, err := url.Parse(request.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || !validHTTPToken(request.Method) {
		return nil, errors.New("invalid HTTP request")
	}
	if request.Redirect == "" {
		request.Redirect = RedirectFollow
	}
	if request.Redirect != RedirectFollow && request.Redirect != RedirectManual && request.Redirect != RedirectError {
		return nil, errors.New("invalid HTTP redirect mode")
	}
	headers, err := normalizedHTTPHeaders(request.Headers)
	if err != nil {
		return nil, err
	}
	var requestCtx context.Context
	var cancel context.CancelFunc
	if request.Timeout > 0 {
		requestCtx, cancel = context.WithTimeout(ctx, request.Timeout)
	} else {
		requestCtx, cancel = context.WithCancel(ctx)
	}
	if request.Authorize != nil {
		if err := request.Authorize(requestCtx, &http.Request{Method: request.Method, URL: parsed}); err != nil {
			cancel()
			return nil, err
		}
	}
	pipeReader, pipeWriter := io.Pipe()
	req, err := http.NewRequestWithContext(requestCtx, request.Method, parsed.String(), pipeReader)
	if err != nil {
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		return nil, err
	}
	req.Header = headers
	result := make(chan httpResult, 1)
	if request.Transport == nil {
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		return nil, os.ErrPermission
	}
	client := &http.Client{Transport: request.Transport}
	client.CheckRedirect = func(next *http.Request, previous []*http.Request) error {
		if len(previous) >= 10 {
			return errors.New("HTTP redirect limit exceeded")
		}
		if request.Redirect != RedirectFollow {
			return http.ErrUseLastResponse
		}
		if request.Authorize != nil {
			return request.Authorize(next.Context(), next)
		}
		return nil
	}
	go func() {
		response, requestErr := client.Do(req)
		if requestErr != nil {
			_ = pipeReader.CloseWithError(requestErr)
			result <- httpResult{err: requestErr}
			return
		}
		_ = pipeReader.Close()
		if request.Redirect == RedirectError && response.StatusCode >= 300 && response.StatusCode < 400 {
			_ = response.Body.Close()
			result <- httpResult{err: errors.New("HTTP redirect is not allowed")}
			return
		}
		if request.Redirect == RedirectFollow && (response.StatusCode == http.StatusTemporaryRedirect || response.StatusCode == http.StatusPermanentRedirect) && response.Header.Get("Location") != "" {
			_ = response.Body.Close()
			result <- httpResult{err: ErrRedirectRequiresReplay}
			return
		}
		result <- httpResult{response: &HTTPResponse{
			Status:   response.StatusCode,
			Headers:  headerPairs(response.Header),
			FinalURL: response.Request.URL.String(),
			Body:     &cancelHTTPBody{ReadCloser: response.Body, cancel: cancel},
		}}
	}()
	return &HTTPUpload{writer: pipeWriter, result: result, cancel: cancel}, nil
}

func validHTTPToken(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char <= 0x20 || char >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", char) {
			return false
		}
	}
	return true
}

var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func normalizedHTTPHeaders(input []Header) (http.Header, error) {
	result := make(http.Header)
	for _, pair := range input {
		if !validHTTPToken(pair.Name) || strings.ContainsAny(pair.Value, "\r\n") {
			return nil, errors.New("invalid HTTP header")
		}
		name := http.CanonicalHeaderKey(pair.Name)
		if _, blocked := hopByHopHeaders[name]; blocked {
			continue
		}
		result.Add(name, pair.Value)
	}
	return result, nil
}

func headerPairs(headers http.Header) []Header {
	result := make([]Header, 0, len(headers))
	for name, values := range headers {
		if _, blocked := hopByHopHeaders[http.CanonicalHeaderKey(name)]; blocked {
			continue
		}
		for _, value := range values {
			result = append(result, Header{Name: name, Value: value})
		}
	}
	return result
}

func (upload *HTTPUpload) Write(value []byte) (int, error) {
	return upload.WriteChunk(context.Background(), value, 0)
}

func (upload *HTTPUpload) WriteChunk(ctx context.Context, value []byte, flags uint32) (int, error) {
	if len(value) > MaxIOChunkBytes || flags != 0 {
		return 0, ErrResourceLimit
	}
	upload.mu.Lock()
	if upload.writer == nil || upload.closed {
		upload.mu.Unlock()
		return 0, ErrResourceClosed
	}
	writer := upload.writer
	upload.mu.Unlock()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	stop := context.AfterFunc(ctx, func() { _ = upload.Abort(ctx.Err()) })
	defer stop()
	written, err := writer.Write(value)
	if err == nil {
		return written, nil
	}
	if terminal := upload.awaitResult(); terminal.err != nil {
		return written, terminal.err
	}
	return written, err
}

func (upload *HTTPUpload) Finish() (*HTTPResponse, error) {
	if upload == nil {
		return nil, ErrResourceClosed
	}
	upload.mu.Lock()
	if upload.writer == nil || upload.closed {
		upload.mu.Unlock()
		return nil, ErrResourceClosed
	}
	upload.closed = true
	writer := upload.writer
	upload.mu.Unlock()
	if err := writer.Close(); err != nil {
		result := upload.awaitResult()
		upload.cancel()
		if result.err != nil {
			return nil, result.err
		}
		return nil, err
	}
	result := upload.awaitResult()
	if result.err != nil {
		upload.cancel()
	} else {
		upload.mu.Lock()
		if upload.aborted {
			upload.mu.Unlock()
			_ = result.response.Body.Close()
			return nil, context.Canceled
		}
		upload.transferred = true
		upload.mu.Unlock()
	}
	return result.response, result.err
}

func (upload *HTTPUpload) awaitResult() httpResult {
	upload.resultOnce.Do(func() {
		upload.terminal = <-upload.result
	})
	return upload.terminal
}

func (upload *HTTPUpload) Abort(cause error) error {
	if upload == nil {
		return nil
	}
	upload.mu.Lock()
	if upload.writer == nil || upload.transferred {
		upload.mu.Unlock()
		return nil
	}
	upload.closed = true
	upload.aborted = true
	writer := upload.writer
	upload.mu.Unlock()
	if cause == nil {
		cause = context.Canceled
	}
	upload.cancel()
	err := writer.CloseWithError(cause)
	result := upload.awaitResult()
	if result.response != nil {
		err = errors.Join(err, result.response.Body.Close())
	}
	return err
}

func (upload *HTTPUpload) Close() error { return upload.Abort(context.Canceled) }

type TCPConnectOptions struct {
	Dial      func(context.Context, TCPConnectOptions) (net.Conn, error)
	Address   string
	Timeout   time.Duration
	NoDelay   bool
	KeepAlive time.Duration
}

type TCPStream struct {
	connection net.Conn
}

func OpenTCP(ctx context.Context, options TCPConnectOptions) (*TCPStream, error) {
	if options.Dial == nil {
		return nil, os.ErrPermission
	}
	connection, err := options.Dial(ctx, options)
	if err != nil {
		return nil, err
	}
	return &TCPStream{connection: connection}, nil
}

func (*TCPStream) FullDuplexResource() {}

func (stream *TCPStream) ReadChunk(ctx context.Context, p []byte) (int, uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	n, err := stream.Read(p)
	if ctx.Err() != nil {
		return n, 0, ctx.Err()
	}
	if errors.Is(err, io.EOF) {
		return n, IOFlagEOF, nil
	}
	return n, 0, err
}
func (stream *TCPStream) WriteChunk(ctx context.Context, p []byte, flags uint32) (int, error) {
	if flags != 0 {
		return 0, ErrInvalidHandle
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	n, err := stream.Write(p)
	if ctx.Err() != nil {
		return n, ctx.Err()
	}
	return n, err
}

func (stream *TCPStream) Read(destination []byte) (int, error) {
	if stream == nil || stream.connection == nil {
		return 0, ErrResourceClosed
	}
	return stream.connection.Read(destination)
}

func (stream *TCPStream) Write(source []byte) (int, error) {
	if stream == nil || stream.connection == nil {
		return 0, ErrResourceClosed
	}
	return stream.connection.Write(source)
}

type TCPShutdown string

const (
	TCPShutdownRead  TCPShutdown = "read"
	TCPShutdownWrite TCPShutdown = "write"
	TCPShutdownBoth  TCPShutdown = "both"
)

func (stream *TCPStream) Shutdown(direction TCPShutdown) error {
	if stream == nil || stream.connection == nil {
		return ErrResourceClosed
	}
	switch direction {
	case TCPShutdownRead:
		if conn, ok := stream.connection.(interface{ CloseRead() error }); ok {
			return conn.CloseRead()
		}
		return ErrInvalidHandle
	case TCPShutdownWrite:
		if conn, ok := stream.connection.(interface{ CloseWrite() error }); ok {
			return conn.CloseWrite()
		}
		return ErrInvalidHandle
	case TCPShutdownBoth:
		return stream.connection.Close()
	default:
		return ErrInvalidHandle
	}
}

func (stream *TCPStream) Close() error {
	if stream == nil || stream.connection == nil {
		return nil
	}
	return stream.connection.Close()
}

type TCPListener struct {
	listener *net.TCPListener
}

func ListenTCP(ctx context.Context, address string) (*TCPListener, error) {
	configuration := net.ListenConfig{}
	listener, err := configuration.Listen(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tcp, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		return nil, errors.New("TCP listener has an unexpected type")
	}
	return &TCPListener{listener: tcp}, nil
}

func (listener *TCPListener) Accept(ctx context.Context, noDelay bool, keepAlive time.Duration) (*TCPStream, error) {
	if listener == nil || listener.listener == nil {
		return nil, ErrResourceClosed
	}
	for {
		deadline := time.Now().Add(250 * time.Millisecond)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := listener.listener.SetDeadline(deadline); err != nil {
			return nil, err
		}
		connection, err := listener.listener.AcceptTCP()
		if err == nil {
			_ = listener.listener.SetDeadline(time.Time{})
			if err := connection.SetNoDelay(noDelay); err != nil {
				_ = connection.Close()
				return nil, err
			}
			if keepAlive > 0 {
				if err := connection.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: keepAlive}); err != nil {
					_ = connection.Close()
					return nil, err
				}
			}
			return &TCPStream{connection: connection}, nil
		}
		if networkErr, ok := err.(net.Error); !ok || !networkErr.Timeout() {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

func (listener *TCPListener) Address() string {
	if listener == nil || listener.listener == nil {
		return ""
	}
	return listener.listener.Addr().String()
}

func (listener *TCPListener) Close() error {
	if listener == nil || listener.listener == nil {
		return nil
	}
	return listener.listener.Close()
}

type UDPResource struct {
	connection DatagramConnection
}

type DatagramConnection interface {
	net.Conn
	ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error)
}

func OpenUDP(ctx context.Context, address string, timeout time.Duration, dial func(context.Context, string, time.Duration) (DatagramConnection, error)) (*UDPResource, error) {
	if dial == nil {
		return nil, os.ErrPermission
	}
	connection, err := dial(ctx, address, timeout)
	if err != nil {
		return nil, err
	}
	return &UDPResource{connection: connection}, nil
}

func (resource *UDPResource) ReadChunk(ctx context.Context, destination []byte) (int, uint32, error) {
	stop := context.AfterFunc(ctx, func() { _ = resource.Close() })
	defer stop()
	if resource == nil || resource.connection == nil {
		return 0, 0, ErrResourceClosed
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = resource.connection.SetReadDeadline(deadline)
		defer resource.connection.SetReadDeadline(time.Time{})
	}
	n, _, flags, _, err := resource.connection.ReadMsgUDP(destination, nil)
	if datagramTruncated(flags) {
		return 0, 0, ErrResourceLimit
	}
	return n, IOFlagDatagramEnd, err
}

func (resource *UDPResource) WriteChunk(ctx context.Context, source []byte, flags uint32) (int, error) {
	stop := context.AfterFunc(ctx, func() { _ = resource.Close() })
	defer stop()
	if resource == nil || resource.connection == nil {
		return 0, ErrResourceClosed
	}
	if flags != IOFlagDatagramEnd {
		return 0, ErrInvalidHandle
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = resource.connection.SetWriteDeadline(deadline)
		defer resource.connection.SetWriteDeadline(time.Time{})
	}
	return resource.connection.Write(source)
}

func (resource *UDPResource) Close() error {
	if resource == nil || resource.connection == nil {
		return nil
	}
	return resource.connection.Close()
}

func (*UDPResource) FullDuplexResource() {}

const maxWebSocketMessageBytes int64 = 64 << 20

type WebSocketOpen struct {
	Lifetime     context.Context
	Open         func(context.Context, WebSocketOpen) (WebSocketStream, http.Header, func() error, error)
	URL          string
	Headers      []Header
	Subprotocols []string
	Timeout      time.Duration
	Authorize    func(context.Context, *url.URL) error
}

type WebSocketConnection struct {
	Resource        *WebSocketResource
	Protocol        string
	ResponseHeaders []Header
}

type WebSocketResource struct {
	lifetime        context.Context
	connection      WebSocketStream
	closeConnection func() error

	readMu      sync.Mutex
	reader      io.Reader
	readerFlags uint32
	readerFirst bool
	writeMu     sync.Mutex
	writer      io.WriteCloser
	writerOwner string
}

func OpenWebSocket(ctx context.Context, request WebSocketOpen) (WebSocketConnection, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	parsed, err := url.Parse(request.URL)
	if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.Host == "" || parsed.User != nil {
		return WebSocketConnection{}, errors.New("invalid WebSocket URL")
	}
	if _, err := normalizedHTTPHeaders(request.Headers); err != nil {
		return WebSocketConnection{}, err
	}
	if request.Authorize != nil {
		if err := request.Authorize(ctx, parsed); err != nil {
			return WebSocketConnection{}, err
		}
	}
	if request.Open == nil {
		return WebSocketConnection{}, os.ErrPermission
	}
	connection, responseHeaders, closeConnection, err := request.Open(ctx, request)
	if err != nil {
		return WebSocketConnection{}, err
	}
	lifetime := request.Lifetime
	if lifetime == nil {
		lifetime = ctx
	}
	return WebSocketConnection{Resource: &WebSocketResource{lifetime: lifetime, connection: connection, closeConnection: closeConnection}, Protocol: connection.Subprotocol(), ResponseHeaders: headerPairs(responseHeaders)}, nil
}

func (*WebSocketResource) FullDuplexResource() {}

func (resource *WebSocketResource) ReadChunk(ctx context.Context, destination []byte) (int, uint32, error) {
	if resource == nil || resource.connection == nil {
		return 0, 0, ErrResourceClosed
	}
	resource.readMu.Lock()
	defer resource.readMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	stop := context.AfterFunc(ctx, func() { _ = resource.Close() })
	defer stop()
	if resource.reader == nil {
		messageType, reader, err := resource.connection.Reader(resource.lifetime)
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				return 0, IOFlagEOF, nil
			}
			return 0, 0, err
		}
		resource.reader = reader
		resource.readerFirst = true
		switch messageType {
		case websocket.MessageText:
			resource.readerFlags = IOFlagText
		case websocket.MessageBinary:
			resource.readerFlags = IOFlagBinary
		default:
			_ = resource.connection.CloseNow()
			return 0, 0, ErrInvalidHandle
		}
	}
	flags := uint32(0)
	if resource.readerFirst {
		flags = resource.readerFlags
		resource.readerFirst = false
	}
	n, err := resource.reader.Read(destination)
	if errors.Is(err, io.EOF) {
		resource.reader = nil
		resource.readerFlags = 0
		return n, flags | IOFlagMessageEnd, nil
	}
	if err != nil {
		_ = resource.connection.CloseNow()
		return 0, 0, err
	}
	return n, flags, nil
}

func (resource *WebSocketResource) WriteOwnedChunk(ctx context.Context, owner Owner, source []byte, flags uint32) (int, error) {
	if resource == nil || resource.connection == nil {
		return 0, ErrResourceClosed
	}
	resource.writeMu.Lock()
	defer resource.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	stop := context.AfterFunc(ctx, func() { _ = resource.Close() })
	defer stop()
	messageTypeFlags := flags & (IOFlagText | IOFlagBinary)
	if flags&^(IOFlagText|IOFlagBinary|IOFlagMessageEnd) != 0 || messageTypeFlags == IOFlagText|IOFlagBinary {
		return 0, ErrInvalidHandle
	}
	if resource.writer == nil {
		if messageTypeFlags == 0 {
			return 0, ErrInvalidHandle
		}
		messageType := websocket.MessageText
		if messageTypeFlags == IOFlagBinary {
			messageType = websocket.MessageBinary
		}
		writer, err := resource.connection.Writer(resource.lifetime, messageType)
		if err != nil {
			return 0, err
		}
		resource.writer = writer
		resource.writerOwner = owner.InvocationID
	} else if messageTypeFlags != 0 || resource.writerOwner != owner.InvocationID {
		_ = resource.connection.CloseNow()
		resource.writer = nil
		resource.writerOwner = ""
		return 0, ErrInvalidHandle
	}
	n, err := resource.writer.Write(source)
	if err != nil || n != len(source) {
		_ = resource.connection.CloseNow()
		resource.writer = nil
		resource.writerOwner = ""
		if err == nil {
			err = io.ErrShortWrite
		}
		return 0, err
	}
	if flags&IOFlagMessageEnd != 0 {
		if err := resource.writer.Close(); err != nil {
			_ = resource.connection.CloseNow()
			resource.writer = nil
			resource.writerOwner = ""
			return 0, err
		}
		resource.writer = nil
		resource.writerOwner = ""
	}
	return n, nil
}

func (resource *WebSocketResource) Ping(ctx context.Context) error {
	if resource == nil || resource.connection == nil {
		return ErrResourceClosed
	}
	return resource.connection.Ping(ctx)
}

func (resource *WebSocketResource) GracefulClose(code websocket.StatusCode, reason string) error {
	if resource == nil || resource.connection == nil {
		return nil
	}
	return resource.connection.Close(code, reason)
}

func (resource *WebSocketResource) Close() error {
	if resource == nil || resource.connection == nil {
		return nil
	}
	err := resource.closeConnection()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

type cancelHTTPBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelHTTPBody) Close() error { b.cancel(); return b.ReadCloser.Close() }

type WebSocketStream interface {
	Reader(context.Context) (websocket.MessageType, io.Reader, error)
	Writer(context.Context, websocket.MessageType) (io.WriteCloser, error)
	Ping(context.Context) error
	Subprotocol() string
	Close(websocket.StatusCode, string) error
	CloseNow() error
}

func (b *cancelHTTPBody) ReadChunk(ctx context.Context, p []byte) (int, uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	stop := context.AfterFunc(ctx, func() { _ = b.Close() })
	defer stop()
	n, err := b.Read(p)
	if ctx.Err() != nil {
		return n, 0, ctx.Err()
	}
	if errors.Is(err, io.EOF) {
		return n, IOFlagEOF, nil
	}
	return n, 0, err
}
