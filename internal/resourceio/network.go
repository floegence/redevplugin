package resourceio

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
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
	Authorize func(context.Context, *url.URL) error
}

type HTTPResponse struct {
	Status   int
	Headers  []Header
	FinalURL string
	Body     io.ReadCloser
}

type HTTPUpload struct {
	mu         sync.Mutex
	writer     *io.PipeWriter
	result     <-chan httpResult
	resultOnce sync.Once
	terminal   httpResult
	cancel     context.CancelFunc
	closed     bool
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
	requestCtx, cancel := context.WithCancel(ctx)
	if request.Timeout > 0 {
		requestCtx, cancel = context.WithTimeout(ctx, request.Timeout)
	}
	if request.Authorize != nil {
		if err := request.Authorize(requestCtx, parsed); err != nil {
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
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: transport}
	client.CheckRedirect = func(next *http.Request, previous []*http.Request) error {
		if len(previous) >= 10 {
			return errors.New("HTTP redirect limit exceeded")
		}
		if request.Redirect != RedirectFollow {
			return http.ErrUseLastResponse
		}
		if request.Authorize != nil {
			return request.Authorize(next.Context(), next.URL)
		}
		return nil
	}
	go func() {
		defer transport.CloseIdleConnections()
		response, requestErr := client.Do(req)
		if requestErr != nil {
			_ = pipeReader.CloseWithError(requestErr)
			result <- httpResult{err: requestErr}
			return
		}
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
			Body:     response.Body,
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
	if upload.writer == nil || upload.closed {
		upload.mu.Unlock()
		return nil
	}
	upload.closed = true
	writer := upload.writer
	upload.mu.Unlock()
	if cause == nil {
		cause = context.Canceled
	}
	upload.cancel()
	return writer.CloseWithError(cause)
}

func (upload *HTTPUpload) Close() error { return upload.Abort(context.Canceled) }

type TCPConnectOptions struct {
	Address   string
	Timeout   time.Duration
	NoDelay   bool
	KeepAlive time.Duration
}

type TCPStream struct {
	connection *net.TCPConn
}

func OpenTCP(ctx context.Context, options TCPConnectOptions) (*TCPStream, error) {
	dialer := net.Dialer{Timeout: options.Timeout, KeepAlive: options.KeepAlive}
	connection, err := dialer.DialContext(ctx, "tcp", options.Address)
	if err != nil {
		return nil, err
	}
	tcp, ok := connection.(*net.TCPConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("TCP socket has an unexpected type")
	}
	if err := tcp.SetNoDelay(options.NoDelay); err != nil {
		_ = tcp.Close()
		return nil, err
	}
	return &TCPStream{connection: tcp}, nil
}

func (*TCPStream) FullDuplexResource() {}

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
		return stream.connection.CloseRead()
	case TCPShutdownWrite:
		return stream.connection.CloseWrite()
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
	connection *net.UDPConn
}

func OpenUDP(ctx context.Context, address string, timeout time.Duration) (*UDPResource, error) {
	destination, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "udp", destination.String())
	if err != nil {
		return nil, err
	}
	udp, ok := connection.(*net.UDPConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("connected UDP socket has an unexpected type")
	}
	return &UDPResource{connection: udp}, nil
}

func (resource *UDPResource) ReadChunk(ctx context.Context, destination []byte) (int, uint32, error) {
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
	connection *websocket.Conn

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
	headers, err := normalizedHTTPHeaders(request.Headers)
	if err != nil {
		return WebSocketConnection{}, err
	}
	if request.Authorize != nil {
		if err := request.Authorize(ctx, parsed); err != nil {
			return WebSocketConnection{}, err
		}
	}
	dialCtx := ctx
	if request.Timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, request.Timeout)
		defer cancel()
	}
	connection, response, err := websocket.Dial(dialCtx, parsed.String(), &websocket.DialOptions{HTTPHeader: headers, Subprotocols: append([]string(nil), request.Subprotocols...)})
	if err != nil {
		return WebSocketConnection{}, err
	}
	connection.SetReadLimit(maxWebSocketMessageBytes)
	result := WebSocketConnection{Resource: &WebSocketResource{connection: connection}, Protocol: connection.Subprotocol()}
	if response != nil {
		result.ResponseHeaders = headerPairs(response.Header)
		if response.Body != nil {
			_ = response.Body.Close()
		}
	}
	return result, nil
}

func (*WebSocketResource) FullDuplexResource() {}

func (resource *WebSocketResource) ReadChunk(ctx context.Context, destination []byte) (int, uint32, error) {
	if resource == nil || resource.connection == nil {
		return 0, 0, ErrResourceClosed
	}
	resource.readMu.Lock()
	defer resource.readMu.Unlock()
	if resource.reader == nil {
		messageType, reader, err := resource.connection.Reader(ctx)
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
		writer, err := resource.connection.Writer(ctx, messageType)
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
	err := resource.connection.CloseNow()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
