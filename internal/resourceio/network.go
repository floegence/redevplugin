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
	"time"

	"golang.org/x/net/websocket"
)

const MaxIOChunkBytes = 64 << 10

type HTTPRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Timeout time.Duration
}

type HTTPResponse struct {
	Status   int
	Headers  http.Header
	FinalURL string
	Body     io.ReadCloser
}

type HTTPUpload struct {
	writer *io.PipeWriter
	result <-chan httpResult
	closed bool
}

type httpResult struct {
	response *HTTPResponse
	err      error
}

func BeginHTTP(ctx context.Context, request HTTPRequest) (*HTTPUpload, error) {
	parsed, err := url.Parse(request.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || strings.ContainsAny(request.Method, "\r\n") {
		return nil, errors.New("invalid HTTP request")
	}
	pipeReader, pipeWriter := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, request.Method, parsed.String(), pipeReader)
	if err != nil {
		return nil, err
	}
	for key, values := range request.Headers {
		if strings.ContainsAny(key, "\r\n") {
			return nil, errors.New("invalid HTTP header")
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return nil, errors.New("invalid HTTP header")
			}
			req.Header.Add(key, value)
		}
	}
	result := make(chan httpResult, 1)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	go func() {
		if request.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, request.Timeout)
			defer cancel()
			req = req.WithContext(ctx)
		}
		response, requestErr := client.Do(req)
		if requestErr != nil {
			result <- httpResult{err: requestErr}
			return
		}
		result <- httpResult{response: &HTTPResponse{Status: response.StatusCode, Headers: response.Header.Clone(), FinalURL: response.Request.URL.String(), Body: response.Body}}
	}()
	return &HTTPUpload{writer: pipeWriter, result: result}, nil
}

func (upload *HTTPUpload) Write(value []byte) (int, error) {
	if upload == nil || upload.writer == nil || upload.closed {
		return 0, ErrResourceClosed
	}
	if len(value) > MaxIOChunkBytes {
		return 0, ErrResourceLimit
	}
	return upload.writer.Write(value)
}

func (upload *HTTPUpload) Finish() (*HTTPResponse, error) {
	if upload == nil || upload.writer == nil || upload.closed {
		return nil, ErrResourceClosed
	}
	upload.closed = true
	if err := upload.writer.Close(); err != nil {
		return nil, err
	}
	result := <-upload.result
	return result.response, result.err
}

func (upload *HTTPUpload) Abort(err error) error {
	if upload == nil || upload.writer == nil || upload.closed {
		return nil
	}
	upload.closed = true
	if err == nil {
		err = context.Canceled
	}
	return upload.writer.CloseWithError(err)
}

func OpenTCP(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", address)
}

func OpenUDP(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "udp", address)
}

func OpenWebSocket(ctx context.Context, rawURL string, headers http.Header, timeout time.Duration) (io.ReadWriteCloser, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("invalid WebSocket URL")
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	origin := "http://" + parsed.Host
	config, err := websocket.NewConfig(parsed.String(), origin)
	if err != nil {
		return nil, err
	}
	config.Header = headers.Clone()
	if deadline, ok := ctx.Deadline(); ok {
		config.Dialer = &net.Dialer{Deadline: deadline}
	}
	return websocket.DialConfig(config)
}
