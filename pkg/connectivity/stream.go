package connectivity

import (
	"context"
	"io"
	"net/http"
	"sync"
)

// HTTPBodyResponse exposes response headers without buffering the response.
// The caller must close Body. Cancellation, expiry and byte limits remain owned
// by the executor for the complete response lifetime.
type HTTPBodyResponse struct {
	StatusCode int
	Headers    http.Header
	Body       io.ReadCloser
}

func (e *Executor) OpenHTTP(ctx context.Context, req HTTPRequest) (HTTPBodyResponse, error) {
	response, cancel, err := e.openHTTP(ctx, req)
	if err != nil {
		return HTTPBodyResponse{}, err
	}
	body := &limitedHTTPBody{body: response.Body, cancel: cancel, remaining: responseLimit(req.MaxResponseBytes, e.maxResponseBytes)}
	return HTTPBodyResponse{StatusCode: response.StatusCode, Headers: cloneHTTPHeader(response.Header), Body: body}, nil
}

type limitedHTTPBody struct {
	body      io.ReadCloser
	cancel    context.CancelFunc
	remaining int64
	once      sync.Once
}

func (b *limitedHTTPBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining == 0 {
		var probe [1]byte
		n, err := b.body.Read(probe[:])
		if n > 0 {
			_ = b.Close()
			return 0, ErrResponseTooLarge
		}
		if err != nil {
			_ = b.Close()
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)
	if err != nil {
		_ = b.Close()
	}
	return n, err
}

func (b *limitedHTTPBody) Close() error {
	var err error
	b.once.Do(func() { b.cancel(); err = b.body.Close() })
	return err
}

type limitedHTTPRequest struct {
	source    io.Reader
	remaining int64
}

func (b *limitedHTTPRequest) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining == 0 {
		var probe [1]byte
		n, err := b.source.Read(probe[:])
		if n > 0 {
			return 0, ErrRequestTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.source.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *limitedHTTPRequest) Close() error {
	if closer, ok := b.source.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
