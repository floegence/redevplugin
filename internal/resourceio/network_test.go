package resourceio

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestHTTPStreamsUploadResponseAndPreservesRepeatedHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Connection") != "" {
			t.Error("hop-by-hop Connection header reached server")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		response.Header().Add("X-Repeated", "first")
		response.Header().Add("X-Repeated", "second")
		_, _ = response.Write(bytes.ToUpper(body))
	}))
	defer server.Close()
	var authorizations atomic.Int32
	upload, err := BeginHTTP(context.Background(), HTTPRequest{
		Method: "POST", URL: server.URL, Redirect: RedirectFollow,
		Headers: []Header{{Name: "X-Repeated", Value: "a"}, {Name: "X-Repeated", Value: "b"}, {Name: "Connection", Value: "close"}},
		Authorize: func(context.Context, *url.URL) error {
			authorizations.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range [][]byte{[]byte("hello "), []byte("world")} {
		if n, err := upload.Write(chunk); err != nil || n != len(chunk) {
			t.Fatalf("upload write = %d, %v", n, err)
		}
	}
	response, err := upload.Finish()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "HELLO WORLD" {
		t.Fatalf("response body = %q, %v", body, err)
	}
	repeated := 0
	for _, header := range response.Headers {
		if header.Name == "X-Repeated" {
			repeated++
		}
	}
	if repeated != 2 || authorizations.Load() != 1 {
		t.Fatalf("repeated headers = %d, authorizations = %d", repeated, authorizations.Load())
	}
}

func TestHTTPUploadWritePreservesCompletedNetworkFailure(t *testing.T) {
	reader, writer := io.Pipe()
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	networkErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	result := make(chan httpResult, 1)
	result <- httpResult{err: networkErr}
	upload := &HTTPUpload{writer: writer, result: result, cancel: func() {}}

	_, err := upload.WriteChunk(context.Background(), []byte("payload"), 0)
	if !errors.Is(err, networkErr) {
		t.Fatalf("upload write error = %v, want completed network error %v", err, networkErr)
	}
	if code, _ := StableError(err); code != "NETWORK_ERROR" {
		t.Fatalf("upload write error code = %q, want NETWORK_ERROR", code)
	}
}

func TestHTTPRedirectReauthorizesAndRefusesStreamingReplay(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("done"))
	}))
	defer final.Close()
	redirect303 := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, final.URL, http.StatusSeeOther)
	}))
	defer redirect303.Close()
	var calls atomic.Int32
	upload, err := BeginHTTP(context.Background(), HTTPRequest{Method: "POST", URL: redirect303.URL, Redirect: RedirectFollow, Authorize: func(context.Context, *url.URL) error {
		calls.Add(1)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := upload.Finish()
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if calls.Load() != 2 || response.FinalURL != final.URL {
		t.Fatalf("redirect calls = %d, final URL = %q", calls.Load(), response.FinalURL)
	}

	redirect307 := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", final.URL)
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect307.Close()
	upload, err = BeginHTTP(context.Background(), HTTPRequest{Method: "POST", URL: redirect307.URL, Redirect: RedirectFollow})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = upload.Write([]byte("cannot replay"))
	if _, err := upload.Finish(); !errors.Is(err, ErrRedirectRequiresReplay) {
		t.Fatalf("307 finish error = %v, want ErrRedirectRequiresReplay", err)
	}
}

func TestConnectedUDPPreservesDatagramBoundaries(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		buffer := make([]byte, MaxIOChunkBytes)
		n, peer, readErr := listener.ReadFromUDP(buffer)
		if readErr == nil {
			_, _ = listener.WriteToUDP(buffer[:n], peer)
		}
	}()
	resource, err := OpenUDP(context.Background(), listener.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer resource.Close()
	if _, err := resource.WriteChunk(context.Background(), []byte("packet"), 0); !errors.Is(err, ErrInvalidHandle) {
		t.Fatalf("UDP write without boundary error = %v", err)
	}
	if n, err := resource.WriteChunk(context.Background(), []byte("packet"), IOFlagDatagramEnd); err != nil || n != 6 {
		t.Fatalf("UDP write = %d, %v", n, err)
	}
	buffer := make([]byte, 64)
	n, flags, err := resource.ReadChunk(context.Background(), buffer)
	if err != nil || string(buffer[:n]) != "packet" || flags != IOFlagDatagramEnd {
		t.Fatalf("UDP read = %q, %d, %v", buffer[:n], flags, err)
	}
}

func TestWebSocketStreamsRepeatedMessagesWithBoundaries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{Subprotocols: []string{"fixture.v1"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		for range 2 {
			messageType, reader, err := connection.Reader(request.Context())
			if err != nil {
				return
			}
			writer, err := connection.Writer(request.Context(), messageType)
			if err != nil {
				return
			}
			_, copyErr := io.Copy(writer, reader)
			closeErr := writer.Close()
			if copyErr != nil || closeErr != nil {
				return
			}
		}
	}))
	defer server.Close()
	websocketURL := "ws" + server.URL[len("http"):]
	opened, err := OpenWebSocket(context.Background(), WebSocketOpen{URL: websocketURL, Subprotocols: []string{"fixture.v1"}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Resource.Close()
	if opened.Protocol != "fixture.v1" {
		t.Fatalf("subprotocol = %q", opened.Protocol)
	}
	owner := testOwner("websocket-session")
	owner.InvocationID = "invoke-1"
	for _, fixture := range []struct {
		parts [][]byte
		kind  uint32
	}{
		{parts: [][]byte{[]byte("hello"), []byte(" world")}, kind: IOFlagText},
		{parts: [][]byte{{0, 1, 2}, {3, 4}}, kind: IOFlagBinary},
	} {
		for index, part := range fixture.parts {
			flags := uint32(0)
			if index == 0 {
				flags |= fixture.kind
			}
			if index == len(fixture.parts)-1 {
				flags |= IOFlagMessageEnd
			}
			if n, err := opened.Resource.WriteOwnedChunk(context.Background(), owner, part, flags); err != nil || n != len(part) {
				t.Fatalf("WebSocket write = %d, %v", n, err)
			}
		}
		var body []byte
		var observed uint32
		for observed&IOFlagMessageEnd == 0 {
			chunk := make([]byte, 3)
			n, flags, err := opened.Resource.ReadChunk(context.Background(), chunk)
			if err != nil {
				t.Fatal(err)
			}
			body = append(body, chunk[:n]...)
			observed |= flags
		}
		if !bytes.Equal(body, bytes.Join(fixture.parts, nil)) || observed&fixture.kind == 0 {
			t.Fatalf("WebSocket message = %x flags=%d", body, observed)
		}
		owner.InvocationID = owner.InvocationID + "-next"
	}
}

func TestWebSocketRejectsCrossInvocationMessageContinuation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, nil)
		if err == nil {
			defer connection.CloseNow()
			_, _, _ = connection.Read(request.Context())
		}
	}))
	defer server.Close()
	opened, err := OpenWebSocket(context.Background(), WebSocketOpen{URL: "ws" + server.URL[len("http"):], Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Resource.Close()
	first := testOwner("websocket-session")
	first.InvocationID = "invoke-a"
	if _, err := opened.Resource.WriteOwnedChunk(context.Background(), first, []byte("partial"), IOFlagText); err != nil {
		t.Fatal(err)
	}
	second := first
	second.InvocationID = "invoke-b"
	if _, err := opened.Resource.WriteOwnedChunk(context.Background(), second, []byte("bad"), IOFlagMessageEnd); !errors.Is(err, ErrInvalidHandle) {
		t.Fatalf("cross-invocation continuation error = %v", err)
	}
}

func TestTCPRepeatedReadWriteAcceptAndShutdown(t *testing.T) {
	listener, err := ListenTCP(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		stream, acceptErr := listener.Accept(context.Background(), true, time.Second)
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer stream.Close()
		_, acceptErr = io.Copy(stream, stream)
		serverResult <- acceptErr
	}()
	client, err := OpenTCP(context.Background(), TCPConnectOptions{Address: listener.Address(), Timeout: time.Second, NoDelay: true, KeepAlive: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{[]byte("first"), []byte("second message")} {
		if n, err := client.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("TCP write = %d, %v", n, err)
		}
		response := make([]byte, len(payload))
		if _, err := io.ReadFull(client, response); err != nil || !bytes.Equal(response, payload) {
			t.Fatalf("TCP response = %q, %v", response, err)
		}
	}
	if err := client.Shutdown(TCPShutdownWrite); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP server did not observe shutdown")
	}
}

func TestTCPListenerAcceptHonorsCancellation(t *testing.T) {
	listener, err := ListenTCP(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if _, err := listener.Accept(ctx, false, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled accept error = %v", err)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("canceled accept did not wake promptly")
	}
}
