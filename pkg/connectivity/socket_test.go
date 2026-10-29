package connectivity

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestOpenTCPRetainsHalfCloseAndCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		body, _ := io.ReadAll(conn)
		received <- string(body)
		_, _ = conn.Write([]byte("ack"))
	}()
	executor := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String()))
	conn, err := executor.OpenTCP(context.Background(), SocketRequest{Grant: testGrant(t, TransportTCP, "tcp://api.example.com:443", time.Minute), NoDelay: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != "ack" {
		t.Fatalf("reply %q %v", reply, err)
	}
	select {
	case body := <-received:
		if body != "hello" {
			t.Fatalf("received %q", body)
		}
	case <-time.After(time.Second):
		t.Fatal("half-close did not reach receiver")
	}
}

func TestOpenSocketsCancelPendingReads(t *testing.T) {
	for _, transport := range []Transport{TransportTCP, TransportUDP} {
		t.Run(string(transport), func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			executor := newTestExecutor(ExecutorOptions{}, func(context.Context, string, string) (net.Conn, error) { return client, nil })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn, err := executor.openSocket(ctx, SocketRequest{Grant: testGrant(t, transport, string(transport)+"://api.example.com:443", time.Minute)}, transport)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			done := make(chan error, 1)
			go func() { _, err := conn.Read(make([]byte, 8)); done <- err }()
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled read succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("cancel did not interrupt socket read")
			}
		})
	}
}

func TestOpenUDPEnforcesDatagramBudgetAndRate(t *testing.T) {
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	var received atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		n, peer, err := receiver.ReadFromUDP(buf)
		if err == nil {
			received.Add(1)
			_, _ = receiver.WriteToUDP(buf[:n], peer)
		}
	}()
	var allowed atomic.Int32
	executor := newTestExecutor(ExecutorOptions{UDPRateLimiter: UDPRateLimiterFunc(func(time.Time, UDPRateLimitKey) bool { return allowed.Add(1) == 1 })}, mapDialer(receiver.LocalAddr().String()))
	conn, err := executor.OpenUDP(context.Background(), SocketRequest{Grant: testGrant(t, TransportUDP, "udp://api.example.com:443", time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("packet")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _, flags, _, err := conn.ReadMsgUDP(buf, nil)
	if err != nil || string(buf[:n]) != "packet" || flags != 0 {
		t.Fatalf("datagram %q %d %v", buf[:n], flags, err)
	}
	if _, err = conn.Write([]byte("denied")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rate result %v", err)
	}
	<-done
	if received.Load() != 1 {
		t.Fatalf("received %d datagrams", received.Load())
	}
}

func TestOpenWebSocketPreservesMessagesAndCancels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"fixture"}})
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		for {
			kind, body, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if err = conn.Write(r.Context(), kind, body); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	executor := newTestExecutor(ExecutorOptions{}, mapDialer(server.Listener.Addr().String()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened, err := executor.OpenWebSocket(ctx, WebSocketOpenRequest{SocketRequest: SocketRequest{Grant: testGrant(t, TransportWebSocket, "ws://api.example.com", time.Minute)}, URL: "ws://api.example.com/messages", Subprotocols: []string{"fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	if opened.Connection.Subprotocol() != "fixture" {
		t.Fatal("subprotocol lost")
	}
	for _, body := range []string{"first", "second"} {
		if err := opened.Connection.Write(ctx, websocket.MessageText, []byte(body)); err != nil {
			t.Fatal(err)
		}
		kind, received, err := opened.Connection.Read(ctx)
		if err != nil || kind != websocket.MessageText || string(received) != body {
			t.Fatalf("message %d %q %v", kind, received, err)
		}
	}
	cancel()
	if _, _, err := opened.Connection.Read(context.Background()); err == nil {
		t.Fatal("canceled websocket remained readable")
	}
}

func TestSocketExecutorRejectsPrivateTargetsBeforeDial(t *testing.T) {
	var dials atomic.Int32
	executor := NewExecutor(ExecutorOptions{LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
		dials.Add(1)
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}})
	for _, transport := range []Transport{TransportTCP, TransportUDP} {
		_, err := executor.openSocket(context.Background(), SocketRequest{Grant: testGrant(t, transport, string(transport)+"://api.example.com:443", time.Minute)}, transport)
		if err == nil {
			t.Fatalf("%s accepted private DNS", transport)
		}
	}
	if dials.Load() != 2 {
		t.Fatalf("resolver calls %d", dials.Load())
	}
}
