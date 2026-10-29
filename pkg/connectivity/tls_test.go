package connectivity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/coder/websocket"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestTLSInvalidConfigurationDeniedBeforeDial(t *testing.T) {
	for _, transport := range []Transport{TransportTCP, TransportUDP} {
		t.Run(string(transport), func(t *testing.T) {
			var dials atomic.Int32
			executor := newTestExecutor(ExecutorOptions{}, func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				client, peer := net.Pipe()
				peer.Close()
				return client, nil
			})
			defer executor.Close(context.Background())
			_, err := executor.openSocket(context.Background(), SocketRequest{Grant: testGrant(t, transport, string(transport)+"://api.example.com:443", time.Minute), TLSConfig: &tls.Config{InsecureSkipVerify: true}}, transport)
			if err == nil || dials.Load() != 0 {
				t.Fatalf("invalid TLS: err=%v dials=%d", err, dials.Load())
			}
		})
	}
}

func networkTLSFixture(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.example.com"}, DNSNames: []string{"api.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key, Leaf: cert}, roots
}
func TestTLSHTTPRequiresVerifiedHostAndClientIdentity(t *testing.T) {
	cert, roots := networkTLSFixture(t)
	var received atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		_, _ = io.WriteString(w, r.URL.RequestURI())
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	executor := newTestExecutor(ExecutorOptions{}, mapDialer(server.Listener.Addr().String()))
	defer executor.Close(context.Background())
	grant := testGrant(t, TransportHTTP, "https://api.example.com", time.Minute)
	for _, config := range []*tls.Config{{RootCAs: roots}, {RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: "wrong.example.com"}, {RootCAs: roots, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}, {Certificates: []tls.Certificate{cert}}} {
		if response, err := executor.OpenHTTP(context.Background(), HTTPRequest{Grant: grant, TLSConfig: config}); err == nil {
			response.Body.Close()
			t.Fatal("unverified TLS configuration succeeded")
		}
	}
	if received.Load() != 0 {
		t.Fatal("invalid credentials reached HTTP handler")
	}
	config := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}
	response, err := executor.OpenHTTP(context.Background(), HTTPRequest{Grant: grant, TLSConfig: config, RequestURI: "/signed%2fpath?x=%2f"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "/signed%2fpath?x=%2f" || received.Load() != 1 {
		t.Fatalf("TLS response %q %v", body, err)
	}
	if config.ServerName != "" || config.MinVersion != 0 {
		t.Fatal("executor mutated adapter TLS config")
	}
}
func TestTLSTCPPreservesHalfClose(t *testing.T) {
	cert, roots := networkTLSFixture(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		body, err := io.ReadAll(conn)
		if err != nil {
			observed <- err.Error()
			return
		}
		observed <- string(body)
		_, _ = conn.Write([]byte("ack"))
	}()
	executor := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String()))
	defer executor.Close(context.Background())
	conn, err := executor.OpenTCP(context.Background(), SocketRequest{Grant: testGrant(t, TransportTCP, "tcp://api.example.com:443", time.Minute), TLSConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}, NoDelay: true})
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
	if received := <-observed; received != "hello" {
		t.Fatalf("received %q", received)
	}
}
func TestTLSWebSocketRequiresVerifiedIdentity(t *testing.T) {
	cert, roots := networkTLSFixture(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		kind, body, err := conn.Read(r.Context())
		if err == nil {
			_ = conn.Write(r.Context(), kind, body)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	executor := newTestExecutor(ExecutorOptions{}, mapDialer(server.Listener.Addr().String()))
	defer executor.Close(context.Background())
	opened, err := executor.OpenWebSocket(context.Background(), WebSocketOpenRequest{SocketRequest: SocketRequest{Grant: testGrant(t, TransportWebSocket, "wss://api.example.com", time.Minute), TLSConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}}, URL: "wss://api.example.com/messages"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	if err := opened.Connection.Write(context.Background(), websocket.MessageText, []byte("verified")); err != nil {
		t.Fatal(err)
	}
	_, body, err := opened.Connection.Read(context.Background())
	if err != nil || string(body) != "verified" {
		t.Fatalf("message %q %v", body, err)
	}
}
