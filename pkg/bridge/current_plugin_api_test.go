package bridge

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOpenSurfaceUsesCurrentPluginAPIWithoutUIProtocolVersion(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	req := testOpenSurfaceRequest(time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC))

	bootstrap, err := service.OpenSurface(req)
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	encoded, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "ui_protocol_version") || strings.Contains(string(encoded), "plugin-ui-v") {
		t.Fatalf("bootstrap exposes a retired UI compatibility axis: %s", encoded)
	}

	handshake := handshakeFromBootstrap(bootstrap)
	encoded, err = json.Marshal(handshake)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "ui_protocol_version") || strings.Contains(string(encoded), "plugin-ui-v") {
		t.Fatalf("handshake exposes a retired UI compatibility axis: %s", encoded)
	}
}
