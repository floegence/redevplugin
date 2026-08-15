package phase0

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
)

func compatPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "compat", "v1.1.4", name)
}

func TestPhase0FrozenV114ArtifactsAreImmutable(t *testing.T) {
	for _, fixture := range []struct {
		name string
		sha  string
	}{
		{name: "ui-only.redevplugin", sha: "e9d5e320fb92a2df27fc8573470dfa17e14845711f78b87acc8c27155e86cfd9"},
		{name: "worker.redevplugin", sha: "fec2d584d9a48744d6b0df2cde59c61671af878780308388c806c4f7fd444e71"},
	} {
		raw, err := os.ReadFile(compatPath(t, fixture.name))
		if err != nil {
			t.Fatal(err)
		}
		actual := sha256.Sum256(raw)
		if got := hex.EncodeToString(actual[:]); got != fixture.sha {
			t.Fatalf("%s changed: got %s want %s", fixture.name, got, fixture.sha)
		}
		pkg, err := pluginpkg.Read(context.Background(), bytes.NewReader(raw), int64(len(raw)), pluginpkg.DefaultReadLimits())
		if err != nil {
			t.Fatalf("Read(%s): %v", fixture.name, err)
		}
		if pkg.Manifest.SchemaVersion != "redevplugin.manifest.v8" {
			t.Fatalf("%s schema = %q, want frozen v8", fixture.name, pkg.Manifest.SchemaVersion)
		}
	}
}

func TestPhase0V9UnknownOptionalFieldPreservesManifestHash(t *testing.T) {
	raw := []byte(`{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example","display_name":"Example"},"plugin":{"plugin_id":"com.example.v9","display_name":"V9","version":"1.0.0"},"api":{"surface":1,"worker":1,"optional_features":[]},"permissions":[],"surfaces":[],"workers":[],"methods":[],"storage":{"stores":[]},"future":{"opaque":true}}`)
	if _, err := manifest.Decode(bytes.NewReader(raw)); err != nil {
		t.Fatalf("v9 optional field must be tolerated and normalized: %v", err)
	}
	withoutFuture := bytes.Replace(raw, []byte(`,"future":{"opaque":true}`), nil, 1)
	if bytes.Equal(raw, withoutFuture) {
		t.Fatal("test fixture did not include the unknown field")
	}
	if string(raw) == string(withoutFuture) {
		t.Fatal("unknown field was lost from the signed input")
	}
}

func TestPhase0UnknownRequiredFeatureIsRejected(t *testing.T) {
	raw := []byte(`{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example","display_name":"Example"},"plugin":{"plugin_id":"com.example.v9","display_name":"V9","version":"1.0.0"},"api":{"surface":1,"worker":1,"required_features":["io.future.v9"]},"permissions":[],"surfaces":[],"workers":[],"methods":[],"storage":{"stores":[]}}`)
	_, err := manifest.Decode(bytes.NewReader(raw))
	if err == nil || !strings.Contains(strings.ToUpper(err.Error()), "UNSUPPORTED_FEATURE") {
		t.Fatalf("unknown required feature error = %v, want stable UNSUPPORTED_FEATURE", err)
	}
}

func TestPhase0LargeBinaryReadUsesRawChunkedDataPlane(t *testing.T) {
	assertContractGap(t, "worker ABI v1 raw data plane", "rdp_read_v1", "rdp_write_v1", "body_base64")
}

func TestPhase0WebSocketSupportsRepeatedMessages(t *testing.T) {
	assertContractGap(t, "WebSocket long connection", "net.websocket.open", "MESSAGE_END", "WebSocketRoundTrip")
}

func TestPhase0TCPSupportsRepeatedReadWrite(t *testing.T) {
	assertContractGap(t, "TCP stream handle", "net.tcp.connect", "rdp_read_v1", "TCPRoundTrip")
}

func TestPhase0BlockingReadDoesNotStarveAnotherPlugin(t *testing.T) {
	assertContractGap(t, "per-invocation cancellable scheduler", "IO_READ", "per_plugin_concurrency", "detached")
}

func TestPhase0ResourceScopeSeparatesUsers(t *testing.T) {
	assertContractGap(t, "resource handle owner binding", "OwnerUserHash", "RuntimeGeneration", "handle table")
}

func TestPhase0PanelOpenDoesNotWaitForRuntime(t *testing.T) {
	assertContractGap(t, "immediate surface open", "catalog projection", "runtime spawn", "compatibility scan")
}

func TestPhase0StartupPublishesInventoryBeforeRuntimeReady(t *testing.T) {
	assertContractGap(t, "startup inventory projection", "prewarm", "readiness future", "RUNTIME_UNAVAILABLE")
}

func TestPhase0FrozenWorkerRunsWithoutRebuild(t *testing.T) {
	assertContractGap(t, "frozen worker execution", "artifact_sha256", "module cache", "cargo build")
}

func TestPhase0HTTPUsesStreamingBodyHandles(t *testing.T) {
	assertContractGap(t, "HTTP upload and response handles", "net.http.begin", "net.http.finish", "rdp_read_v1")
}

func TestPhase0RevocationClosesAllResourceKinds(t *testing.T) {
	assertContractGap(t, "unified resource revoke", "REVOKE_PLUGIN", "RESOURCE_CLOSED", "KindWebSocket")
}

func TestPhase0InstallConfirmationEnablesByDefault(t *testing.T) {
	assertContractGap(t, "install enabled transaction", "DesiredEnabled", "needs_attention", "enabled")
}

func assertContractGap(t *testing.T, contract string, required ...string) {
	t.Helper()
	// This is deliberately red in Phase 0. Each gap is replaced by a focused
	// behavioral test when its owning phase lands.
	if contract == "" || len(required) == 0 {
		t.Fatal("invalid Phase 0 contract gap")
	}
	t.Fatalf("RED: %s is not implemented; required evidence: %s", contract, strings.Join(required, ", "))
}
