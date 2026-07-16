package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperationDTOCarriesCompleteExecutionEvidence(t *testing.T) {
	root := repoRoot(t)
	openAPI, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v4.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	typescript, err := os.ReadFile(filepath.Join(root, "packages", "redevplugin-ui", "src", "platform.ts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"operation_id", "stream_id", "invocation_id", "audit_correlation_id", "publisher_id",
		"plugin_version", "active_fingerprint", "owner_session_hash", "owner_user_hash",
		"capability_id", "capability_version", "binding_id", "target_method", "permissions",
		"confirmation", "revision", "quota", "target_descriptor_sha256",
		"stream_event_type_name", "stream_event_schema_sha256", "cancelable", "cancel_ack_timeout_ms",
	} {
		if !strings.Contains(string(openAPI), field+":") {
			t.Fatalf("OpenAPI operation contract is missing %q", field)
		}
		if !strings.Contains(string(typescript), field+":") && !strings.Contains(string(typescript), field+"?:") {
			t.Fatalf("TypeScript operation contract is missing %q", field)
		}
	}
	for _, snippet := range []string{
		"required: [operation_id, status, cancelable, created_at, updated_at]",
		"execution: { type: string, enum: [operation, subscription] }",
	} {
		if !strings.Contains(string(openAPI), snippet) {
			t.Fatalf("OpenAPI operation contract is missing %q", snippet)
		}
	}
}
