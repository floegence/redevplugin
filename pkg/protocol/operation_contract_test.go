package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperationDTOCarriesCompleteExecutionEvidence(t *testing.T) {
	root := repoRoot(t)
	openAPI, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v5.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	typescript, err := os.ReadFile(filepath.Join(root, "packages", "redevplugin-ui", "src", "openapi.gen.ts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"operation_id", "stream_id", "invocation_id", "audit_correlation_id", "publisher_id",
		"plugin_version", "active_fingerprint", "owner_session_hash", "owner_user_hash", "owner_env_hash",
		"capability_id", "capability_version", "binding_id", "target_method", "permissions",
		"confirmation", "revision", "quota", "target_descriptor_sha256",
		"stream_event_type_name", "stream_event_schema_sha256", "cancelable", "cancel_ack_timeout_ms",
		"failure_code", "terminal_at",
	} {
		if !strings.Contains(string(openAPI), field+":") {
			t.Fatalf("OpenAPI operation contract is missing %q", field)
		}
		if !strings.Contains(string(typescript), field+":") && !strings.Contains(string(typescript), field+"?:") {
			t.Fatalf("TypeScript operation contract is missing %q", field)
		}
	}
	for _, snippet := range []string{
		"- owner_session_hash\n            - owner_user_hash\n            - owner_env_hash\n            - session_channel_id_hash",
		"owner_session_hash: { type: string, minLength: 1 }",
		"owner_user_hash: { type: string, minLength: 1 }",
		"owner_env_hash: { type: string, minLength: 1 }",
		"session_channel_id_hash: { type: string, minLength: 1 }",
		"execution: { type: string, enum: [operation, subscription] }",
		"enum: [adapter_failed, contract_invalid, platform_failed, quota_exceeded, runtime_failed]",
		"required: [status, failure_code, reason]",
		"status: { const: failed }",
		"reason: { const: \"execution failed\" }",
		"status:\n                  enum: [running, cancel_requested, canceled, completed, orphaned_after_disable, orphaned_after_uninstall]",
		"not:\n                required: [failure_code]",
	} {
		if !strings.Contains(string(openAPI), snippet) {
			t.Fatalf("OpenAPI operation contract is missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"owner_session_hash: string;",
		"owner_user_hash: string;",
		"owner_env_hash: string;",
		"session_channel_id_hash: string;",
		"status: \"failed\";",
		"failure_code: components[\"schemas\"][\"ExecutionFailureCode\"];",
		"reason: \"execution failed\";",
		"status: \"running\" | \"cancel_requested\" | \"canceled\" | \"completed\" | \"orphaned_after_disable\" | \"orphaned_after_uninstall\";",
	} {
		if !strings.Contains(string(typescript), snippet) {
			t.Fatalf("TypeScript operation contract is missing %q", snippet)
		}
	}
}
