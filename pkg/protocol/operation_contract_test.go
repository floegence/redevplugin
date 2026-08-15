package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutionAndEventDTOsAreTheOnlyPublicAsyncEnvelopes(t *testing.T) {
	root := repoRoot(t)
	openAPI, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v17.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	typescript, err := os.ReadFile(filepath.Join(root, "packages", "redevplugin-ui", "src", "openapi.gen.ts"))
	if err != nil {
		t.Fatal(err)
	}
	openAPIText := string(openAPI)
	typescriptText := string(typescript)
	execution := openAPISchemaBlock(t, openAPIText, "Execution")
	event := openAPISchemaBlock(t, openAPIText, "Event")
	for name, block := range map[string]string{"Execution": execution, "Event": event} {
		if !strings.Contains(block, "additionalProperties: false") {
			t.Fatalf("OpenAPI %s contract must remain closed:\n%s", name, block)
		}
	}
	for _, snippet := range []string{
		"required: [execution_id, plugin_instance_id, kind, status, cursor, cancelable, created_at, updated_at]",
		"kind: { type: string, enum: [sync, operation, subscription] }",
		"status: { type: string, enum: [running, cancel_requested, completed, canceled, failed, orphaned] }",
		"cursor: { type: integer, minimum: 0, maximum: 9007199254740991 }",
		"failure_code: { type: string, minLength: 1 }",
		"cancelable: { type: boolean }",
		"terminal_at: { type: string, format: date-time }",
	} {
		if !strings.Contains(execution, snippet) {
			t.Fatalf("OpenAPI Execution contract is missing %q:\n%s", snippet, execution)
		}
	}
	for _, snippet := range []string{
		"required: [execution_id, sequence, kind]",
		"sequence: { type: integer, minimum: 1, maximum: 9007199254740991 }",
		"kind: { type: string, enum: [progress, data, diagnostic, terminal] }",
		`error: { $ref: "#/components/schemas/PublicError" }`,
	} {
		if !strings.Contains(event, snippet) {
			t.Fatalf("OpenAPI Event contract is missing %q:\n%s", snippet, event)
		}
	}
	for _, snippet := range []string{
		"execution_id: string;",
		`kind: "sync" | "operation" | "subscription";`,
		`status: "running" | "cancel_requested" | "completed" | "canceled" | "failed" | "orphaned";`,
		`kind: "progress" | "data" | "diagnostic" | "terminal";`,
		`error?: components["schemas"]["PublicError"];`,
	} {
		if !strings.Contains(typescriptText, snippet) {
			t.Fatalf("TypeScript Execution/Event contract is missing %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"operation_id", "stream_id", "stream_ticket", "owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash",
	} {
		if strings.Contains(execution, forbidden+":") || strings.Contains(event, forbidden+":") {
			t.Fatalf("OpenAPI Execution/Event contract exposes retired or internal field %q", forbidden)
		}
	}
	for _, retired := range []string{"    PublicOperationBinding:\n", "    PublicStreamBinding:\n", "    PluginOperationList:\n"} {
		if strings.Contains(openAPIText, retired) || strings.Contains(typescriptText, retired) {
			t.Fatalf("public contracts retain retired async schema %q", strings.TrimSpace(retired))
		}
	}
}
