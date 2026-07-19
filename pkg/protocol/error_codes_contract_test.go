package protocol

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/security"
)

func TestStableErrorCodeCatalogsMatchContracts(t *testing.T) {
	root := repoRoot(t)
	errorCodeSchema := readJSONMap(t, filepath.Join(root, "spec", "plugin", "error-codes-v4.schema.json"))
	defs := requireNestedObject(t, errorCodeSchema, "$defs")

	platformCodes := errorCodesToStrings(security.PlatformErrorCodes())
	bridgeCodes := errorCodesToStrings(security.BridgeErrorCodes())
	clientCodes := errorCodesToStrings(security.TypeScriptClientErrorCodes())

	assertStringSlicesEqual(t, schemaEnum(t, defs, "platform_error_code"), platformCodes, "error-codes schema platform_error_code")
	assertStringSlicesEqual(t, schemaEnum(t, defs, "bridge_error_code"), bridgeCodes, "error-codes schema bridge_error_code")
	assertStringSlicesEqual(t, schemaEnum(t, defs, "typescript_client_error_code"), clientCodes, "error-codes schema typescript_client_error_code")

	openAPIRaw, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v7.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(openAPIRaw), `ErrorCode:
      $ref: "../plugin/error-codes-v4.schema.json#/$defs/platform_error_code"`) {
		t.Fatal("OpenAPI ErrorCode must reference the canonical error-code schema")
	}
	typedCodes := []string{
		string(security.ErrJSONLimitExceeded),
		string(security.ErrManifestInvalid),
		string(security.ErrPackageInvalid),
		string(security.ErrPackageTooLarge),
		string(security.ErrPackagePathForbidden),
		string(security.ErrManagementRevisionMismatch),
		string(security.ErrAuthorizationRevisionMismatch),
		string(security.ErrBindingRevisionMismatch),
		string(security.ErrValuesRevisionMismatch),
		string(security.ErrCapabilityError),
		string(security.ErrWorkerError),
	}
	genericCodes := readOpenAPIEnum(t, string(openAPIRaw), "GenericPlatformErrorCode")
	assertStringSlicesEqual(t, genericCodes, diffStrings(platformCodes, typedCodes), "OpenAPI generic platform error code partition")

	bridgeSchema := readBridgeSchema(t)
	bridgeResponse := requireNestedObject(t, bridgeSchema, "$defs", "response")
	bridgeVariants, ok := bridgeResponse["oneOf"].([]any)
	if !ok || len(bridgeVariants) != 2 {
		t.Fatalf("bridge response oneOf = %#v, want two variants", bridgeResponse["oneOf"])
	}
	errorVariant, ok := bridgeVariants[1].(map[string]any)
	if !ok {
		t.Fatalf("bridge response error variant = %#v, want object", bridgeVariants[1])
	}
	bridgeCode := requireNestedObject(t, errorVariant, "properties", "error_code")
	assertStringSlicesEqual(t, requireStringSlice(t, bridgeCode["enum"], "bridge error_code enum"), bridgeCodes, "bridge schema error_code enum")

	tsSource, err := os.ReadFile(filepath.Join(root, "packages", "redevplugin-ui", "src", "error-codes.gen.ts"))
	if err != nil {
		t.Fatal(err)
	}
	assertStringSlicesEqual(t, readTypeScriptLiteralArray(t, string(tsSource), "pluginPlatformErrorCodes"), platformCodes, "TypeScript pluginPlatformErrorCodes")
	assertStringSlicesEqual(t, readTypeScriptLiteralArray(t, string(tsSource), "pluginBridgeErrorCodes"), bridgeCodes, "TypeScript pluginBridgeErrorCodes")
	assertStringSlicesEqual(t, readTypeScriptLiteralArray(t, string(tsSource), "pluginClientErrorCodes"), clientCodes, "TypeScript pluginClientErrorCodes")
}

func readOpenAPIEnum(t *testing.T, source string, schemaName string) []string {
	t.Helper()
	pattern := regexp.MustCompile(`(?m)^    ` + regexp.QuoteMeta(schemaName) + `:\n(?:      [^\n]*\n)*?      enum:\n((?:        - [A-Z0-9_]+\n)+)`)
	match := pattern.FindStringSubmatch(source)
	if len(match) != 2 {
		t.Fatalf("OpenAPI schema %s enum not found", schemaName)
	}
	lines := strings.Split(strings.TrimSpace(match[1]), "\n")
	values := make([]string, 0, len(lines))
	for _, line := range lines {
		values = append(values, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- ")))
	}
	return values
}

func TestRustIPCErrorCodesMatchSchemaAndSource(t *testing.T) {
	root := repoRoot(t)
	errorCodeSchema := readJSONMap(t, filepath.Join(root, "spec", "plugin", "error-codes-v4.schema.json"))
	want := schemaEnum(t, requireNestedObject(t, errorCodeSchema, "$defs"), "rust_ipc_error_code")
	source, err := os.ReadFile(filepath.Join(root, "crates", "redevplugin-ipc", "src", "lib.rs"))
	if err != nil {
		t.Fatal(err)
	}
	got := readRustIPCErrorCodeConstants(string(source))
	assertStringSlicesEqual(t, got, want, "Rust IPC error code constants")
}

func TestRuntimeProcessFailureCodesAndExitStatusesMatchContracts(t *testing.T) {
	root := repoRoot(t)
	errorCodeSchema := readJSONMap(t, filepath.Join(root, "spec", "plugin", "error-codes-v4.schema.json"))
	defs := requireNestedObject(t, errorCodeSchema, "$defs")
	wantCodes := schemaEnum(t, defs, "runtime_process_failure_code")
	gotCodes := make([]string, 0, len(observability.RuntimeProcessFailureCodes()))
	for _, code := range observability.RuntimeProcessFailureCodes() {
		if !code.Valid() {
			t.Fatalf("runtime process failure code %q is not valid", code)
		}
		gotCodes = append(gotCodes, string(code))
	}
	if observability.RuntimeProcessFailureCode("RUNTIME_PROCESS_UNKNOWN").Valid() {
		t.Fatal("unknown runtime process failure code is valid")
	}
	assertStringSlicesEqual(t, wantCodes, gotCodes, "runtime process failure codes")

	exitDefinition := requireNestedObject(t, defs, "runtime_process_exit_failure")
	variants, ok := exitDefinition["oneOf"].([]any)
	if !ok || len(variants) == 0 {
		t.Fatalf("runtime_process_exit_failure oneOf = %#v", exitDefinition["oneOf"])
	}
	type exitFailure struct {
		ExitCode int
		Code     string
	}
	wantFailures := make([]exitFailure, 0, len(variants))
	for index, rawVariant := range variants {
		variant, ok := rawVariant.(map[string]any)
		if !ok {
			t.Fatalf("runtime process exit variant %d = %#v", index, rawVariant)
		}
		properties := requireNestedObject(t, variant, "properties")
		exitCode, ok := requireNestedObject(t, properties, "exit_code")["const"].(float64)
		if !ok || exitCode != float64(int(exitCode)) {
			t.Fatalf("runtime process exit variant %d exit_code = %#v", index, requireNestedObject(t, properties, "exit_code")["const"])
		}
		code, ok := requireNestedObject(t, properties, "code")["const"].(string)
		if !ok {
			t.Fatalf("runtime process exit variant %d code = %#v", index, requireNestedObject(t, properties, "code")["const"])
		}
		wantFailures = append(wantFailures, exitFailure{ExitCode: int(exitCode), Code: code})
	}
	gotFailures := make([]exitFailure, 0, len(runtimeclient.RuntimeProcessExitFailures()))
	for _, failure := range runtimeclient.RuntimeProcessExitFailures() {
		gotFailures = append(gotFailures, exitFailure{ExitCode: failure.ExitCode, Code: string(failure.Code)})
	}
	if !reflect.DeepEqual(gotFailures, wantFailures) {
		t.Fatalf("runtime process exit failures = %#v, want %#v", gotFailures, wantFailures)
	}

	tsSource, err := os.ReadFile(filepath.Join(root, "packages", "redevplugin-ui", "src", "error-codes.gen.ts"))
	if err != nil {
		t.Fatal(err)
	}
	assertStringSlicesEqual(t, readTypeScriptLiteralArray(t, string(tsSource), "runtimeProcessFailureCodes"), wantCodes, "TypeScript runtime process failure codes")

	rustSource, err := os.ReadFile(filepath.Join(root, "crates", "redevplugin-runtime", "src", "main.rs"))
	if err != nil {
		t.Fatal(err)
	}
	rustConstants := map[string]string{
		"RUNTIME_PROCESS_FAILED":             "RUNTIME_PROCESS_EXIT_GENERAL",
		"IPC_WRITER_CAPACITY_OVERFLOW":       "RUNTIME_PROCESS_EXIT_WRITER_CAPACITY_OVERFLOW",
		"IPC_WRITER_CAPACITY_LIMIT_EXCEEDED": "RUNTIME_PROCESS_EXIT_WRITER_CAPACITY_LIMIT_EXCEEDED",
		"IPC_WRITER_START_FAILED":            "RUNTIME_PROCESS_EXIT_WRITER_START_FAILED",
		"IPC_WRITER_CLOSED":                  "RUNTIME_PROCESS_EXIT_WRITER_CLOSED",
		"IPC_WRITER_BATCH_SIZE_OVERFLOW":     "RUNTIME_PROCESS_EXIT_WRITER_BATCH_SIZE_OVERFLOW",
		"IPC_WRITER_WRITE_FAILED":            "RUNTIME_PROCESS_EXIT_WRITER_WRITE_FAILED",
		"IPC_WRITER_FLUSH_FAILED":            "RUNTIME_PROCESS_EXIT_WRITER_FLUSH_FAILED",
		"IPC_WRITER_PANICKED":                "RUNTIME_PROCESS_EXIT_WRITER_PANICKED",
	}
	for _, failure := range wantFailures {
		constant := rustConstants[failure.Code]
		if constant == "" || !strings.Contains(string(rustSource), fmt.Sprintf("const %s: i32 = %d;", constant, failure.ExitCode)) {
			t.Fatalf("Rust runtime missing exit mapping %d -> %s", failure.ExitCode, failure.Code)
		}
	}
	ipcSource, err := os.ReadFile(filepath.Join(root, "crates", "redevplugin-ipc", "src", "lib.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ipcSource), "parse_frame_identity_v3") {
		t.Fatal("Rust IPC exposes obsolete parse_frame_identity_v3")
	}
	if !strings.Contains(string(ipcSource), "pub fn parse_frame_identity(input: &str) -> IpcResult<FrameIdentity>") {
		t.Fatal("Rust IPC does not expose the unique typed parse_frame_identity API")
	}
}

func readJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func schemaEnum(t *testing.T, defs map[string]any, name string) []string {
	t.Helper()
	def := requireNestedObject(t, defs, name)
	return requireStringSlice(t, def["enum"], name+" enum")
}

func errorCodesToStrings(codes []security.ErrorCode) []string {
	out := make([]string, len(codes))
	for i, code := range codes {
		out[i] = string(code)
	}
	return out
}

func readTypeScriptLiteralArray(t *testing.T, source string, name string) []string {
	t.Helper()
	body := readTypeScriptArrayBody(t, source, name)
	if strings.Contains(body, "...") {
		t.Fatalf("%s must be a literal array without spread", name)
	}
	return quotedStrings(body)
}

func readTypeScriptArrayBody(t *testing.T, source string, name string) string {
	t.Helper()
	prefix := "export const " + name + " = ["
	start := strings.Index(source, prefix)
	if start < 0 {
		t.Fatalf("TypeScript source missing %s", name)
	}
	start += len(prefix)
	end := strings.Index(source[start:], "] as const;")
	if end < 0 {
		t.Fatalf("TypeScript source missing end of %s", name)
	}
	return source[start : start+end]
}

func quotedStrings(source string) []string {
	re := regexp.MustCompile(`"([^"]+)"`)
	matches := re.FindAllStringSubmatch(source, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		out = append(out, match[1])
	}
	return out
}

func readRustIPCErrorCodeConstants(source string) []string {
	re := regexp.MustCompile(`(?m)^pub const ERR_[A-Z0-9_]+: &str = "([^"]+)";$`)
	matches := re.FindAllStringSubmatch(source, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		out = append(out, match[1])
	}
	return out
}

func diffStrings(all []string, remove []string) []string {
	blocked := map[string]bool{}
	for _, value := range remove {
		blocked[value] = true
	}
	var out []string
	for _, value := range all {
		if !blocked[value] {
			out = append(out, value)
		}
	}
	return out
}

func assertStringSlicesEqual(t *testing.T, got []string, want []string, label string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s mismatch\n got: %#v\nwant: %#v", label, got, want)
	}
}
