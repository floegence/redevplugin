package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/security"
)

func TestStableErrorCodeCatalogsMatchContracts(t *testing.T) {
	root := repoRoot(t)
	errorCodeSchema := readJSONMap(t, filepath.Join(root, "spec", "plugin", "error-codes-v1.schema.json"))
	defs := requireNestedObject(t, errorCodeSchema, "$defs")

	platformCodes := errorCodesToStrings(security.PlatformErrorCodes())
	bridgeCodes := errorCodesToStrings(security.BridgeErrorCodes())
	clientCodes := errorCodesToStrings(security.TypeScriptClientErrorCodes())

	assertStringSlicesEqual(t, schemaEnum(t, defs, "platform_error_code"), platformCodes, "error-codes schema platform_error_code")
	assertStringSlicesEqual(t, schemaEnum(t, defs, "bridge_error_code"), bridgeCodes, "error-codes schema bridge_error_code")
	assertStringSlicesEqual(t, schemaEnum(t, defs, "typescript_client_error_code"), clientCodes, "error-codes schema typescript_client_error_code")

	openAPICodes, err := readOpenAPIErrorCodes(filepath.Join(root, "spec", "openapi", "plugin-platform-v3.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	assertStringSlicesEqual(t, openAPICodes, platformCodes, "OpenAPI ErrorCode enum")

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

	tsSource, err := os.ReadFile(filepath.Join(root, "packages", "redevplugin-ui", "src", "errors.ts"))
	if err != nil {
		t.Fatal(err)
	}
	assertStringSlicesEqual(t, readTypeScriptLiteralArray(t, string(tsSource), "pluginPlatformErrorCodes"), platformCodes, "TypeScript pluginPlatformErrorCodes")
	assertStringSlicesEqual(t, readTypeScriptSpreadArray(t, string(tsSource), "pluginBridgeErrorCodes", "pluginPlatformErrorCodes"), diffStrings(bridgeCodes, platformCodes), "TypeScript pluginBridgeErrorCodes extras")
	assertStringSlicesEqual(t, readTypeScriptSpreadArray(t, string(tsSource), "pluginClientErrorCodes", "pluginBridgeErrorCodes"), diffStrings(clientCodes, bridgeCodes), "TypeScript pluginClientErrorCodes extras")
}

func TestRustIPCErrorCodesMatchSchemaAndSource(t *testing.T) {
	root := repoRoot(t)
	errorCodeSchema := readJSONMap(t, filepath.Join(root, "spec", "plugin", "error-codes-v1.schema.json"))
	want := schemaEnum(t, requireNestedObject(t, errorCodeSchema, "$defs"), "rust_ipc_error_code")
	source, err := os.ReadFile(filepath.Join(root, "crates", "redevplugin-ipc", "src", "lib.rs"))
	if err != nil {
		t.Fatal(err)
	}
	got := readRustIPCErrorCodeConstants(string(source))
	assertStringSlicesEqual(t, got, want, "Rust IPC error code constants")
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

func readOpenAPIErrorCodes(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	inErrorCode := false
	inEnum := false
	var codes []string
	for _, line := range lines {
		switch {
		case line == "    ErrorCode:":
			inErrorCode = true
			inEnum = false
			continue
		case inErrorCode && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") && line != "    ErrorCode:":
			return codes, nil
		case inErrorCode && strings.TrimSpace(line) == "enum:":
			inEnum = true
			continue
		case inEnum && strings.HasPrefix(strings.TrimSpace(line), "- "):
			codes = append(codes, strings.TrimPrefix(strings.TrimSpace(line), "- "))
		}
	}
	return codes, nil
}

func readTypeScriptLiteralArray(t *testing.T, source string, name string) []string {
	t.Helper()
	body := readTypeScriptArrayBody(t, source, name)
	if strings.Contains(body, "...") {
		t.Fatalf("%s must be a literal array without spread", name)
	}
	return quotedStrings(body)
}

func readTypeScriptSpreadArray(t *testing.T, source string, name string, spreadName string) []string {
	t.Helper()
	body := readTypeScriptArrayBody(t, source, name)
	if !strings.Contains(body, "..."+spreadName) {
		t.Fatalf("%s must include ...%s", name, spreadName)
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
