package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/internal/runtimeclient"
	"github.com/floegence/redevplugin/pkg/manifest"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestIPCSchemaReferencesWorkerInvocationContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	allOf, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatal("ipc schema missing allOf")
	}
	for _, item := range allOf {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ifBlock := requireNestedObject(t, block, "if", "properties", "frame_type")
		if ifBlock["const"] != "invoke_worker" {
			continue
		}
		thenBlock, ok := block["then"].(map[string]any)
		if !ok {
			continue
		}
		properties := requireNestedObject(t, thenBlock, "properties", "payload", "properties")
		invocation, ok := properties["invocation"].(map[string]any)
		if !ok {
			continue
		}
		if invocation["$ref"] != "https://schemas.redevplugin.dev/plugin/worker-invocation-v3.schema.json" {
			t.Fatalf("invoke_worker invocation ref = %#v", invocation["$ref"])
		}
		return
	}
	t.Fatal("ipc schema missing invoke_worker invocation reference")
}

func TestIPCSchemaBindsHelloChannelNonce(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	allOf, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatal("ipc schema missing allOf")
	}
	assertPayload := func(frameType string) {
		t.Helper()
		for _, item := range allOf {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			ifBlock := requireNestedObject(t, block, "if", "properties", "frame_type")
			if ifBlock["const"] != frameType {
				continue
			}
			payload := requireNestedObject(t, block, "then", "properties", "payload")
			required := requireStringSlice(t, payload["required"], frameType+" payload required")
			hasChannelNonce := false
			for _, name := range required {
				if name == "channel_nonce" {
					hasChannelNonce = true
					break
				}
			}
			if !hasChannelNonce {
				t.Fatalf("%s payload required missing channel_nonce: %#v", frameType, required)
			}
			props := requireNestedObject(t, payload, "properties")
			channelNonce := requireNestedObject(t, props, "channel_nonce")
			if channelNonce["type"] != "string" || channelNonce["minLength"] != float64(16) {
				t.Fatalf("%s channel_nonce schema = %#v", frameType, channelNonce)
			}
			if frameType == "hello" {
				if !containsRequiredString(required, "runtime_lease_public_keys") {
					t.Fatalf("hello payload must require runtime_lease_public_keys: %#v", required)
				}
				keys := requireNestedObject(t, props, "runtime_lease_public_keys")
				if keys["type"] != "array" || keys["minItems"] != float64(1) {
					t.Fatalf("hello runtime_lease_public_keys schema = %#v", keys)
				}
				items := requireNestedObject(t, keys, "items")
				keyProps := requireNestedObject(t, items, "properties")
				for _, name := range []string{"algorithm", "key_id", "public_key_base64"} {
					if _, ok := keyProps[name].(map[string]any); !ok {
						t.Fatalf("hello runtime_lease_public_keys missing %s", name)
					}
				}
			}
			return
		}
		t.Fatalf("ipc schema missing %s block", frameType)
	}
	assertPayload("hello")
	assertPayload("hello_ack")
}

func TestIPCSchemaDefinesHeartbeatPayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	frameType := requireNestedObject(t, schema, "properties", "frame_type")
	frameEnum, ok := frameType["enum"].([]any)
	if !ok || !containsString(frameEnum, "heartbeat") {
		t.Fatalf("frame_type enum missing heartbeat: %#v", frameType["enum"])
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "heartbeat_request_payload")
	requestRequired := requireStringSlice(t, request["required"], "heartbeat request required")
	for _, name := range []string{"sent_unix_nano", "max_staleness_ms"} {
		if !containsRequiredString(requestRequired, name) {
			t.Fatalf("heartbeat request required missing %s: %#v", name, requestRequired)
		}
		field := requireNestedObject(t, request, "properties", name)
		if field["type"] != "integer" || field["minimum"] != float64(1) {
			t.Fatalf("heartbeat request %s schema = %#v", name, field)
		}
	}
	response := requireNestedObject(t, defs, "heartbeat_response_payload")
	success, failure := requireClosedResponseBranches(t, defs, response, "heartbeat response")
	if resultRef := requireNestedObject(t, success, "properties", "result")["$ref"]; resultRef != "#/$defs/heartbeat_ack_result" {
		t.Fatalf("heartbeat result ref = %#v", resultRef)
	}
	assertClosedFailureBranch(t, failure, "heartbeat response")
	result := requireNestedObject(t, defs, "heartbeat_ack_result")
	resultRequired := requireStringSlice(t, result["required"], "heartbeat result required")
	for _, name := range []string{
		"runtime_generation_id",
		"runtime_unix_nano",
		"max_staleness_ms",
		"host_sent_unix_nano",
		"active_invocations",
		"queued_invocations",
		"limits",
		"module_cache",
	} {
		if !containsRequiredString(resultRequired, name) {
			t.Fatalf("heartbeat result required missing %s: %#v", name, resultRequired)
		}
	}
	resultProps := requireNestedObject(t, result, "properties")
	for _, name := range []string{"active_invocations", "queued_invocations"} {
		field := requireNestedObject(t, resultProps, name)
		if field["type"] != "integer" || field["minimum"] != float64(0) {
			t.Fatalf("heartbeat result %s schema = %#v", name, field)
		}
	}
	if got := requireNestedObject(t, resultProps, "limits")["$ref"]; got != "#/$defs/runtime_limits" {
		t.Fatalf("heartbeat limits ref = %#v", got)
	}
	if got := requireNestedObject(t, resultProps, "module_cache")["$ref"]; got != "#/$defs/module_cache_metrics" {
		t.Fatalf("heartbeat module_cache ref = %#v", got)
	}
}

func TestIPCSchemaNegotiatesClosedRuntimeLimits(t *testing.T) {
	schema := readPluginSchema(t, "ipc-v6.schema.json")
	defs := requireNestedObject(t, schema, "$defs")
	limits := requireNestedObject(t, defs, "runtime_limits")
	const routeCapacityContract = "Negotiated runtime capacities. per_plugin_concurrency must not exceed worker_count. Route capacities are derived exactly from negotiated limits: active hostcall routes = worker_count, canceled hostcall retention = worker_count + queue_capacity, and compile-flight artifact routes = worker_count."
	if limits["description"] != routeCapacityContract {
		t.Fatalf("runtime limits route capacity contract = %#v", limits["description"])
	}
	if limits["additionalProperties"] != false {
		t.Fatalf("runtime limits additionalProperties = %#v, want false", limits["additionalProperties"])
	}
	assertStringSet(t, requireStringSlice(t, limits["required"], "runtime limits required"), []string{
		"worker_count",
		"queue_capacity",
		"per_plugin_concurrency",
		"module_cache_entries",
		"module_cache_source_bytes",
	}, "runtime limits required")
	limitProps := requireNestedObject(t, limits, "properties")
	minimums := map[string]float64{
		"worker_count":              runtimeclient.RuntimeWorkerCountMin,
		"queue_capacity":            runtimeclient.RuntimeQueueCapacityMin,
		"per_plugin_concurrency":    runtimeclient.RuntimePerPluginConcurrencyMin,
		"module_cache_entries":      runtimeclient.RuntimeModuleCacheEntriesMin,
		"module_cache_source_bytes": runtimeclient.RuntimeModuleCacheSourceBytesMin,
	}
	for name, minimum := range minimums {
		field := requireNestedObject(t, limitProps, name)
		if field["type"] != "integer" || field["minimum"] != minimum {
			t.Fatalf("runtime limit %s schema = %#v, want minimum %v", name, field, minimum)
		}
	}
	for name, maximum := range map[string]float64{
		"worker_count":              runtimeclient.RuntimeWorkerCountMax,
		"queue_capacity":            runtimeclient.RuntimeQueueCapacityMax,
		"per_plugin_concurrency":    runtimeclient.RuntimePerPluginConcurrencyMax,
		"module_cache_entries":      runtimeclient.RuntimeModuleCacheEntriesMax,
		"module_cache_source_bytes": runtimeclient.RuntimeModuleCacheSourceBytesMax,
	} {
		if got := requireNestedObject(t, limitProps, name)["maximum"]; got != maximum {
			t.Fatalf("runtime limit %s maximum = %#v, want %v", name, got, maximum)
		}
	}

	allOf, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatal("ipc schema missing allOf")
	}
	for _, frameType := range []string{"hello", "hello_ack"} {
		block := findIPCFrameBlock(t, allOf, frameType)
		payload := requireNestedObject(t, block, "then", "properties", "payload")
		required := requireStringSlice(t, payload["required"], frameType+" payload required")
		if !containsRequiredString(required, "limits") {
			t.Fatalf("%s payload must require limits: %#v", frameType, required)
		}
		if got := requireNestedObject(t, payload, "properties", "limits")["$ref"]; got != "#/$defs/runtime_limits" {
			t.Fatalf("%s limits ref = %#v", frameType, got)
		}
	}
}

func TestIPCSchemaDefinesClosedModuleCacheMetrics(t *testing.T) {
	schema := readPluginSchema(t, "ipc-v6.schema.json")
	metrics := requireNestedObject(t, schema, "$defs", "module_cache_metrics")
	if metrics["additionalProperties"] != false {
		t.Fatalf("module cache metrics additionalProperties = %#v, want false", metrics["additionalProperties"])
	}
	assertStringSet(t, requireStringSlice(t, metrics["required"], "module cache metrics required"), []string{
		"hits", "misses", "compiles", "entries", "source_bytes",
	}, "module cache metrics required")
	properties := requireNestedObject(t, metrics, "properties")
	for _, name := range []string{"hits", "misses", "compiles", "entries", "source_bytes"} {
		field := requireNestedObject(t, properties, name)
		if field["type"] != "integer" || field["minimum"] != float64(0) {
			t.Fatalf("module cache metric %s schema = %#v", name, field)
		}
	}
}

func TestIPCSchemaDefinesCancellationFrames(t *testing.T) {
	schema := readPluginSchema(t, "ipc-v6.schema.json")
	allOf, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatal("ipc schema missing allOf")
	}
	cancel := findIPCFrameBlock(t, allOf, "cancel_invoke")
	payload := requireNestedObject(t, cancel, "then", "properties", "payload")
	if payload["additionalProperties"] != false {
		t.Fatalf("cancel payload additionalProperties = %#v, want false", payload["additionalProperties"])
	}
	assertStringSet(t, requireStringSlice(t, payload["required"], "cancel payload required"), []string{"invocation_request_id"}, "cancel payload required")
	invocationID := requireNestedObject(t, payload, "properties", "invocation_request_id")
	if invocationID["type"] != "string" || invocationID["minLength"] != float64(1) {
		t.Fatalf("cancel invocation_request_id schema = %#v", invocationID)
	}

	ack := findIPCFrameBlock(t, allOf, "cancel_invoke_ack")
	if got := requireNestedObject(t, ack, "then", "properties", "payload")["$ref"]; got != "#/$defs/cancel_invoke_ack_response_payload" {
		t.Fatalf("cancel ack payload ref = %#v", got)
	}
	response := requireNestedObject(t, schema, "$defs", "cancel_invoke_ack_response_payload")
	success, failure := requireClosedResponseBranches(t, requireNestedObject(t, schema, "$defs"), response, "cancel ack response")
	result := requireNestedObject(t, success, "properties", "result")
	assertStringSet(t, requireStringSlice(t, result["required"], "cancel ack result required"), []string{
		"invocation_request_id", "disposition",
	}, "cancel ack result required")
	assertStringEnum(t, requireNestedObject(t, result, "properties", "disposition")["enum"], "cancel disposition", []string{
		"queued", "running", "complete",
	})
	assertClosedFailureBranch(t, failure, "cancel ack response")
}

func TestIPCSchemaBindsRuntimeHostcallsToParentInvocation(t *testing.T) {
	schema := readPluginSchema(t, "ipc-v6.schema.json")
	parent := requireNestedObject(t, schema, "properties", "parent_request_id")
	if parent["type"] != "string" || parent["minLength"] != float64(1) {
		t.Fatalf("parent_request_id schema = %#v", parent)
	}
	allOf, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatal("ipc schema missing allOf")
	}
	wantFrames := []string{
		"compile_flight_register",
		"compile_flight_complete",
		"open_handle",
		"validate_handle_grant",
		"storage_file",
		"storage_kv",
		"storage_sqlite",
		"network_grant",
		"network_execute",
	}
	for _, item := range allOf {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ifBlock, ok := block["if"].(map[string]any)
		if !ok {
			continue
		}
		frameType, ok := requireNestedObject(t, ifBlock, "properties", "frame_type")["enum"].([]any)
		if !ok || len(frameType) != len(wantFrames) {
			continue
		}
		for _, want := range wantFrames {
			if !containsString(frameType, want) {
				t.Fatalf("runtime hostcall parent binding missing %s: %#v", want, frameType)
			}
		}
		required := requireStringSlice(t, requireNestedObject(t, block, "then")["required"], "runtime hostcall frame required")
		if !containsRequiredString(required, "parent_request_id") {
			t.Fatalf("runtime hostcall frame must require parent_request_id: %#v", required)
		}
		return
	}
	t.Fatal("ipc schema missing runtime hostcall parent binding")
}

func TestIPCSchemaBindsResourceScopesAcrossHandleStorageAndRevocation(t *testing.T) {
	schema := readPluginSchema(t, "ipc-v6.schema.json")
	defs := requireNestedObject(t, schema, "$defs")

	for _, name := range []string{
		"validate_handle_grant_request_payload",
		"storage_file_request_payload",
		"storage_kv_request_payload",
		"storage_sqlite_request_payload",
	} {
		definition := requireNestedObject(t, defs, name)
		required := requireStringSlice(t, definition["required"], name+" required")
		if !containsRequiredString(required, "resource_scope") {
			t.Fatalf("%s must require resource_scope: %#v", name, required)
		}
		if got := requireNestedObject(t, definition, "properties", "resource_scope")["$ref"]; got != "#/$defs/resource_scope" {
			t.Fatalf("%s resource_scope ref = %#v", name, got)
		}
	}

	responseBranches := requireObjectArray(t, requireNestedObject(t, defs, "validate_handle_grant_response_payload")["oneOf"], "handle grant response branches")
	handleResult := responseBranches[0]
	if !containsRequiredString(requireStringSlice(t, handleResult["required"], "handle grant result required"), "resource_scope") {
		t.Fatalf("handle grant result must require resource_scope: %#v", handleResult)
	}

	environmentScope := requireNestedObject(t, defs, "environment_resource_scope")
	if got := requireNestedObject(t, environmentScope, "properties", "kind")["const"]; got != "environment" {
		t.Fatalf("environment resource scope kind = %#v", got)
	}
	allOf, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatal("ipc schema missing allOf")
	}
	revoke := requireNestedObject(t, findIPCFrameBlock(t, allOf, "revoke_epoch"), "then", "properties", "payload")
	if !containsRequiredString(requireStringSlice(t, revoke["required"], "revoke required"), "resource_scope") {
		t.Fatalf("revoke request must require resource_scope: %#v", revoke)
	}
	if got := requireNestedObject(t, revoke, "properties", "resource_scope")["$ref"]; got != "#/$defs/environment_resource_scope" {
		t.Fatalf("revoke request resource_scope ref = %#v", got)
	}
	revokeResult := requireNestedObject(t, defs, "revoke_epoch_ack_result")
	if !containsRequiredString(requireStringSlice(t, revokeResult["required"], "revoke result required"), "resource_scope") {
		t.Fatalf("revoke result must require resource_scope: %#v", revokeResult)
	}
}

func TestIPCSchemaValidatesV4Frames(t *testing.T) {
	root := repoRoot(t)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	for resource, path := range map[string]string{
		"urn:redevplugin:ipc-v5": "ipc-v6.schema.json",
		"https://schemas.redevplugin.dev/plugin/worker-invocation-v3.schema.json": "worker-invocation-v3.schema.json",
	} {
		raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", path))
		if err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource(resource, bytes.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
	}
	compiled, err := compiler.Compile("urn:redevplugin:ipc-v5")
	if err != nil {
		t.Fatal(err)
	}
	validHelloAck, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "ipc", "valid_hello_ack.json"))
	if err != nil {
		t.Fatal(err)
	}
	var helloAckFixture map[string]any
	if err := json.Unmarshal(validHelloAck, &helloAckFixture); err != nil {
		t.Fatal(err)
	}
	validHandleGrant, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "ipc", "valid_validate_handle_grant.json"))
	if err != nil {
		t.Fatal(err)
	}
	var handleGrantFixture map[string]any
	if err := json.Unmarshal(validHandleGrant, &handleGrantFixture); err != nil {
		t.Fatal(err)
	}
	frames := map[string]map[string]any{
		"hello ack":             requireNestedObject(t, helloAckFixture, "frame"),
		"validate handle grant": requireNestedObject(t, handleGrantFixture, "frame"),
		"heartbeat ack": {
			"ipc_version":           "rust-ipc-v6",
			"frame_type":            "heartbeat",
			"request_id":            "heartbeat_1",
			"runtime_generation_id": "generation_1",
			"payload": map[string]any{
				"ok": true,
				"result": map[string]any{
					"runtime_generation_id": "generation_1",
					"runtime_unix_nano":     1,
					"max_staleness_ms":      5000,
					"host_sent_unix_nano":   1,
					"active_invocations":    1,
					"queued_invocations":    2,
					"limits": map[string]any{
						"worker_count":              8,
						"queue_capacity":            32,
						"per_plugin_concurrency":    4,
						"module_cache_entries":      64,
						"module_cache_source_bytes": 134217728,
					},
					"module_cache": map[string]any{
						"hits": 10, "misses": 2, "compiles": 2, "entries": 2, "source_bytes": 4096,
					},
				},
			},
		},
		"cancel request": {
			"ipc_version":           "rust-ipc-v6",
			"frame_type":            "cancel_invoke",
			"request_id":            "cancel_1",
			"runtime_generation_id": "generation_1",
			"payload":               map[string]any{"invocation_request_id": "invoke_1"},
		},
		"cancel ack": {
			"ipc_version":           "rust-ipc-v6",
			"frame_type":            "cancel_invoke_ack",
			"request_id":            "cancel_1",
			"runtime_generation_id": "generation_1",
			"payload": map[string]any{
				"ok":     true,
				"result": map[string]any{"invocation_request_id": "invoke_1", "disposition": "running"},
			},
		},
		"hostcall request": {
			"ipc_version":           "rust-ipc-v6",
			"frame_type":            "open_handle",
			"request_id":            "invoke_1:artifact",
			"parent_request_id":     "invoke_1",
			"runtime_generation_id": "generation_1",
			"payload": map[string]any{
				"package_hash":    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"artifact":        "workers/backend.wasm",
				"artifact_sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		"hostcall response": {
			"ipc_version":           "rust-ipc-v6",
			"frame_type":            "open_handle",
			"request_id":            "invoke_1:artifact",
			"parent_request_id":     "invoke_1",
			"runtime_generation_id": "generation_1",
			"payload": map[string]any{
				"ok":             true,
				"package_hash":   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"artifact":       "workers/backend.wasm",
				"sha256":         "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				"content_base64": "AGFzbQ==",
			},
		},
	}
	for name, frame := range frames {
		if err := compiled.Validate(frame); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Draft 2020-12 has no standard property-relative numeric keyword. The
	// schema documents this cross-field rule while the language parsers enforce it.
	crossFieldInvalid := mapsClone(frames["heartbeat ack"])
	payload := mapsClone(crossFieldInvalid["payload"].(map[string]any))
	result := mapsClone(payload["result"].(map[string]any))
	limits := mapsClone(result["limits"].(map[string]any))
	limits["worker_count"] = 1
	limits["per_plugin_concurrency"] = 2
	result["limits"] = limits
	payload["result"] = result
	crossFieldInvalid["payload"] = payload
	if err := compiled.Validate(crossFieldInvalid); err != nil {
		t.Fatalf("per-field runtime limit schema rejected parser-enforced cross-field input: %v", err)
	}
	if err := runtimeclient.ValidateRuntimeLimits(runtimeclient.RuntimeLimits{
		WorkerCount:            1,
		QueueCapacity:          32,
		PerPluginConcurrency:   2,
		ModuleCacheEntries:     64,
		ModuleCacheSourceBytes: runtimeclient.RuntimeModuleCacheSourceBytesMax,
	}); !errors.Is(err, runtimeclient.ErrRuntimeLimitsInvalid) {
		t.Fatalf("runtime parser cross-field error = %v, want %v", err, runtimeclient.ErrRuntimeLimitsInvalid)
	}

	missingParent := mapsClone(frames["hostcall request"])
	delete(missingParent, "parent_request_id")
	if err := compiled.Validate(missingParent); err == nil {
		t.Fatal("runtime hostcall without parent_request_id must be rejected")
	}
	for _, path := range []string{
		"workers/../backend.wasm",
		"workers/.hidden/backend.wasm",
		"workers//backend.wasm",
		`workers\backend.wasm`,
	} {
		invalid := mapsClone(frames["hostcall request"])
		payload := mapsClone(invalid["payload"].(map[string]any))
		payload["artifact"] = path
		invalid["payload"] = payload
		if err := compiled.Validate(invalid); err == nil {
			t.Errorf("runtime hostcall artifact path %q must be rejected", path)
		}
	}
}

func mapsClone(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func findIPCFrameBlock(t *testing.T, allOf []any, frameType string) map[string]any {
	t.Helper()
	for _, item := range allOf {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ifBlock, ok := block["if"].(map[string]any)
		if !ok {
			continue
		}
		properties, ok := ifBlock["properties"].(map[string]any)
		if !ok {
			continue
		}
		frame, ok := properties["frame_type"].(map[string]any)
		if ok && frame["const"] == frameType {
			return block
		}
	}
	t.Fatalf("ipc schema missing %s block", frameType)
	return nil
}

func TestIPCSchemaPublishesOnlyImplementedFrameTypes(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	frameType := requireNestedObject(t, schema, "properties", "frame_type")
	assertStringEnum(t, frameType["enum"], "ipc frame types", []string{
		"hello",
		"hello_ack",
		"heartbeat",
		"invoke_worker",
		"invoke_worker_result",
		"cancel_invoke",
		"cancel_invoke_ack",
		"compile_flight_register",
		"compile_flight_complete",
		"open_handle",
		"validate_handle_grant",
		"storage_file",
		"storage_kv",
		"storage_sqlite",
		"network_grant",
		"network_execute",
		"revoke_epoch",
		"revoke_epoch_ack",
		"session_revoke",
		"session_revoke_ack",
		"diagnostic",
	})

	allOf, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatal("ipc schema missing allOf")
	}
	for _, item := range allOf {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ifBlock := requireNestedObject(t, block, "if", "properties", "frame_type")
		if ifBlock["const"] != "diagnostic" {
			continue
		}
		thenBlock := requireNestedObject(t, block, "then")
		if thenBlock["$ref"] != "#/$defs/runtime_response_frame" {
			t.Fatalf("diagnostic response ref = %#v", thenBlock["$ref"])
		}
		return
	}
	t.Fatal("ipc schema missing diagnostic response block")
}

func TestIPCSchemaDefinesClosedCompileFlightLifecycleFrames(t *testing.T) {
	schema := readPluginSchema(t, "ipc-v6.schema.json")
	allOf, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatal("ipc schema missing allOf")
	}
	for _, frameType := range []string{"compile_flight_register", "compile_flight_complete"} {
		block := findIPCFrameBlock(t, allOf, frameType)
		required := requireStringSlice(t, requireNestedObject(t, block, "then")["required"], frameType+" required")
		assertStringSet(t, required, []string{"parent_request_id", "runtime_generation_id", "payload"}, frameType+" required")
		payload := requireNestedObject(t, block, "then", "properties", "payload")
		if payload["$ref"] != "#/$defs/compile_flight_lifecycle_payload" {
			t.Fatalf("%s payload ref = %#v", frameType, payload["$ref"])
		}
	}

	definition := requireNestedObject(t, schema, "$defs", "compile_flight_lifecycle_payload")
	if definition["type"] != "object" || definition["additionalProperties"] != false {
		t.Fatalf("compile flight lifecycle payload must be closed: %#v", definition)
	}
	fields := []string{"artifact_request_id", "package_hash", "artifact", "artifact_sha256", "wasm_abi_version"}
	assertStringSet(t, requireStringSlice(t, definition["required"], "compile flight lifecycle required"), fields, "compile flight lifecycle required")
	properties := requireNestedObject(t, definition, "properties")
	for _, field := range fields {
		if _, ok := properties[field].(map[string]any); !ok {
			t.Fatalf("compile flight lifecycle payload missing %s", field)
		}
	}
	if got := requireNestedObject(t, properties, "wasm_abi_version")["const"]; got != "redevplugin-wasm-worker-v2" {
		t.Fatalf("compile flight wasm ABI = %#v", got)
	}
}

func TestIPCSchemaAttestsClosedErrorOrigins(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := requireNestedObject(t, schema, "$defs")
	for _, name := range []string{
		"heartbeat_response_payload",
		"revoke_epoch_ack_response_payload",
		"runtime_response_frame",
	} {
		definition := requireNestedObject(t, defs, name)
		response := definition
		if name == "runtime_response_frame" {
			response = requireNestedObject(t, definition, "properties", "payload")
		}
		_, failure := requireClosedResponseBranches(t, defs, response, name)
		origin := requireNestedObject(t, failure, "properties", "error_origin")
		assertStringEnum(t, origin["enum"], name+" error origin", []string{"runtime", "hostcall", "plugin"})
	}
	for _, name := range []string{
		"open_handle_response_payload",
		"validate_handle_grant_response_payload",
		"network_grant_response_payload",
		"network_execute_response_payload",
	} {
		definition := requireNestedObject(t, defs, name)
		_, failure := requireClosedResponseBranches(t, defs, definition, name)
		assertClosedHostcallFailureBranch(t, definition, failure, name)
	}
	for _, name := range []string{
		"storage_file_response_payload",
		"storage_kv_response_payload",
		"storage_sqlite_response_payload",
	} {
		definition := requireNestedObject(t, defs, name)
		assertOperationSpecificHostcallFailureBranch(t, defs, definition, name)
	}
}

func TestIPCSchemaRequiresWorkerLeaseContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	allOf, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatal("ipc schema missing allOf")
	}
	for _, item := range allOf {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ifBlock := requireNestedObject(t, block, "if", "properties", "frame_type")
		if ifBlock["const"] != "invoke_worker" {
			continue
		}
		lease := requireNestedObject(t, block, "then", "properties", "payload", "properties", "lease")
		required := requireStringSlice(t, lease["required"], "invoke_worker lease required")
		for _, name := range []string{
			"lease_id",
			"token_id",
			"lease_nonce",
			"runtime_generation_id",
			"plugin_instance_id",
			"plugin_id",
			"plugin_version",
			"active_fingerprint",
			"issued_at_unix_ms",
			"method",
			"effect",
			"execution",
			"audit_correlation_id",
			"target_descriptor_hashes",
			"limits",
			"policy_revision",
			"management_revision",
			"revoke_epoch",
			"runtime_shard_id",
			"runtime_instance_id",
			"ipc_channel_id",
			"connection_nonce",
			"key_id",
			"signature",
			"expires_at_unix_ms",
		} {
			if !containsRequiredString(required, name) {
				t.Fatalf("invoke_worker lease required missing %s: %#v", name, required)
			}
		}
		leaseNonce := requireNestedObject(t, lease, "properties", "lease_nonce")
		if leaseNonce["type"] != "string" || leaseNonce["minLength"] != float64(16) {
			t.Fatalf("invoke_worker lease_nonce schema = %#v", leaseNonce)
		}
		props := requireNestedObject(t, lease, "properties")
		for _, name := range []string{
			"token_id",
			"plugin_id",
			"plugin_version",
			"active_fingerprint",
			"issued_at_unix_ms",
			"method",
			"effect",
			"execution",
			"operation_id",
			"stream_id",
			"audit_correlation_id",
			"surface_instance_id",
			"owner_session_hash",
			"owner_user_hash",
			"owner_env_hash",
			"session_channel_id_hash",
			"bridge_channel_id",
			"target_descriptor_hashes",
			"limits",
			"runtime_shard_id",
			"runtime_instance_id",
			"ipc_channel_id",
			"connection_nonce",
			"key_id",
			"signature",
		} {
			if _, ok := props[name].(map[string]any); !ok {
				t.Fatalf("invoke_worker lease schema missing %s", name)
			}
		}
		if lease["additionalProperties"] != false {
			t.Fatalf("invoke_worker lease must be closed: %#v", lease["additionalProperties"])
		}
		limitsSchema := requireNestedObject(t, lease, "properties", "limits")
		assertStringSet(t, requireStringSlice(t, limitsSchema["required"], "lease limits required"), []string{
			"timeout_ms", "memory_bytes", "max_payload_bytes", "max_stream_bytes_per_sec",
		}, "lease limits required")
		signature := requireNestedObject(t, lease, "properties", "signature")
		if signature["pattern"] != "^ed25519:.+" {
			t.Fatalf("invoke_worker lease signature schema = %#v", signature)
		}
		limits := requireNestedObject(t, lease, "properties", "limits", "properties")
		for _, name := range []string{"timeout_ms", "max_payload_bytes", "max_stream_bytes_per_sec"} {
			field := requireNestedObject(t, limits, name)
			if field["type"] != "integer" || field["minimum"] != float64(0) {
				t.Fatalf("invoke_worker lease limits %s schema = %#v", name, field)
			}
		}
		memory := requireNestedObject(t, limits, "memory_bytes")
		if memory["type"] != "integer" ||
			memory["minimum"] != float64(1) ||
			memory["maximum"] != float64(manifest.MaxWorkerMemoryLimitBytes) {
			t.Fatalf("invoke_worker lease memory_bytes schema = %#v", memory)
		}
		return
	}
	t.Fatal("ipc schema missing invoke_worker block")
}

func TestIPCSchemaDefinesOpenHandlePayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "open_handle_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"package_hash", "artifact", "artifact_sha256"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("open_handle request missing %s", name)
		}
	}
	response := requireNestedObject(t, defs, "open_handle_response_payload")
	success, failure := requireClosedResponseBranches(t, defs, response, "open_handle response")
	assertClosedSuccessBranch(t, success, "open_handle response", []string{"ok", "package_hash", "artifact", "sha256", "content_base64"})
	successProps := requireNestedObject(t, success, "properties")
	for _, name := range []string{"ok", "package_hash", "artifact", "sha256", "content_base64"} {
		if _, ok := successProps[name].(map[string]any); !ok {
			t.Fatalf("open_handle response missing %s", name)
		}
	}
	assertClosedHostcallFailureBranch(t, response, failure, "open_handle response")
	artifact := requireNestedObject(t, defs, "worker_artifact_path")
	if artifact["pattern"] != "^workers/.+\\.wasm$" {
		t.Fatalf("worker artifact pattern = %#v", artifact["pattern"])
	}
	forbidden := requireNestedObject(t, artifact, "not")
	branches := requireObjectArray(t, forbidden["anyOf"], "worker artifact forbidden patterns")
	wantPatterns := map[string]bool{"(^|/)\\.": false, "//": false, "\\\\": false}
	for _, branch := range branches {
		pattern, ok := branch["pattern"].(string)
		if !ok {
			t.Fatalf("worker artifact forbidden branch = %#v", branch)
		}
		if _, ok := wantPatterns[pattern]; !ok {
			t.Fatalf("unexpected worker artifact forbidden pattern %q", pattern)
		}
		wantPatterns[pattern] = true
	}
	for pattern, found := range wantPatterns {
		if !found {
			t.Fatalf("worker artifact forbidden pattern %q is missing", pattern)
		}
	}
}

func TestIPCSchemaDefinesHandleGrantValidationPayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "validate_handle_grant_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"handle_grant_token", "plugin_instance_id", "active_fingerprint", "runtime_instance_id", "runtime_generation_id", "runtime_shard_id", "owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash", "handle_id", "method", "resource_scope", "policy_revision", "management_revision", "revoke_epoch"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("validate_handle_grant request missing %s", name)
		}
	}
	assertRequiredFields(t, request, "validate_handle_grant request", []string{"owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"})
	if minimum := requireNestedObject(t, requestProps, "revoke_epoch")["minimum"]; minimum != float64(1) {
		t.Fatalf("validate_handle_grant revoke_epoch minimum = %#v, want 1", minimum)
	}
	for _, name := range []string{"policy_revision", "management_revision", "revoke_epoch"} {
		field := requireNestedObject(t, requestProps, name)
		wantMinimum := float64(0)
		if name == "revoke_epoch" {
			wantMinimum = 1
		}
		if field["minimum"] != wantMinimum || field["maximum"] != float64(9007199254740991) {
			t.Fatalf("validate_handle_grant %s bounds = %#v", name, field)
		}
	}
	response := requireNestedObject(t, defs, "validate_handle_grant_response_payload")
	success, failure := requireClosedResponseBranches(t, defs, response, "validate_handle_grant response")
	assertClosedSuccessBranch(t, success, "validate_handle_grant response", []string{"ok", "handle_grant_id", "handle_id", "method", "runtime_generation_id", "resource_scope"})
	successProps := requireNestedObject(t, success, "properties")
	for _, name := range []string{"ok", "handle_grant_id", "handle_id", "method", "runtime_generation_id", "resource_scope", "max_total_bytes"} {
		if _, ok := successProps[name].(map[string]any); !ok {
			t.Fatalf("validate_handle_grant response missing %s", name)
		}
	}
	assertClosedHostcallFailureBranch(t, response, failure, "validate_handle_grant response")
}

func TestIPCSchemaRequiresPositiveRevokeEpochs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	count := 0
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if key == "revoke_epoch" {
					field, ok := child.(map[string]any)
					if !ok || field["type"] != "integer" || field["minimum"] != float64(1) || field["maximum"] != float64(9007199254740991) {
						t.Fatalf("revoke_epoch schema must require a positive integer: %#v", child)
					}
					count++
				}
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(schema)
	if count == 0 {
		t.Fatal("ipc-v5 schema does not define revoke_epoch")
	}
}

func TestIPCSchemaBoundsRevisionBindingsToJSONSafeIntegers(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{"policy_revision": 0, "management_revision": 0}
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, tracked := counts[key]; tracked {
					field, ok := child.(map[string]any)
					if !ok || field["type"] != "integer" || field["minimum"] != float64(0) || field["maximum"] != float64(9007199254740991) {
						t.Fatalf("%s schema must be a non-negative JSON-safe integer: %#v", key, child)
					}
					counts[key]++
				}
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(schema)
	for key, count := range counts {
		if count == 0 {
			t.Fatalf("ipc-v5 schema does not define %s", key)
		}
	}
}

func TestIPCSchemaDefinesStorageFilePayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "storage_file_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"handle_grant_token", "plugin_instance_id", "active_fingerprint", "runtime_generation_id", "handle_id", "method", "operation", "store_id", "path", "data_base64"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("storage_file request missing %s", name)
		}
	}
	assertRequiredFields(t, request, "storage_file request", []string{"runtime_instance_id", "runtime_generation_id", "runtime_shard_id"})
	method := requireNestedObject(t, requestProps, "method")
	if method["const"] != "storage.files" {
		t.Fatalf("storage_file method = %#v", method["const"])
	}
	response := requireNestedObject(t, defs, "storage_file_response_payload")
	assertOperationSpecificHostcallResponse(t, defs, response, "storage_file response", map[string][]string{
		"storage_file_read_success_response_payload":   {"ok", "path", "data_base64", "size_bytes", "usage"},
		"storage_file_write_success_response_payload":  {"ok", "path", "size_bytes", "usage"},
		"storage_file_delete_success_response_payload": {"ok", "path"},
		"storage_file_list_success_response_payload":   {"ok", "path", "entries", "usage"},
	})
}

func TestIPCSchemaDefinesStorageKVPayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	frameType := requireNestedObject(t, schema, "properties", "frame_type")
	frameEnum, ok := frameType["enum"].([]any)
	if !ok || !containsString(frameEnum, "storage_kv") {
		t.Fatalf("frame_type enum missing storage_kv: %#v", frameType["enum"])
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "storage_kv_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"handle_grant_token", "plugin_instance_id", "active_fingerprint", "runtime_generation_id", "handle_id", "method", "operation", "store_id", "key", "value_base64", "prefix"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("storage_kv request missing %s", name)
		}
	}
	assertRequiredFields(t, request, "storage_kv request", []string{"runtime_instance_id", "runtime_generation_id", "runtime_shard_id"})
	method := requireNestedObject(t, requestProps, "method")
	if method["const"] != "storage.kv" {
		t.Fatalf("storage_kv method = %#v", method["const"])
	}
	response := requireNestedObject(t, defs, "storage_kv_response_payload")
	assertOperationSpecificHostcallResponse(t, defs, response, "storage_kv response", map[string][]string{
		"storage_kv_get_success_response_payload":    {"ok", "key", "value_base64", "size_bytes", "usage"},
		"storage_kv_put_success_response_payload":    {"ok", "key", "size_bytes", "usage"},
		"storage_kv_delete_success_response_payload": {"ok", "key"},
		"storage_kv_list_success_response_payload":   {"ok", "entries", "usage"},
	})
}

func TestIPCSchemaDefinesStorageSQLitePayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	frameType := requireNestedObject(t, schema, "properties", "frame_type")
	frameEnum, ok := frameType["enum"].([]any)
	if !ok || !containsString(frameEnum, "storage_sqlite") {
		t.Fatalf("frame_type enum missing storage_sqlite: %#v", frameType["enum"])
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "storage_sqlite_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"handle_grant_token", "plugin_instance_id", "active_fingerprint", "runtime_generation_id", "handle_id", "method", "operation", "store_id", "database", "sql", "args", "max_rows", "max_response_bytes", "timeout_ms"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("storage_sqlite request missing %s", name)
		}
	}
	assertRequiredFields(t, request, "storage_sqlite request", []string{"runtime_instance_id", "runtime_generation_id", "runtime_shard_id"})
	method := requireNestedObject(t, requestProps, "method")
	if method["const"] != "storage.sqlite" {
		t.Fatalf("storage_sqlite method = %#v", method["const"])
	}
	response := requireNestedObject(t, defs, "storage_sqlite_response_payload")
	assertOperationSpecificHostcallResponse(t, defs, response, "storage_sqlite response", map[string][]string{
		"storage_sqlite_exec_success_response_payload":  {"ok", "database", "rows_affected", "usage"},
		"storage_sqlite_query_success_response_payload": {"ok", "database", "columns", "rows", "usage"},
	})
	value := requireNestedObject(t, defs, "storage_sqlite_value")
	valueProps := requireNestedObject(t, value, "properties")
	for _, name := range []string{"null", "int", "float", "text", "blob_base64"} {
		if _, ok := valueProps[name].(map[string]any); !ok {
			t.Fatalf("storage_sqlite value missing %s", name)
		}
	}
	branches, ok := value["oneOf"].([]any)
	if !ok || len(branches) != 5 {
		t.Fatalf("storage_sqlite value oneOf = %#v, want five typed branches", value["oneOf"])
	}
	for _, raw := range branches {
		branch, ok := raw.(map[string]any)
		if !ok || len(branch) == 0 {
			t.Fatalf("storage_sqlite value branch = %#v", raw)
		}
		if _, ok := branch["required"].([]any); !ok {
			t.Fatalf("storage_sqlite value branch lacks required field: %#v", branch)
		}
	}
}

func TestIPCSchemaDefinesStorageUsageFileQuotaFields(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	usage := requireNestedObject(t, requireNestedObject(t, schema, "$defs"), "storage_usage")
	props := requireNestedObject(t, usage, "properties")
	for _, name := range []string{"plugin_instance_id", "store_id", "usage_bytes", "quota_bytes", "usage_files", "quota_files"} {
		if _, ok := props[name].(map[string]any); !ok {
			t.Fatalf("storage_usage missing %s", name)
		}
	}
	assertStringSet(t, requireStringSlice(t, usage["required"], "storage_usage required"), []string{"plugin_instance_id", "store_id", "usage_bytes", "quota_bytes", "usage_files", "quota_files"}, "storage_usage required")
}

func TestIPCSchemaDefinesNetworkGrantPayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "network_grant_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"plugin_instance_id", "active_fingerprint", "resource_scope", "runtime_generation_id", "policy_revision", "management_revision", "revoke_epoch", "connector_id", "transport", "destination", "ttl_ms"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("network_grant request missing %s", name)
		}
	}
	assertRequiredFields(t, request, "network_grant request", []string{"resource_scope", "runtime_instance_id", "runtime_generation_id", "runtime_shard_id"})
	transport := requireNestedObject(t, requestProps, "transport")
	enum, ok := transport["enum"].([]any)
	if !ok || len(enum) != 4 {
		t.Fatalf("network_grant transport enum = %#v", transport["enum"])
	}
	response := requireNestedObject(t, defs, "network_grant_response_payload")
	success, failure := requireClosedResponseBranches(t, defs, response, "network_grant response")
	assertClosedSuccessBranch(t, success, "network_grant response", []string{
		"ok", "grant_id", "plugin_instance_id", "active_fingerprint", "policy_revision", "management_revision",
		"revoke_epoch", "connector_id", "transport", "destination", "runtime_generation_id",
		"resource_scope", "target_classifier_version", "expires_at",
	})
	successProps := requireNestedObject(t, success, "properties")
	for _, name := range []string{"ok", "grant_id", "resource_scope", "connector_id", "transport", "destination", "runtime_generation_id", "target_classifier_version", "expires_at"} {
		if _, ok := successProps[name].(map[string]any); !ok {
			t.Fatalf("network_grant response missing %s", name)
		}
	}
	assertClosedHostcallFailureBranch(t, response, failure, "network_grant response")
	destination := requireNestedObject(t, defs, "network_destination")
	destinationProps := requireNestedObject(t, destination, "properties")
	for _, name := range []string{"transport", "scheme", "host", "port"} {
		if _, ok := destinationProps[name].(map[string]any); !ok {
			t.Fatalf("network_destination missing %s", name)
		}
	}
}

func TestIPCSchemaDefinesNetworkExecutePayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	frameType := requireNestedObject(t, schema, "properties", "frame_type")
	frameEnum, ok := frameType["enum"].([]any)
	if !ok || !containsString(frameEnum, "network_execute") {
		t.Fatalf("frame_type enum missing network_execute: %#v", frameType["enum"])
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "network_execute_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"plugin_id", "plugin_instance_id", "active_fingerprint", "resource_scope", "runtime_generation_id", "policy_revision", "management_revision", "revoke_epoch", "connector_id", "transport", "destination", "operation", "method", "path", "headers", "body_base64", "payload_base64", "max_response_bytes", "max_chunk_bytes", "max_buffered_bytes", "timeout_ms", "stream_id", "stream_method", "stream_effect", "stream_execution", "surface_instance_id", "owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash", "bridge_channel_id", "content_type"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("network_execute request missing %s", name)
		}
	}
	assertRequiredFields(t, request, "network_execute request", []string{
		"plugin_id", "resource_scope", "runtime_instance_id", "runtime_generation_id", "runtime_shard_id",
		"owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash",
	})
	operation := requireNestedObject(t, requestProps, "operation")
	if enum, ok := operation["enum"].([]any); !ok || !containsString(enum, "http_stream") || !containsString(enum, "websocket_round_trip") || !containsString(enum, "udp_round_trip") {
		t.Fatalf("network_execute operation enum = %#v", operation["enum"])
	}
	response := requireNestedObject(t, defs, "network_execute_response_payload")
	success, failure := requireClosedResponseBranches(t, defs, response, "network_execute response")
	assertClosedSuccessBranch(t, success, "network_execute response", []string{
		"ok", "transport", "destination", "grant_id", "connector_id", "runtime_generation_id",
	})
	successProps := requireNestedObject(t, success, "properties")
	for _, name := range []string{"ok", "transport", "destination", "status_code", "headers", "message_type", "body_base64", "payload_base64", "stream_id", "bytes_read", "chunk_count", "grant_id", "connector_id", "runtime_generation_id"} {
		if _, ok := successProps[name].(map[string]any); !ok {
			t.Fatalf("network_execute response missing %s", name)
		}
	}
	assertClosedHostcallFailureBranch(t, response, failure, "network_execute response")
}

func TestIPCSchemaDefinesRevokeEpochAckResult(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := requireNestedObject(t, schema, "$defs")
	payload := requireNestedObject(t, defs, "revoke_epoch_ack_response_payload")
	success, failure := requireClosedResponseBranches(t, defs, payload, "revoke_epoch_ack payload")
	if resultRef := requireNestedObject(t, success, "properties", "result")["$ref"]; resultRef != "#/$defs/revoke_epoch_ack_result" {
		t.Fatalf("revoke_epoch_ack result ref = %#v", resultRef)
	}
	assertClosedFailureBranch(t, failure, "revoke_epoch_ack payload")
	result := requireNestedObject(t, defs, "revoke_epoch_ack_result")
	required := requireStringSlice(t, result["required"], "revoke_epoch_ack result required")
	for _, name := range []string{"plugin_instance_id", "revoke_epoch", "closed_socket_count", "closed_stream_count", "closed_storage_handle_count"} {
		if !containsRequiredString(required, name) {
			t.Fatalf("revoke_epoch_ack result required missing %s: %#v", name, required)
		}
	}
	resultProps := requireNestedObject(t, result, "properties")
	if _, ok := resultProps["closed_actor_count"]; ok {
		t.Fatal("revoke_epoch_ack contains an undeclared actor counter")
	}
	for _, name := range []string{"revoke_epoch", "closed_socket_count", "closed_stream_count", "closed_storage_handle_count"} {
		field := requireNestedObject(t, resultProps, name)
		minimum := float64(0)
		if name == "revoke_epoch" {
			minimum = 1
		}
		if field["type"] != "integer" || field["minimum"] != minimum {
			t.Fatalf("revoke_epoch_ack result %s schema = %#v", name, field)
		}
	}
	pluginInstanceID := requireNestedObject(t, resultProps, "plugin_instance_id")
	if pluginInstanceID["type"] != "string" || pluginInstanceID["minLength"] != float64(1) {
		t.Fatalf("revoke_epoch_ack plugin_instance_id schema = %#v", pluginInstanceID)
	}
}

func requireClosedResponseBranches(t *testing.T, defs, response map[string]any, label string) (map[string]any, map[string]any) {
	t.Helper()
	branches, ok := response["oneOf"].([]any)
	if !ok || len(branches) != 2 {
		t.Fatalf("%s oneOf = %#v, want two branches", label, response["oneOf"])
	}
	var success, failure map[string]any
	for _, raw := range branches {
		branch, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s branch is not an object: %#v", label, raw)
		}
		if ref, ok := branch["$ref"].(string); ok {
			const prefix = "#/$defs/"
			if len(branch) != 1 || len(ref) <= len(prefix) || ref[:len(prefix)] != prefix {
				t.Fatalf("%s branch ref = %#v", label, raw)
			}
			branch = requireNestedObject(t, defs, ref[len(prefix):])
		}
		if branch["additionalProperties"] != false {
			t.Fatalf("%s branch is not closed: %#v", label, raw)
		}
		okValue := requireNestedObject(t, branch, "properties", "ok")["const"]
		switch okValue {
		case true:
			success = branch
		case false:
			failure = branch
		default:
			t.Fatalf("%s branch ok const = %#v", label, okValue)
		}
	}
	if success == nil || failure == nil {
		t.Fatalf("%s must define success and failure branches", label)
	}
	return success, failure
}

func assertOperationSpecificHostcallResponse(t *testing.T, defs, response map[string]any, label string, successes map[string][]string) {
	t.Helper()
	branches, ok := response["oneOf"].([]any)
	if !ok || len(branches) != len(successes)+1 {
		t.Fatalf("%s oneOf = %#v, want %d success branches and one failure", label, response["oneOf"], len(successes))
	}
	wantRefs := make(map[string]struct{}, len(successes)+1)
	for name, required := range successes {
		definition := requireNestedObject(t, defs, name)
		if definition["additionalProperties"] != false {
			t.Fatalf("%s success %s is not closed: %#v", label, name, definition)
		}
		if requireNestedObject(t, definition, "properties", "ok")["const"] != true {
			t.Fatalf("%s success %s ok is not true", label, name)
		}
		assertClosedSuccessBranch(t, definition, label+" "+name, required)
		wantRefs["#/$defs/"+name] = struct{}{}
	}
	wantRefs["#/$defs/hostcall_failure_response_payload"] = struct{}{}
	for _, raw := range branches {
		branch, ok := raw.(map[string]any)
		if !ok || len(branch) != 1 {
			t.Fatalf("%s branch is not a single ref: %#v", label, raw)
		}
		ref, ok := branch["$ref"].(string)
		if !ok {
			t.Fatalf("%s branch has no ref: %#v", label, raw)
		}
		if _, ok := wantRefs[ref]; !ok {
			t.Fatalf("%s has unexpected branch %s", label, ref)
		}
		delete(wantRefs, ref)
	}
	if len(wantRefs) != 0 {
		t.Fatalf("%s missing branches: %#v", label, wantRefs)
	}
	failure := requireNestedObject(t, defs, "hostcall_failure_response_payload")
	assertClosedHostcallFailureBranch(t, response, failure, label)
}

func assertClosedHostcallFailureBranch(t *testing.T, response, failure map[string]any, label string) {
	t.Helper()
	assertClosedFailureBranch(t, failure, label)
	origin := requireNestedObject(t, failure, "properties", "error_origin")
	if origin["const"] != "hostcall" {
		t.Fatalf("%s error origin = %#v, want hostcall", label, origin)
	}
	assertStableHostcallCode(t, failure, label)
	branches := response["oneOf"].([]any)
	for _, raw := range branches {
		branch, ok := raw.(map[string]any)
		if ok && len(branch) == 1 && branch["$ref"] == "#/$defs/hostcall_failure_response_payload" {
			return
		}
	}
	t.Fatalf("%s does not reference the shared hostcall failure branch", label)
}

func assertOperationSpecificHostcallFailureBranch(t *testing.T, defs, response map[string]any, label string) {
	t.Helper()
	branches, ok := response["oneOf"].([]any)
	if !ok || len(branches) < 2 {
		t.Fatalf("%s oneOf = %#v, want success branches and one failure", label, response["oneOf"])
	}
	failureRef := "#/$defs/hostcall_failure_response_payload"
	found := false
	for _, raw := range branches {
		branch, ok := raw.(map[string]any)
		if !ok || len(branch) != 1 {
			continue
		}
		if branch["$ref"] == failureRef {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("%s does not reference shared hostcall failure branch", label)
	}
	failure := requireNestedObject(t, defs, "hostcall_failure_response_payload")
	assertClosedFailureBranch(t, failure, label)
	origin := requireNestedObject(t, failure, "properties", "error_origin")
	if origin["const"] != "hostcall" {
		t.Fatalf("%s error origin = %#v, want hostcall", label, origin)
	}
	assertStableHostcallCode(t, failure, label)
}

func assertStableHostcallCode(t *testing.T, failure map[string]any, label string) {
	t.Helper()
	code := requireNestedObject(t, failure, "properties", "code")
	if code["maxLength"] != float64(128) || code["pattern"] != "^[A-Z][A-Z0-9_]{0,127}$" {
		t.Fatalf("%s failure code is not the stable hostcall code contract: %#v", label, code)
	}
}

func assertClosedSuccessBranch(t *testing.T, branch map[string]any, label string, wantRequired []string) {
	t.Helper()
	assertStringSet(t, requireStringSlice(t, branch["required"], label+" success required"), wantRequired, label+" success required")
}

func assertClosedFailureBranch(t *testing.T, branch map[string]any, label string) {
	t.Helper()
	required := requireStringSlice(t, branch["required"], label+" failure required")
	for _, name := range []string{"ok", "code", "message", "error_origin"} {
		if !containsRequiredString(required, name) {
			t.Fatalf("%s failure missing required %s: %#v", label, name, required)
		}
	}
	properties := requireNestedObject(t, branch, "properties")
	for _, name := range []string{"code", "message"} {
		field := requireNestedObject(t, properties, name)
		if field["type"] != "string" || field["minLength"] != float64(1) {
			t.Fatalf("%s failure %s = %#v", label, name, field)
		}
	}
}

func containsString(values []any, want string) bool {
	for _, value := range values {
		if got, ok := value.(string); ok && got == want {
			return true
		}
	}
	return false
}

func assertRequiredFields(t *testing.T, definition map[string]any, label string, fields []string) {
	t.Helper()
	required := requireStringSlice(t, definition["required"], label+" required")
	for _, field := range fields {
		if !containsRequiredString(required, field) {
			t.Fatalf("%s required missing %s: %#v", label, field, required)
		}
	}
}

func containsRequiredString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
