package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestPerformanceEvidenceSchemaValidatesReleaseEvidence(t *testing.T) {
	t.Parallel()
	schema := compilePerformanceEvidenceSchema(t)
	evidence := validPerformanceEvidence()
	if err := schema.Validate(evidence); err != nil {
		t.Fatalf("valid performance evidence was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "failed scenario",
			mutate: func(document map[string]any) {
				document["scenarios"].([]any)[0].(map[string]any)["status"] = "fail"
			},
		},
		{
			name: "negative metric",
			mutate: func(document map[string]any) {
				document["scenarios"].([]any)[0].(map[string]any)["metrics"].([]any)[0].(map[string]any)["observed"] = -1.0
			},
		},
		{
			name: "unknown top-level field",
			mutate: func(document map[string]any) {
				document["fallback"] = true
			},
		},
		{
			name: "missing chromium version",
			mutate: func(document map[string]any) {
				delete(document["environment"].(map[string]any), "chromium_version")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := cloneJSONDocument(t, evidence)
			test.mutate(mutated)
			if err := schema.Validate(mutated); err == nil {
				t.Fatalf("performance evidence schema accepted %s", test.name)
			}
		})
	}
}

func compilePerformanceEvidenceSchema(t testing.TB) *jsonschema.Schema {
	t.Helper()
	root := hostCapabilityRepositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "performance-evidence-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	const resource = "urn:redevplugin:test:performance-evidence-v1"
	if err := compiler.AddResource(resource, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(resource)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func validPerformanceEvidence() map[string]any {
	return map[string]any{
		"schema_version":  "redevplugin.performance_evidence.v1",
		"release_version": "0.5.0",
		"source_commit":   "0123456789abcdef0123456789abcdef01234567",
		"generated_at":    "2026-07-16T08:00:00Z",
		"environment": map[string]any{
			"os":               "darwin",
			"arch":             "arm64",
			"logical_cpus":     10,
			"go_version":       "go version go1.24.0 darwin/arm64",
			"node_version":     "v24.0.0",
			"rustc_version":    "rustc 1.88.0",
			"chromium_version": "Chromium 138.0.0.0",
		},
		"scenarios": []any{
			map[string]any{
				"id":           "runtime.warm-invocations",
				"gate":         "release",
				"status":       "pass",
				"sample_count": 32,
				"metrics": []any{
					map[string]any{
						"name":       "p95",
						"unit":       "milliseconds",
						"observed":   7.5,
						"limit":      100.0,
						"comparator": "lte",
					},
				},
			},
		},
		"contract_hashes": []any{
			map[string]any{
				"id":     "rust-ipc-schema",
				"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
		},
	}
}

func cloneJSONDocument(t testing.TB, value map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}
