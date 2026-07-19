package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
			name: "missing comparison provenance",
			mutate: func(document map[string]any) {
				delete(document, "comparisons")
			},
		},
		{
			name: "missing comparison run",
			mutate: func(document map[string]any) {
				comparison := document["comparisons"].([]any)[0].(map[string]any)
				comparison["runs"] = comparison["runs"].([]any)[:2]
			},
		},
		{
			name: "unknown comparison run field",
			mutate: func(document map[string]any) {
				comparison := document["comparisons"].([]any)[0].(map[string]any)
				comparison["runs"].([]any)[0].(map[string]any)["fallback"] = true
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
		{
			name: "invalid generated at",
			mutate: func(document map[string]any) {
				document["generated_at"] = "2026-02-30T08:00:00Z"
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
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "performance-evidence-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	const resource = "urn:redevplugin:test:performance-evidence-v2"
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
		"schema_version":  "redevplugin.performance_evidence.v2",
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
		"comparisons": []any{
			map[string]any{
				"id":               "httpadapter.route-authorization-v051",
				"baseline_release": "0.5.1",
				"baseline_commit":  "3febcc59bbdb2118a4f105781b4c743bc11ba09f",
				"candidate_commit": "0123456789abcdef0123456789abcdef01234567",
				"runs": []any{
					validRouteAuthorizationRun("1", "2"),
					validRouteAuthorizationRun("3", "4"),
					validRouteAuthorizationRun("5", "6"),
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

func validRouteAuthorizationRun(baselineHashPrefix, candidateHashPrefix string) map[string]any {
	return map[string]any{
		"baseline_profile_sha256":  baselineHashPrefix + strings.Repeat("0", 63),
		"candidate_profile_sha256": candidateHashPrefix + strings.Repeat("0", 63),
		"baseline_profile":         validRouteAuthorizationProfile("v0.5.1", "3febcc59bbdb2118a4f105781b4c743bc11ba09f"),
		"candidate_profile":        validRouteAuthorizationProfile("v0.6.0", "0123456789abcdef0123456789abcdef01234567"),
	}
}

func validRouteAuthorizationProfile(variant, commit string) map[string]any {
	measurement := func(concurrency, batches, samples int) map[string]any {
		return map[string]any{
			"concurrency":             concurrency,
			"batch_count":             batches,
			"sample_count":            samples,
			"median_nanoseconds":      100,
			"p95_nanoseconds":         120,
			"p99_nanoseconds":         140,
			"allocations_per_request": 7.0,
			"bytes_per_request":       1024.0,
		}
	}
	return map[string]any{
		"schema_version": "redevplugin.route_authorization_performance.v1",
		"variant":        variant,
		"commit":         commit,
		"environment": map[string]any{
			"os":           "linux",
			"arch":         "amd64",
			"logical_cpus": 8,
			"gomaxprocs":   8,
			"go_version":   "go1.26.0",
		},
		"warmup_count":        8,
		"requests_per_sample": 32,
		"measurements": []any{
			measurement(1, 1000, 32000),
			measurement(100, 64, 204800),
			measurement(1000, 64, 2048000),
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
