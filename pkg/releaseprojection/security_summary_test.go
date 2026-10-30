package releaseprojection

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

func TestSecuritySummarySchemaMatchesGoEncodingOrder(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/contracts/security-summary-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schemas map[string]json.RawMessage
	if err = json.Unmarshal(raw, &schemas); err != nil {
		t.Fatal(err)
	}
	visited := map[reflect.Type]bool{}
	var check func(reflect.Type)
	check = func(typ reflect.Type) {
		if typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			check(typ.Elem())
			return
		}
		if typ.Kind() != reflect.Struct || visited[typ] {
			return
		}
		visited[typ] = true
		var schema struct {
			Properties json.RawMessage `json:"properties"`
			Required   []string        `json:"required"`
		}
		if err := json.Unmarshal(schemas[typ.Name()], &schema); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(strings.NewReader(string(schema.Properties)))
		if _, err := decoder.Token(); err != nil {
			t.Fatal(err)
		}
		names := []string{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, key.(string))
			var value json.RawMessage
			if err = decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
		}
		want := []string{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			want = append(want, tag[0])
			if slices.Contains(schema.Required, tag[0]) == slices.Contains(tag, "omitempty") {
				t.Errorf("%s.%s requiredness differs from Go encoding", typ.Name(), tag[0])
			}
			check(field.Type)
		}
		if !slices.Equal(names, want) {
			t.Errorf("%s field order %v, want Go encoding %v", typ.Name(), names, want)
		}
	}
	check(reflect.TypeOf(ExternalPackageSecuritySummary{}))
}

func TestSecuritySummarySharedCanonicalFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../spec/plugin/security-summary-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Valid []struct {
			Name      string                         `json:"name"`
			Summary   ExternalPackageSecuritySummary `json:"summary"`
			SHA256    string                         `json:"sha256"`
			Contracts string                         `json:"capability_contract_set_sha256"`
		} `json:"valid"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, item := range fixture.Valid {
		t.Run(item.Name, func(t *testing.T) {
			hash, err := SecuritySummarySHA256(item.Summary)
			if err != nil {
				t.Fatal(err)
			}
			if hash != item.SHA256 {
				t.Fatalf("summary digest %s, want %s", hash, item.SHA256)
			}
			contracts, err := CapabilityContractSetSHA256(item.Summary)
			if err != nil {
				t.Fatal(err)
			}
			if contracts != item.Contracts {
				t.Fatalf("contract digest %s, want %s", contracts, item.Contracts)
			}
		})
	}
}

func TestSecuritySummaryBindsOptionalExecutionDeclarations(t *testing.T) {
	base, err := BuildExternalPackageSecuritySummaryFromContracts(manifest.Manifest{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*ExternalPackageSecuritySummary)
	}{
		{"process", func(s *ExternalPackageSecuritySummary) {
			s.Process = &ExternalPackageProcessSummary{ResourceLimits: ExternalPackageProcessResourceLimits{OutputBufferBytes: 4096, MaxRuntimeMS: 1000}, MethodAccess: []ExternalPackageProcessMethodAccessSummary{}}
		}},
		{"background", func(s *ExternalPackageSecuritySummary) {
			s.Background = &ExternalPackageBackgroundSummary{Strategy: "on_demand", WorkerID: "worker"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.change(&changed)
			digest, err := SecuritySummarySHA256(changed)
			if err != nil {
				t.Fatal(err)
			}
			if digest == base.SummarySHA256 {
				t.Fatal("execution declaration was not bound to the summary hash")
			}
		})
	}
}

func TestSecuritySummaryUnusedResourcesKeepRequiredArrays(t *testing.T) {
	value := manifest.Manifest{
		NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{{ConnectorID: "api", Transport: "http", Scope: "environment", Destinations: []string{"https://example.com"}}}},
		Storage:       &manifest.StorageSpec{Stores: []manifest.StoreSpec{{StoreID: "data", Kind: "kv", Scope: "environment", QuotaBytes: 4096, SchemaVersion: 1}}},
	}
	summary, err := BuildExternalPackageSecuritySummaryFromContracts(value, nil)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Network[0].MethodAccess == nil || summary.Storage[0].MethodAccess == nil {
		t.Fatal("required resource access arrays must not encode as null")
	}
}
