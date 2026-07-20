package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestPlatformPackageSchemasValidateClosedGeneratedContracts(t *testing.T) {
	registrySchema := compilePlatformPackageSchema(t, "contract-registry-v2.schema.json")
	packageSetSchema := compilePlatformPackageSchema(t, "platform-package-set-v1.schema.json")
	publicationSchema := compilePlatformPackageSchema(t, "platform-package-publication-v1.schema.json")

	registry := readPlatformPackageJSON(t, "contract-registry-v2.json")
	packageSet := readPlatformPackageJSON(t, "platform-package-set-v1.json")
	publication := validPlatformPackagePublication(t, packageSet)

	for name, testCase := range map[string]struct {
		schema *jsonschema.Schema
		value  any
	}{
		"registry":    {schema: registrySchema, value: registry},
		"package set": {schema: packageSetSchema, value: packageSet},
		"publication": {schema: publicationSchema, value: publication},
	} {
		t.Run(name, func(t *testing.T) {
			if err := testCase.schema.Validate(testCase.value); err != nil {
				t.Fatalf("valid contract rejected: %v", err)
			}
		})
	}
}

func TestPlatformPackageSchemasRejectOpenOrAmbiguousCoordinates(t *testing.T) {
	registrySchema := compilePlatformPackageSchema(t, "contract-registry-v2.schema.json")
	packageSetSchema := compilePlatformPackageSchema(t, "platform-package-set-v1.schema.json")
	publicationSchema := compilePlatformPackageSchema(t, "platform-package-publication-v1.schema.json")

	registry := readPlatformPackageJSON(t, "contract-registry-v2.json")
	packageSet := readPlatformPackageJSON(t, "platform-package-set-v1.json")
	publication := validPlatformPackagePublication(t, packageSet)

	tests := map[string]struct {
		schema *jsonschema.Schema
		value  map[string]any
	}{
		"registry traversal": {
			schema: registrySchema,
			value: mutatePlatformPackageValue(t, registry, func(value map[string]any) {
				value["artifacts"].([]any)[0].(map[string]any)["path"] = "spec/plugin/../../etc/passwd"
			}),
		},
		"registry nested unknown": {
			schema: registrySchema,
			value: mutatePlatformPackageValue(t, registry, func(value map[string]any) {
				value["artifacts"].([]any)[0].(map[string]any)["runtime_binary"] = "forbidden"
			}),
		},
		"registry reserved self id": {
			schema: registrySchema,
			value: mutatePlatformPackageValue(t, registry, func(value map[string]any) {
				value["artifacts"].([]any)[0].(map[string]any)["id"] = "contract-registry"
			}),
		},
		"registry self path": {
			schema: registrySchema,
			value: mutatePlatformPackageValue(t, registry, func(value map[string]any) {
				value["artifacts"].([]any)[0].(map[string]any)["path"] = "spec/plugin/contract-registry-v2.json"
			}),
		},
		"registry package set instance path": {
			schema: registrySchema,
			value: mutatePlatformPackageValue(t, registry, func(value map[string]any) {
				value["artifacts"].([]any)[0].(map[string]any)["path"] = "spec/plugin/platform-package-set-v1.json"
			}),
		},
		"package set duplicate npm": {
			schema: packageSetSchema,
			value: mutatePlatformPackageValue(t, packageSet, func(value map[string]any) {
				packages := value["npm_packages"].([]any)
				packages[1] = packages[0]
			}),
		},
		"package set role mismatch": {
			schema: packageSetSchema,
			value: mutatePlatformPackageValue(t, packageSet, func(value map[string]any) {
				value["rust_crates"].([]any)[0].(map[string]any)["role"] = "runtime"
			}),
		},
		"package set nested OS artifact": {
			schema: packageSetSchema,
			value: mutatePlatformPackageValue(t, packageSet, func(value map[string]any) {
				value["rust_crates"].([]any)[0].(map[string]any)["runtime_archive"] = "forbidden"
			}),
		},
		"publication duplicate crate": {
			schema: publicationSchema,
			value: mutatePlatformPackageValue(t, publication, func(value map[string]any) {
				crates := value["rust_crates"].([]any)
				crates[1] = crates[0]
			}),
		},
		"publication wrong workflow": {
			schema: publicationSchema,
			value: mutatePlatformPackageValue(t, publication, func(value map[string]any) {
				value["workflow"].(map[string]any)["path"] = ".github/workflows/other.yml"
			}),
		},
		"publication nested OS artifact": {
			schema: publicationSchema,
			value: mutatePlatformPackageValue(t, publication, func(value map[string]any) {
				value["npm_packages"].([]any)[0].(map[string]any)["product_signature"] = "forbidden"
			}),
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			if err := testCase.schema.Validate(testCase.value); err == nil {
				t.Fatal("invalid contract accepted")
			}
		})
	}
}

func compilePlatformPackageSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", name))
	if err != nil {
		t.Fatal(err)
	}
	resource := "urn:redevplugin:test:" + name
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource(resource, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func readPlatformPackageJSON(t *testing.T, name string) map[string]any {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", name))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func validPlatformPackagePublication(t *testing.T, packageSet map[string]any) map[string]any {
	t.Helper()
	version := packageSet["platform_version"].(string)
	commit := "1111111111111111111111111111111111111111"
	npmPackages := make([]any, 0, 2)
	for index, raw := range packageSet["npm_packages"].([]any) {
		coordinate := raw.(map[string]any)
		digest := bytes.Repeat([]byte{byte(index + 1)}, 64)
		npmPackages = append(npmPackages, map[string]any{
			"name":                      coordinate["name"],
			"version":                   version,
			"integrity":                 "sha512-" + base64.StdEncoding.EncodeToString(digest),
			"provenance_subject_sha512": hex.EncodeToString(digest),
		})
	}
	rustCrates := make([]any, 0, 6)
	for index, raw := range packageSet["rust_crates"].([]any) {
		coordinate := raw.(map[string]any)
		rustCrates = append(rustCrates, map[string]any{
			"name":                     coordinate["name"],
			"version":                  version,
			"registry_checksum_sha256": fmt.Sprintf("%064x", index+1),
		})
	}
	return map[string]any{
		"schema_version":   "redevplugin.platform_package_publication.v1",
		"platform_version": version,
		"source_commit":    commit,
		"workflow": map[string]any{
			"repository": "floegence/redevplugin",
			"path":       ".github/workflows/release.yml",
			"ref":        "refs/tags/v" + version,
			"sha":        commit,
		},
		"go_module": map[string]any{
			"module":    "github.com/floegence/redevplugin",
			"version":   "v" + version,
			"h1":        "h1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
			"go_mod_h1": "h1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)),
		},
		"npm_packages":        npmPackages,
		"rust_crates":         rustCrates,
		"contract_set_sha256": packageSet["contract_set_sha256"],
	}
}

func mutatePlatformPackageValue(t *testing.T, source map[string]any, mutate func(map[string]any)) map[string]any {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	return value
}
