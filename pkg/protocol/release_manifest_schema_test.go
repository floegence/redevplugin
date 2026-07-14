package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const releaseManifestSchemaVersion = "redevplugin.release_manifest.v2"

func TestReleaseManifestSchemaMatchesBundleVerifierContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "release-manifest-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	if schema["additionalProperties"] != false {
		t.Fatalf("release manifest schema additionalProperties = %#v, want false", schema["additionalProperties"])
	}
	if id, ok := schema["$id"].(string); !ok || !strings.Contains(id, "release-manifest-v2") {
		t.Fatalf("release manifest $id = %#v, want release-manifest-v2", schema["$id"])
	}
	required := requireStringSlice(t, schema["required"], "release manifest required")
	assertStringSet(t, required, []string{
		"schema_version",
		"version",
		"source_commit",
		"runtime_target",
		"generated_at",
		"compatibility_sha256",
		"npm_package",
		"files",
	}, "release manifest required fields")

	props := requireNestedObject(t, schema, "properties")
	assertStringSet(t, objectKeys(props), []string{
		"schema_version",
		"version",
		"source_commit",
		"runtime_target",
		"generated_at",
		"compatibility_sha256",
		"npm_package",
		"files",
	}, "release manifest properties")
	if got := requireNestedObject(t, props, "schema_version")["const"]; got != releaseManifestSchemaVersion {
		t.Fatalf("schema_version const = %#v, want %q", got, releaseManifestSchemaVersion)
	}
	assertStringMinLength(t, requireNestedObject(t, props, "version"), "version", 1)
	assertLowerHexPattern(t, requireNestedObject(t, props, "source_commit"), "source_commit", 40)
	assertRuntimeTargetOneOf(t, requireNestedObject(t, props, "runtime_target"))
	generatedAt := requireNestedObject(t, props, "generated_at")
	if generatedAt["type"] != "string" || generatedAt["format"] != "date-time" {
		t.Fatalf("generated_at property = %#v, want string date-time", generatedAt)
	}
	assertLowerHexPattern(t, requireNestedObject(t, props, "compatibility_sha256"), "compatibility_sha256", 64)
	assertReleaseManifestNpmPackage(t, schema, requireNestedObject(t, props, "npm_package"))
	files := requireNestedObject(t, props, "files")
	if files["type"] != "array" || files["minItems"] != float64(1) {
		t.Fatalf("files property = %#v, want array minItems 1", files)
	}
	if requireNestedObject(t, files, "items")["$ref"] != "#/$defs/file" {
		t.Fatalf("files item ref = %#v, want #/$defs/file", requireNestedObject(t, files, "items")["$ref"])
	}

	fileDef := requireNestedObject(t, schema, "$defs", "file")
	if fileDef["additionalProperties"] != false {
		t.Fatalf("release manifest file additionalProperties = %#v, want false", fileDef["additionalProperties"])
	}
	fileRequired := requireStringSlice(t, fileDef["required"], "release manifest file required")
	assertStringSet(t, fileRequired, []string{"path", "sha256", "size"}, "release manifest file required fields")
	fileProps := requireNestedObject(t, fileDef, "properties")
	assertStringSet(t, objectKeys(fileProps), []string{"path", "sha256", "size"}, "release manifest file properties")
	assertReleaseManifestPathSchema(t, requireNestedObject(t, fileProps, "path"))
	sha := requireNestedObject(t, fileProps, "sha256")
	if sha["type"] != "string" || sha["pattern"] != "^[0-9a-f]{64}$" {
		t.Fatalf("sha256 property = %#v, want lowercase hex sha256", sha)
	}
	size := requireNestedObject(t, fileProps, "size")
	if size["type"] != "integer" || size["minimum"] != float64(0) {
		t.Fatalf("size property = %#v, want integer minimum 0", size)
	}

	assertReleaseManifestBuildScriptContract(t, filepath.Join(root, "scripts", "build_redevplugin_release.sh"))
	assertReleaseManifestVerifierContract(t, filepath.Join(root, "scripts", "verify_redevplugin_release_bundle.mjs"))
	assertReleaseWorkflowContract(t, filepath.Join(root, ".github", "workflows", "release.yml"))
}

func assertLowerHexPattern(t *testing.T, property map[string]any, label string, width int) {
	t.Helper()
	want := "^[0-9a-f]{" + strconv.Itoa(width) + "}$"
	if property["type"] != "string" || property["pattern"] != want {
		t.Fatalf("%s property = %#v, want lowercase hex width %d", label, property, width)
	}
}

func assertReleaseManifestNpmPackage(t *testing.T, schema map[string]any, property map[string]any) {
	t.Helper()
	if property["$ref"] != "#/$defs/npm_package" {
		t.Fatalf("npm_package property = %#v, want #/$defs/npm_package", property)
	}
	npmPackage := requireNestedObject(t, schema, "$defs", "npm_package")
	if npmPackage["additionalProperties"] != false {
		t.Fatalf("npm_package additionalProperties = %#v, want false", npmPackage["additionalProperties"])
	}
	assertStringSet(t, requireStringSlice(t, npmPackage["required"], "npm_package required"), []string{
		"name",
		"version",
		"path",
		"sha256",
		"integrity",
		"size",
	}, "npm_package required fields")
	props := requireNestedObject(t, npmPackage, "properties")
	if got := requireNestedObject(t, props, "name")["const"]; got != "@floegence/redevplugin-ui" {
		t.Fatalf("npm_package name const = %#v", got)
	}
	assertStringMinLength(t, requireNestedObject(t, props, "version"), "npm_package version", 1)
	if got := requireNestedObject(t, props, "path")["pattern"]; got != `^npm/floegence-redevplugin-ui-[A-Za-z0-9._+-]+\.tgz$` {
		t.Fatalf("npm_package path pattern = %#v", got)
	}
	assertLowerHexPattern(t, requireNestedObject(t, props, "sha256"), "npm_package sha256", 64)
	if got := requireNestedObject(t, props, "integrity")["pattern"]; got != `^sha512-[A-Za-z0-9+/]+={0,2}$` {
		t.Fatalf("npm_package integrity pattern = %#v", got)
	}
	if got := requireNestedObject(t, props, "size")["minimum"]; got != float64(1) {
		t.Fatalf("npm_package size minimum = %#v, want 1", got)
	}
}

func assertStringMinLength(t *testing.T, property map[string]any, label string, minLength float64) {
	t.Helper()
	if property["type"] != "string" || property["minLength"] != minLength {
		t.Fatalf("%s property = %#v, want string minLength %.0f", label, property, minLength)
	}
}

func assertRuntimeTargetOneOf(t *testing.T, property map[string]any) {
	t.Helper()
	options, ok := property["oneOf"].([]any)
	if !ok || len(options) != 2 {
		t.Fatalf("runtime_target oneOf = %#v, want string|null", property["oneOf"])
	}
	var hasString bool
	var hasNull bool
	for _, raw := range options {
		option, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("runtime_target option = %#v, want object", raw)
		}
		switch option["type"] {
		case "string":
			if option["minLength"] != float64(1) {
				t.Fatalf("runtime_target string option = %#v, want minLength 1", option)
			}
			hasString = true
		case "null":
			hasNull = true
		default:
			t.Fatalf("runtime_target option = %#v, want string|null", option)
		}
	}
	if !hasString || !hasNull {
		t.Fatalf("runtime_target oneOf missing string/null: %#v", property["oneOf"])
	}
}

func assertReleaseManifestPathSchema(t *testing.T, property map[string]any) {
	t.Helper()
	assertStringMinLength(t, property, "path", 1)
	if property["pattern"] != "^[A-Za-z0-9._/@+-]+$" {
		t.Fatalf("path pattern = %#v, want safe bundle path character class", property["pattern"])
	}
	forbidden := requireNestedObject(t, property, "not")
	anyOf, ok := forbidden["anyOf"].([]any)
	if !ok || len(anyOf) != 3 {
		t.Fatalf("path not.anyOf = %#v, want absolute, parent traversal, backslash guards", forbidden["anyOf"])
	}
	requiredPatterns := []string{"^/", "(^|/)\\.\\.(/|$)", "\\\\"}
	for _, want := range requiredPatterns {
		var found bool
		for _, raw := range anyOf {
			option, ok := raw.(map[string]any)
			if !ok {
				t.Fatalf("path not.anyOf option = %#v, want object", raw)
			}
			if option["pattern"] == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("path not.anyOf missing pattern %q in %#v", want, anyOf)
		}
	}
}

func assertReleaseManifestBuildScriptContract(t *testing.T, path string) {
	t.Helper()
	source := readTextFile(t, path)
	for _, snippet := range []string{
		`rel === "release-manifest.json" || rel === "SHA256SUMS"`,
		`files.sort((a, b) => a.path.localeCompare(b.path))`,
		`schema_version: "redevplugin.release_manifest.v2"`,
		`source_commit: sourceCommit`,
		`runtime_target: runtimeTarget || null`,
		`generated_at: generatedAt`,
		`compatibility_sha256: compatibilitySHA256`,
		`npm_package: npmPackage`,
		`"$OUT_DIR/bin/redevplugin" host-capability build "$sample_config" "$sample_root"`,
		`source_commit: sourceCommit`,
		"const sums = files.map((file) => `${file.sha256}  ${file.path}`).join(\"\\n\") + \"\\n\";",
		`node "$ROOT_DIR/scripts/verify_redevplugin_release_bundle.mjs" "$OUT_DIR" "$VERSION"`,
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("%s missing release manifest build contract snippet %q", path, snippet)
		}
	}
}

func assertReleaseManifestVerifierContract(t *testing.T, path string) {
	t.Helper()
	source := readTextFile(t, path)
	for _, snippet := range []string{
		`const releaseManifestPath = join(bundleDir, "release-manifest.json");`,
		`const sha256SumsPath = join(bundleDir, "SHA256SUMS");`,
		`verifyReleaseManifestShape(manifest, expectedVersion);`,
		`verifyManifestFiles(bundleDir, manifest);`,
		`assertEqual(manifest.schema_version, "redevplugin.release_manifest.v2", "release manifest schema_version");`,
		`assertGitCommit(manifest.source_commit, "release manifest source_commit");`,
		`manifest.runtime_target !== null && typeof manifest.runtime_target !== "string"`,
		`!Number.isFinite(Date.parse(manifest.generated_at))`,
		`assertHexSHA256(manifest.compatibility_sha256, "release manifest compatibility_sha256");`,
		`verifyNpmManifestEntry(manifest.npm_package, expectedVersion);`,
		`!Array.isArray(manifest.files) || manifest.files.length === 0`,
		`assertBundlePath(file.path, ` + "`release manifest files[${index}].path`" + `);`,
		`assertHexSHA256(file.sha256, ` + "`release manifest files[${index}].sha256`" + `);`,
		`!Number.isSafeInteger(file.size) || file.size < 0`,
		`release manifest contains duplicate file path`,
		`assertDeepEqual(manifestFiles, actualFiles, "release manifest file list");`,
		"const expectedSums = manifestFiles.map((file) => `${file.sha256}  ${file.path}`).join(\"\\n\") + \"\\n\";",
		`assertEqual(actualSums, expectedSums, "SHA256SUMS content");`,
		`"contracts/spec/plugin/release-manifest-v2.schema.json"`,
		`"contracts/spec/plugin/opaque-surface-document-v1.schema.json"`,
		`"contracts/spec/plugin/opaque-surface-transport-v1.schema.json"`,
		`const structuralOnly = args.includes("--structural-only");`,
		`verifyExecutableTargets(bundleDir, manifest.runtime_target);`,
		`verifyCompatibility(bundleDir, expectedVersion, manifest, structuralOnly);`,
		`verifyHostCapabilitySample(bundleDir, manifest, structuralOnly);`,
		`assertEqual(sampleManifest.source_commit, releaseManifest.source_commit, "host capability sample source_commit");`,
		`assertEqual(sampleManifest.generated_at, releaseManifest.generated_at, "host capability sample generated_at");`,
		`"examples/host-capability/sample-documents-v1/plugin-consumer.ts"`,
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("%s missing release manifest verifier contract snippet %q", path, snippet)
		}
	}
}

func assertReleaseWorkflowContract(t *testing.T, path string) {
	t.Helper()
	source := readTextFile(t, path)
	for _, snippet := range []string{
		"contents: read",
		"cancel-in-progress: false",
		"startsWith(github.ref, 'refs/tags/v')",
		"./scripts/assert_github_release_absent.sh",
		"gh release create",
		"node scripts/verify_go_module_readback.mjs",
		"npm@11.18.0",
		`if published_integrity=$(npm view "@floegence/redevplugin-ui@${version}" dist.integrity 2>/dev/null); then`,
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("%s missing hardened release workflow snippet %q", path, snippet)
		}
	}
	for _, forbidden := range []string{
		"softprops/action-gh-release",
		"if: startsWith(github.ref, 'refs/tags/')",
		"govulncheck@latest",
		"cargo install cargo-deny --locked",
		`dist.integrity --json 2>/dev/null | tr -d '"' || true`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("%s retains mutable or overbroad release workflow snippet %q", path, forbidden)
		}
	}
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- uses: ") {
			continue
		}
		uses := strings.TrimPrefix(trimmed, "- uses: ")
		uses = strings.Fields(uses)[0]
		at := strings.LastIndex(uses, "@")
		if at < 0 || len(uses)-at-1 != 40 {
			t.Fatalf("release workflow action must be pinned to a full commit: %q", uses)
		}
	}
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
