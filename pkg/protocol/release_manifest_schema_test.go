package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const releaseManifestSchemaVersion = "redevplugin.release_manifest.v4"

func TestReleaseManifestDocumentationTracksV4Transition(t *testing.T) {
	root := repoRoot(t)
	readme := readTextFile(t, filepath.Join(root, "README.md"))
	if !strings.Contains(readme, "release manifest\n  v4") || strings.Contains(readme, "release manifest v3 remain unchanged") {
		t.Fatal("README current platform snapshot does not identify release manifest v4")
	}

	changelog := readTextFile(t, filepath.Join(root, "CHANGELOG.md"))
	v050 := changelogSection(t, changelog, "## v0.5.0", "## v0.4.3")
	if !strings.Contains(v050, "release manifest v4") || strings.Contains(v050, "release manifest v3 remain unchanged") {
		t.Fatal("v0.5.0 changelog section does not own the release manifest v4 transition")
	}
	v040 := changelogSection(t, changelog, "## v0.4.0", "## v0.3.2")
	if !strings.Contains(v040, "redevplugin.release_manifest.v3") || strings.Contains(v040, "redevplugin.release_manifest.v4") {
		t.Fatal("published v0.4.0 changelog history does not retain release manifest v3")
	}

	releaseGuide := readTextFile(t, filepath.Join(root, "docs", "release", "ci-and-release-gates.md"))
	if !strings.Contains(releaseGuide, "release manifest v4 Worker SDK identity") || strings.Contains(releaseGuide, "release manifest v3 Worker SDK identity") {
		t.Fatal("release gate documentation does not identify release manifest v4")
	}
}

func TestReleaseManifestSchemaMatchesBundleVerifierContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "release-manifest-v4.schema.json"))
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
	if id, ok := schema["$id"].(string); !ok || !strings.Contains(id, "release-manifest-v4") {
		t.Fatalf("release manifest $id = %#v, want release-manifest-v4", schema["$id"])
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
		"worker_sdk",
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
		"worker_sdk",
		"files",
	}, "release manifest properties")
	if got := requireNestedObject(t, props, "schema_version")["const"]; got != releaseManifestSchemaVersion {
		t.Fatalf("schema_version const = %#v, want %q", got, releaseManifestSchemaVersion)
	}
	if got := requireNestedObject(t, props, "version")["$ref"]; got != "#/$defs/semver" {
		t.Fatalf("version property = %#v, want strict semver ref", requireNestedObject(t, props, "version"))
	}
	assertLowerHexPattern(t, requireNestedObject(t, props, "source_commit"), "source_commit", 40)
	assertRuntimeTargetOneOf(t, requireNestedObject(t, props, "runtime_target"))
	generatedAt := requireNestedObject(t, props, "generated_at")
	if generatedAt["type"] != "string" || generatedAt["format"] != "date-time" {
		t.Fatalf("generated_at property = %#v, want string date-time", generatedAt)
	}
	assertLowerHexPattern(t, requireNestedObject(t, props, "compatibility_sha256"), "compatibility_sha256", 64)
	assertReleaseManifestNpmPackage(t, schema, requireNestedObject(t, props, "npm_package"))
	assertReleaseManifestWorkerSDK(t, schema, requireNestedObject(t, props, "worker_sdk"))
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
	assertWorkerSDKPackagerContract(t, filepath.Join(root, "scripts", "build_redevplugin_worker_sdk_package.mjs"))
	assertReleaseManifestVerifierContract(t, filepath.Join(root, "scripts", "verify_redevplugin_release_bundle.mjs"))
	assertReleaseWorkflowContract(t, filepath.Join(root, ".github", "workflows", "release.yml"))
}

func assertWorkerSDKPackagerContract(t *testing.T, path string) {
	t.Helper()
	source := readTextFile(t, path)
	for _, snippet := range []string{
		`["show", "active-toolchain"]`,
		`RUSTUP_TOOLCHAIN: activeToolchain`,
		`"check",`,
		`"--target",`,
		`"wasm32-unknown-unknown",`,
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("%s missing Worker SDK packager contract snippet %q", path, snippet)
		}
	}
}

func assertReleaseManifestWorkerSDK(t *testing.T, schema map[string]any, property map[string]any) {
	t.Helper()
	if property["$ref"] != "#/$defs/worker_sdk" {
		t.Fatalf("worker_sdk property = %#v, want #/$defs/worker_sdk", property)
	}
	workerSDK := requireNestedObject(t, schema, "$defs", "worker_sdk")
	if workerSDK["additionalProperties"] != false {
		t.Fatalf("worker_sdk additionalProperties = %#v, want false", workerSDK["additionalProperties"])
	}
	assertStringSet(t, requireStringSlice(t, workerSDK["required"], "worker_sdk required"), []string{
		"name",
		"version",
		"path",
		"sha256",
		"size",
	}, "worker_sdk required fields")
	props := requireNestedObject(t, workerSDK, "properties")
	if got := requireNestedObject(t, props, "name")["const"]; got != "redevplugin-worker-sdk" {
		t.Fatalf("worker_sdk name const = %#v", got)
	}
	if got := requireNestedObject(t, props, "version")["$ref"]; got != "#/$defs/semver" {
		t.Fatalf("worker_sdk version property = %#v, want strict semver ref", requireNestedObject(t, props, "version"))
	}
	if got := requireNestedObject(t, props, "path")["pattern"]; got != `^sdk/redevplugin-worker-sdk-[A-Za-z0-9._+-]+\.crate$` {
		t.Fatalf("worker_sdk path pattern = %#v", got)
	}
	assertLowerHexPattern(t, requireNestedObject(t, props, "sha256"), "worker_sdk sha256", 64)
	if got := requireNestedObject(t, props, "size")["minimum"]; got != float64(1) {
		t.Fatalf("worker_sdk size minimum = %#v, want 1", got)
	}
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
	if got := requireNestedObject(t, props, "version")["$ref"]; got != "#/$defs/semver" {
		t.Fatalf("npm_package version property = %#v, want strict semver ref", requireNestedObject(t, props, "version"))
	}
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
	var hasClosedEnum bool
	var hasNull bool
	for _, raw := range options {
		option, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("runtime_target option = %#v, want object", raw)
		}
		if option["type"] == "null" {
			hasNull = true
			continue
		}
		if option["type"] != "string" {
			t.Fatalf("runtime_target enum option = %#v, want string enum", option)
		}
		values := requireStringSlice(t, option["enum"], "runtime_target enum")
		assertStringSet(t, values, []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"}, "runtime_target enum")
		hasClosedEnum = true
	}
	if !hasClosedEnum || !hasNull {
		t.Fatalf("runtime_target oneOf missing closed enum/null: %#v", property["oneOf"])
	}
	for _, raw := range options {
		option := raw.(map[string]any)
		if option["type"] == "string" && option["minLength"] != nil {
			t.Fatalf("runtime_target retained open string schema: %#v", option)
		}
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
		`schema_version: "redevplugin.release_manifest.v4"`,
		`RUNTIME_PLATFORM_TARGET=$(node "$ROOT_DIR/scripts/runtime_targets.mjs" --platform-for-build "$RUNTIME_TARGET")`,
		`source_commit: sourceCommit`,
		`runtime_target: runtimeTarget || null`,
		`generated_at: generatedAt`,
		`compatibility_sha256: compatibilitySHA256`,
		`npm_package: npmPackage`,
		`worker_sdk: workerSDK`,
		`--worker-sdk-package`,
		`--performance-evidence`,
		`copy_redevplugin_performance_evidence.mjs`,
		`--skip-execution --allow-smoke`,
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
		`assertEqual(manifest.schema_version, "redevplugin.release_manifest.v4", "release manifest schema_version");`,
		`assertGitCommit(manifest.source_commit, "release manifest source_commit");`,
		`manifest.runtime_target !== null && typeof manifest.runtime_target !== "string"`,
		`assertRFC3339DateTime(manifest.generated_at, "release manifest generated_at");`,
		`assertHexSHA256(manifest.compatibility_sha256, "release manifest compatibility_sha256");`,
		`verifyNpmManifestEntry(manifest.npm_package, expectedVersion);`,
		`verifyWorkerSDKManifestEntry(manifest.worker_sdk, expectedVersion);`,
		`verifyWorkerSDKCrate(bundleDir, expectedVersion, manifest);`,
		`const rustToolchain = resolveRustToolchain();`,
		`RUSTUP_TOOLCHAIN: rustToolchain`,
		`!Array.isArray(manifest.files) || manifest.files.length === 0`,
		`assertExactKeys(file, ["path", "sha256", "size"], ` + "`release manifest files[${index}]`" + `);`,
		`assertBundlePath(file.path, ` + "`release manifest files[${index}].path`" + `);`,
		`assertHexSHA256(file.sha256, ` + "`release manifest files[${index}].sha256`" + `);`,
		`!Number.isSafeInteger(file.size) || file.size < 0`,
		`release manifest contains duplicate file path`,
		`assertDeepEqual(manifestFiles, actualFiles, "release manifest file list");`,
		"const expectedSums = manifestFiles.map((file) => `${file.sha256}  ${file.path}`).join(\"\\n\") + \"\\n\";",
		`assertEqual(actualSums, expectedSums, "SHA256SUMS content");`,
		`"contracts/spec/plugin/release-manifest-v4.schema.json"`,
		`"contracts/spec/plugin/opaque-surface-document-v3.schema.json"`,
		`"contracts/spec/plugin/opaque-surface-transport-v4.schema.json"`,
		`const skipExecution = args.includes("--skip-execution");`,
		`const allowSmoke = args.includes("--allow-smoke");`,
		`verifyExecutableTargets(bundleDir, manifest.runtime_target);`,
		`runtimeTargetForPlatform(runtimeTarget)`,
		`runtimeTargetPayload = runtimeTargetPayloadForPlatform(runtimeTarget);`,
		`target: runtimeTargetPayload,`,
		`host_process_id: process.pid,`,
		`host_ipc_version: "rust-ipc-v4",`,
		`host_wasm_abi: "redevplugin-wasm-worker-v2",`,
		`started_unix_nano: 1,`,
		`verifyCompatibility(bundleDir, expectedVersion, manifest, skipExecution);`,
		`verifyPerformanceEvidence(bundleDir, expectedVersion, manifest, allowSmoke);`,
		`verifyHostCapabilitySample(bundleDir, manifest, skipExecution);`,
		`headers: { "Content-Type": "application/json", Origin: origin },`,
		`assertEqual(sampleManifest.source_commit, releaseManifest.source_commit, "host capability sample source_commit");`,
		`assertEqual(sampleManifest.generated_at, releaseManifest.generated_at, "host capability sample generated_at");`,
		`"examples/host-capability/sample-documents-v1/plugin-consumer.ts"`,
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("%s missing release manifest verifier contract snippet %q", path, snippet)
		}
	}
	if strings.Contains(source, "manifestFiles.sort(") {
		t.Fatalf("%s normalizes unordered release manifest files instead of rejecting them", path)
	}
	if strings.Contains(source, "target: { os: process.platform") || strings.Contains(source, "arch: process.arch") {
		t.Fatalf("%s derives runtime IPC target from the verifier process", path)
	}
}

func assertReleaseWorkflowContract(t *testing.T, path string) {
	t.Helper()
	source := readTextFile(t, path)
	stressReleaseStart := strings.Index(source, "  stress-release:\n")
	packageUIStart := strings.Index(source, "  package-ui:\n")
	runtimeStart := strings.Index(source, "  runtime:\n")
	if stressReleaseStart < 0 || packageUIStart <= stressReleaseStart || runtimeStart <= packageUIStart {
		t.Fatalf("%s missing package-ui workflow job boundaries", path)
	}
	stressRelease := source[stressReleaseStart:packageUIStart]
	stressTarget := strings.Index(stressRelease, "rustup target add wasm32-unknown-unknown")
	stressCommand := strings.Index(stressRelease, "./scripts/check_redevplugin_stress.sh --release")
	if stressTarget < 0 || stressCommand < 0 || stressTarget >= stressCommand {
		t.Fatalf("%s stress-release job must install wasm32-unknown-unknown before running release stress", path)
	}
	packageUI := source[packageUIStart:runtimeStart]
	if !strings.Contains(packageUI, "rustup target add wasm32-unknown-unknown") {
		t.Fatalf("%s package-ui job must install wasm32-unknown-unknown before checking the Worker SDK crate", path)
	}
	verifyPublishedStart := strings.Index(source, "  verify-published-release:\n")
	if verifyPublishedStart < 0 {
		t.Fatalf("%s missing verify-published-release workflow job", path)
	}
	verifyPublished := source[verifyPublishedStart:]
	if !strings.Contains(verifyPublished, "rustup target add wasm32-unknown-unknown") {
		t.Fatalf("%s verify-published-release job must install wasm32-unknown-unknown before checking the Worker SDK crate", path)
	}
	for _, snippet := range []string{
		"contents: read",
		"cancel-in-progress: false",
		"startsWith(github.ref, 'refs/tags/v')",
		"./scripts/assert_github_release_absent.sh",
		"gh release create",
		"node scripts/verify_go_module_readback.mjs",
		"npm@11.18.0",
		`node scripts/check_redevplugin_release_metadata.mjs "$version"`,
		"Build immutable Rust worker SDK crate",
		"Immutable Release Performance Evidence",
		"runs-on: ubuntu-24.04",
		"redevplugin-performance-release",
		`--performance-evidence "$performance_evidence"`,
		"redevplugin-worker-sdk-package",
		`--worker-sdk-package "$worker_sdk_package"`,
		`if published_integrity=$(npm view "@floegence/redevplugin-ui@${version}" dist.integrity 2>/dev/null); then`,
		`id: published-release`,
		`--npm-integrity`,
		`echo "npm_integrity=$npm_integrity" >> "$GITHUB_OUTPUT"`,
		`steps.published-release.outputs.npm_integrity`,
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

func changelogSection(t *testing.T, changelog, startHeading, endHeading string) string {
	t.Helper()
	start := strings.Index(changelog, startHeading)
	end := strings.Index(changelog, endHeading)
	if start < 0 || end <= start {
		t.Fatalf("CHANGELOG.md section boundaries are invalid: %s to %s", startHeading, endHeading)
	}
	return changelog[start:end]
}
