#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
OUT_DIR="$ROOT_DIR/dist/redevplugin-release"
VERSION=""
RUNTIME_TARGET=""
NPM_PACKAGE=""
WORKER_SDK_PACKAGE=""
SOURCE_COMMIT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --runtime-target)
      RUNTIME_TARGET="$2"
      shift 2
      ;;
    --npm-package)
      NPM_PACKAGE="$2"
      shift 2
      ;;
    --worker-sdk-package)
      WORKER_SDK_PACKAGE="$2"
      shift 2
      ;;
    --source-commit)
      SOURCE_COMMIT="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  VERSION="$(git -C "$ROOT_DIR" describe --tags --always --dirty)"
fi
if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "release version must be semantic version text without a v prefix: $VERSION" >&2
  exit 1
fi
if [[ "$OUT_DIR" != /* ]]; then
  OUT_DIR="$ROOT_DIR/$OUT_DIR"
fi
if [[ -z "$SOURCE_COMMIT" ]]; then
  SOURCE_COMMIT=$(git -C "$ROOT_DIR" rev-parse HEAD)
fi
if [[ ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "source commit must be a full lowercase Git commit: $SOURCE_COMMIT" >&2
  exit 1
fi
if [[ -n "$NPM_PACKAGE" && "$NPM_PACKAGE" != /* ]]; then
  NPM_PACKAGE="$ROOT_DIR/$NPM_PACKAGE"
fi
if [[ -n "$WORKER_SDK_PACKAGE" && "$WORKER_SDK_PACKAGE" != /* ]]; then
  WORKER_SDK_PACKAGE="$ROOT_DIR/$WORKER_SDK_PACKAGE"
fi

if [[ -n "${HOME:-}" && -x "$HOME/.cargo/bin/cargo" ]]; then
  PATH="$HOME/.cargo/bin:$PATH"
fi

if ! command -v go >/dev/null 2>&1; then
  echo "go is required to build the ReDevPlugin release bundle" >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required to build redevplugin-runtime" >&2
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to build @floegence/redevplugin-ui" >&2
  exit 1
fi

GENERATED_AT=$(node --input-type=module -e 'process.stdout.write(new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace(".000Z", "Z"))')

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/bin" "$OUT_DIR/contracts" "$OUT_DIR/docs/release" "$OUT_DIR/examples/host-capability" "$OUT_DIR/npm" "$OUT_DIR/notices" "$OUT_DIR/sdk"

go_version_pkg="github.com/floegence/redevplugin/pkg/version"
ldflags="-X ${go_version_pkg}.GoModuleVersion=${VERSION} -X ${go_version_pkg}.UIPackageVersion=${VERSION} -X ${go_version_pkg}.RuntimeVersion=${VERSION}"

(
  cd "$ROOT_DIR"
  rustup target add wasm32-unknown-unknown >/dev/null
  npm run examples:check
  npm run scaffold:check
  GOWORK=off go build -trimpath -ldflags "$ldflags" -o "$OUT_DIR/bin/redevplugin" ./cmd/redevplugin
  "$OUT_DIR/bin/redevplugin" version >"$OUT_DIR/compatibility.json"
  if [[ -n "$NPM_PACKAGE" ]]; then
    if [[ ! -f "$NPM_PACKAGE" ]]; then
      echo "prebuilt npm package not found: $NPM_PACKAGE" >&2
      exit 1
    fi
    cp "$NPM_PACKAGE" "$OUT_DIR/npm/$(basename "$NPM_PACKAGE")"
  else
    npm run build
    node "$ROOT_DIR/scripts/build_redevplugin_ui_package.mjs" "$VERSION" "$OUT_DIR/npm" >/dev/null
  fi
  if [[ -n "$WORKER_SDK_PACKAGE" ]]; then
    if [[ ! -f "$WORKER_SDK_PACKAGE" ]]; then
      echo "prebuilt worker SDK package not found: $WORKER_SDK_PACKAGE" >&2
      exit 1
    fi
    if [[ "$(basename "$WORKER_SDK_PACKAGE")" != "redevplugin-worker-sdk-${VERSION}.crate" ]]; then
      echo "prebuilt worker SDK package filename does not match release version: $WORKER_SDK_PACKAGE" >&2
      exit 1
    fi
    cp "$WORKER_SDK_PACKAGE" "$OUT_DIR/sdk/$(basename "$WORKER_SDK_PACKAGE")"
  else
    node "$ROOT_DIR/scripts/build_redevplugin_worker_sdk_package.mjs" "$VERSION" "$OUT_DIR/sdk" >/dev/null
  fi
  if [[ -n "$RUNTIME_TARGET" ]]; then
    rustup target add "$RUNTIME_TARGET" >/dev/null
    REDEVPLUGIN_RUNTIME_VERSION="$VERSION" cargo build --release -p redevplugin-runtime --target "$RUNTIME_TARGET"
    runtime_path="$ROOT_DIR/target/$RUNTIME_TARGET/release/redevplugin-runtime"
  else
    REDEVPLUGIN_RUNTIME_VERSION="$VERSION" cargo build --release -p redevplugin-runtime
    runtime_path="$ROOT_DIR/target/release/redevplugin-runtime"
  fi
  if [[ ! -x "$runtime_path" ]]; then
    echo "redevplugin-runtime was not built at $runtime_path" >&2
    exit 1
  fi
  cp "$runtime_path" "$OUT_DIR/bin/redevplugin-runtime"
  cp -R "$ROOT_DIR/spec" "$OUT_DIR/contracts/spec"
  cp "$ROOT_DIR/README.md" "$OUT_DIR/README.md"
  cp "$ROOT_DIR/LICENSE" "$OUT_DIR/LICENSE"
  cp "$ROOT_DIR/CHANGELOG.md" "$OUT_DIR/CHANGELOG.md"
  cp "$ROOT_DIR/AGENTS.md" "$OUT_DIR/AGENTS.md"
  cp "$ROOT_DIR/docs/release/a3-tdd-evidence.md" "$OUT_DIR/docs/release/a3-tdd-evidence.md"
  cp -R "$ROOT_DIR/examples/showcase" "$OUT_DIR/examples/showcase"
  cp -R "$ROOT_DIR/examples/plugins" "$OUT_DIR/examples/plugins"
  sample_root="$OUT_DIR/examples/host-capability/sample-documents-v1"
  sample_config="$OUT_DIR/examples/host-capability/sample-documents-v1.build.json"
  node --input-type=module - \
    "$sample_config" \
    "$ROOT_DIR/examples/host-capability/documents.contract.json" \
    "$ROOT_DIR/testdata/host-capability/release-sample/example-documents.test-only.private.json" \
    "$ROOT_DIR/examples/host-capability/documents.notices.json" \
    "$GENERATED_AT" \
    "$SOURCE_COMMIT" \
    "$VERSION" <<'NODE'
import { writeFileSync } from "node:fs";

const [output, contractFile, privateKeyFile, noticesFile, generatedAt, sourceCommit, version] = process.argv.slice(2);
writeFileSync(output, JSON.stringify({
  contract_file: contractFile,
  private_key_file: privateKeyFile,
  artifact_base_ref: "capabilities/example.documents/v1.0.0",
  generated_at: generatedAt,
  source_commit: sourceCommit,
  min_redevplugin_version: version,
  signature_policy_epoch: "7",
  signature_revocation_epoch: "11",
  notices_file: noticesFile,
}, null, 2) + "\n");
NODE
  "$OUT_DIR/bin/redevplugin" host-capability build "$sample_config" "$sample_root" >/dev/null
  rm -f "$sample_config"
  cp "$ROOT_DIR/testdata/host-capability/release-sample/example-documents.test-only.public.json" "$sample_root/example-documents.public.json"
  cp "$ROOT_DIR/testdata/host-capability/sample-documents-v1/plugin-consumer.ts" "$sample_root/plugin-consumer.ts"
  cp "$ROOT_DIR/Cargo.lock" "$OUT_DIR/notices/Cargo.lock"
  cp "$ROOT_DIR/go.sum" "$OUT_DIR/notices/go.sum"
  cp "$ROOT_DIR/package-lock.json" "$OUT_DIR/notices/package-lock.json"
)

node "$ROOT_DIR/scripts/generate_third_party_notices.mjs" "$ROOT_DIR" "$OUT_DIR/THIRD_PARTY_NOTICES.md"

node --input-type=module - "$OUT_DIR" "$VERSION" "$RUNTIME_TARGET" "$SOURCE_COMMIT" "$GENERATED_AT" <<'NODE'
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const [outDir, version, runtimeTarget, sourceCommit, generatedAt] = process.argv.slice(2);
const files = [];
function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      walk(path);
      continue;
    }
    const rel = relative(outDir, path).replaceAll("\\", "/");
    if (rel === "release-manifest.json" || rel === "SHA256SUMS") {
      continue;
    }
    const sha256 = createHash("sha256").update(readFileSync(path)).digest("hex");
    files.push({ path: rel, sha256, size: stat.size });
  }
}
walk(outDir);
files.sort((a, b) => a.path.localeCompare(b.path));
const compatibilitySHA256 = createHash("sha256")
  .update(readFileSync(join(outDir, "compatibility.json")))
  .digest("hex");
const npmFiles = files.filter((file) => file.path.startsWith("npm/") && file.path.endsWith(".tgz"));
if (npmFiles.length !== 1) {
  throw new Error(`release bundle must contain exactly one npm tarball, found ${npmFiles.length}`);
}
const npmFile = npmFiles[0];
const npmBytes = readFileSync(join(outDir, npmFile.path));
const npmPackage = {
  name: "@floegence/redevplugin-ui",
  version,
  path: npmFile.path,
  sha256: npmFile.sha256,
  integrity: `sha512-${createHash("sha512").update(npmBytes).digest("base64")}`,
  size: npmFile.size,
};
const workerSDKFiles = files.filter((file) => file.path.startsWith("sdk/") && file.path.endsWith(".crate"));
if (workerSDKFiles.length !== 1) {
  throw new Error(`release bundle must contain exactly one worker SDK crate, found ${workerSDKFiles.length}`);
}
const workerSDKFile = workerSDKFiles[0];
const workerSDK = {
  name: "redevplugin-worker-sdk",
  version,
  path: workerSDKFile.path,
  sha256: workerSDKFile.sha256,
  size: workerSDKFile.size,
};
writeFileSync(
  join(outDir, "release-manifest.json"),
  JSON.stringify(
    {
      schema_version: "redevplugin.release_manifest.v3",
      version,
      source_commit: sourceCommit,
      runtime_target: runtimeTarget || null,
      generated_at: generatedAt,
      compatibility_sha256: compatibilitySHA256,
      npm_package: npmPackage,
      worker_sdk: workerSDK,
      files,
    },
    null,
    2,
  ) + "\n",
);
const sums = files.map((file) => `${file.sha256}  ${file.path}`).join("\n") + "\n";
writeFileSync(join(outDir, "SHA256SUMS"), sums);
NODE

node "$ROOT_DIR/scripts/verify_redevplugin_release_bundle.mjs" "$OUT_DIR" "$VERSION"

echo "redevplugin release bundle created at $OUT_DIR"
