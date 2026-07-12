#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
OUT_DIR="$ROOT_DIR/dist/redevplugin-release"
VERSION=""
RUNTIME_TARGET=""
NPM_PACKAGE=""
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

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/bin" "$OUT_DIR/contracts" "$OUT_DIR/docs/release" "$OUT_DIR/npm" "$OUT_DIR/notices"

go_version_pkg="github.com/floegence/redevplugin/pkg/version"
ldflags="-X ${go_version_pkg}.GoModuleVersion=${VERSION} -X ${go_version_pkg}.UIPackageVersion=${VERSION} -X ${go_version_pkg}.RuntimeVersion=${VERSION}"

(
  cd "$ROOT_DIR"
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
  cp "$ROOT_DIR/docs/release/a2-tdd-evidence.md" "$OUT_DIR/docs/release/a2-tdd-evidence.md"
  cp "$ROOT_DIR/Cargo.lock" "$OUT_DIR/notices/Cargo.lock"
  cp "$ROOT_DIR/go.sum" "$OUT_DIR/notices/go.sum"
  cp "$ROOT_DIR/package-lock.json" "$OUT_DIR/notices/package-lock.json"
)

node "$ROOT_DIR/scripts/generate_third_party_notices.mjs" "$ROOT_DIR" "$OUT_DIR/THIRD_PARTY_NOTICES.md"

node --input-type=module - "$OUT_DIR" "$VERSION" "$RUNTIME_TARGET" "$SOURCE_COMMIT" <<'NODE'
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const [outDir, version, runtimeTarget, sourceCommit] = process.argv.slice(2);
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
writeFileSync(
  join(outDir, "release-manifest.json"),
  JSON.stringify(
    {
      schema_version: "redevplugin.release_manifest.v2",
      version,
      source_commit: sourceCommit,
      runtime_target: runtimeTarget || null,
      generated_at: new Date().toISOString(),
      compatibility_sha256: compatibilitySHA256,
      npm_package: npmPackage,
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
