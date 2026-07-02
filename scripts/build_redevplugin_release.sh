#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
OUT_DIR="$ROOT_DIR/dist/redevplugin-release"
VERSION=""
RUNTIME_TARGET=""

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
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  VERSION="$(git -C "$ROOT_DIR" describe --tags --always --dirty)"
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
mkdir -p "$OUT_DIR/bin" "$OUT_DIR/contracts" "$OUT_DIR/npm" "$OUT_DIR/notices"

go_version_pkg="github.com/floegence/redevplugin/pkg/version"
ldflags="-X ${go_version_pkg}.GoModuleVersion=${VERSION} -X ${go_version_pkg}.UIPackageVersion=${VERSION} -X ${go_version_pkg}.RuntimeVersion=${VERSION}"

(
  cd "$ROOT_DIR"
  GOWORK=off go build -trimpath -ldflags "$ldflags" -o "$OUT_DIR/bin/redevplugin" ./cmd/redevplugin
  "$OUT_DIR/bin/redevplugin" version >"$OUT_DIR/compatibility.json"
  npm run build
  npm_pkg_dir="$OUT_DIR/.npm-pack/redevplugin-ui"
  mkdir -p "$npm_pkg_dir"
  cp "$ROOT_DIR/packages/redevplugin-ui/package.json" "$npm_pkg_dir/package.json"
  cp -R "$ROOT_DIR/packages/redevplugin-ui/dist" "$npm_pkg_dir/dist"
  node --input-type=module - "$npm_pkg_dir/package.json" "$VERSION" <<'NODE'
import { readFileSync, writeFileSync } from "node:fs";

const [filename, version] = process.argv.slice(2);
const pkg = JSON.parse(readFileSync(filename, "utf8"));
pkg.version = version;
writeFileSync(filename, JSON.stringify(pkg, null, 2) + "\n");
NODE
  (
    cd "$npm_pkg_dir"
    npm pack --pack-destination "$OUT_DIR/npm" >/dev/null
  )
  rm -rf "$OUT_DIR/.npm-pack"
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
  cp "$ROOT_DIR/AGENTS.md" "$OUT_DIR/AGENTS.md"
  cp "$ROOT_DIR/Cargo.lock" "$OUT_DIR/notices/Cargo.lock"
  cp "$ROOT_DIR/go.sum" "$OUT_DIR/notices/go.sum"
  cp "$ROOT_DIR/package-lock.json" "$OUT_DIR/notices/package-lock.json"
)

node "$ROOT_DIR/scripts/generate_third_party_notices.mjs" "$ROOT_DIR" "$OUT_DIR/THIRD_PARTY_NOTICES.md"

node --input-type=module - "$OUT_DIR" "$VERSION" "$RUNTIME_TARGET" <<'NODE'
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const [outDir, version, runtimeTarget] = process.argv.slice(2);
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
writeFileSync(
  join(outDir, "release-manifest.json"),
  JSON.stringify(
    {
      schema_version: "redevplugin.release_manifest.v1",
      version,
      runtime_target: runtimeTarget || null,
      generated_at: new Date().toISOString(),
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
