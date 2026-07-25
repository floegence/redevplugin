import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const script = readFileSync(new URL("./check_redevplugin_performance.sh", import.meta.url), "utf8");

test("non-Linux release performance runs the supported runtime in pinned Linux containers", () => {
  assert.match(script, /PINNED_GO_LINUX_IMAGE="docker\.io\/library\/golang@sha256:[0-9a-f]{64}"/);
  assert.match(script, /PINNED_RUST_LINUX_AMD64_IMAGE="docker\.io\/library\/rust@sha256:[0-9a-f]{64}"/);
  assert.match(script, /PINNED_RUST_LINUX_ARM64_IMAGE="docker\.io\/library\/rust@sha256:[0-9a-f]{64}"/);
  assert.match(script, /arm64\|aarch64\)[\s\S]*platform="linux\/arm64"/);
  assert.match(script, /x86_64\|amd64\)[\s\S]*platform="linux\/amd64"/);
  assert.match(script, /rust_toolchain="1\.88\.0-aarch64-unknown-linux-gnu"/);
  assert.match(script, /rust_toolchain="1\.88\.0-x86_64-unknown-linux-gnu"/);
  assert.match(script, /--env "RUSTUP_TOOLCHAIN=\$rust_toolchain"/);
  assert.match(script, /src=\$ROOT_DIR,dst=\/repo,readonly/);
  assert.match(script, /cargo build --locked --release -p redevplugin-runtime/);
  assert.match(script, /go test \.\/pkg\/host -run '\^TestPerformanceRuntime' -count=1/);
  assert.doesNotMatch(script, /--privileged/);
});

test("native Linux release performance keeps the direct runtime path", () => {
  assert.match(script, /if \[\[ "\$\(uname -s\)" == "Linux" \]\]; then[\s\S]*REDEVPLUGIN_PERFORMANCE_RUNTIME="\$runtime_path"/);
});
