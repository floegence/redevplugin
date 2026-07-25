import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const script = readFileSync(new URL("./check_redevplugin_stress.sh", import.meta.url), "utf8");

test("non-Linux stress evidence runs the Linux-only revoke contract in a pinned container", () => {
  assert.match(script, /PINNED_GO_LINUX_IMAGE="docker\.io\/library\/golang@sha256:[0-9a-f]{64}"/);
  assert.match(script, /arm64\|aarch64\)[\s\S]*platform="linux\/arm64"/);
  assert.match(script, /x86_64\|amd64\)[\s\S]*platform="linux\/amd64"/);
  assert.match(script, /src=\$ROOT_DIR,dst=\/repo,readonly/);
  assert.match(script, /--network none/);
  assert.match(script, /src=\$go_module_cache,dst=\/go\/pkg\/mod,readonly/);
  assert.match(script, /--env GOMODCACHE=\/go\/pkg\/mod/);
  assert.match(script, /REDEVPLUGIN_STRESS_EVIDENCE_PATH=\/evidence\/stress-evidence\.ndjson/);
  assert.match(script, /go test -count=1 -run '\^TestStressGateRuntimeRevokeACKP95\$' \.\/pkg\/stress/);
  assert.doesNotMatch(script, /--privileged/);
});

test("native Linux stress collection keeps the direct package test", () => {
  assert.match(script, /go test -count=1 \.\/pkg\/stress[\s\S]*if \[\[ "\$\(uname -s\)" == "Linux" \]\]; then/);
  assert.match(script, /run_step stress_evidence collect_stress_evidence/);
});
