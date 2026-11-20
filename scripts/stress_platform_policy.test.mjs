import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const script = readFileSync(new URL("./check_redevplugin_stress.sh", import.meta.url), "utf8");

test("core race partitions cover every package and propagate each failure", () => {
  const capacity = "TestHostOwnedSessionFinalizationReusesFenceCapacity";
  const pattern = `^${capacity}$`;
  const partitions = [
    `test -list ${pattern} ./pkg/host`,
    `test -p=1 -race -run ${pattern} ./pkg/host`,
    `test -p=1 -race -skip ${pattern} ./pkg/host`,
    "test -p=1 -race ./pkg/bridge ./pkg/connectivity ./pkg/httpadapter ./pkg/registry ./internal/runtimeclient ./pkg/storage ./pkg/stress",
  ];
  const body = script.match(/^run_core_race_tests\(\) \{[^]*?^\}/m)?.[0];
  assert.ok(body);
  assert.match(script, /run_step go_race_core run_core_race_tests \|\|/);
  for (const failure of ["", "absent", ...partitions]) {
    const probe = spawnSync("bash", ["-c", `set -uo pipefail
      go() {
        test "$GOWORK" = off || return 2
        printf '%s\\n' "$*" >&2
        test "$*" != "$PARTITION_FAILURE" || return 3
        if [[ "$2" == -list && "$PARTITION_FAILURE" != absent ]]; then printf '%s\\n' '${capacity}'; fi
      }
      ${body}
      run_core_race_tests`], {
      encoding: "utf8", env: { ...process.env, PARTITION_FAILURE: failure, GOWORK: "unexpected" },
    });
    assert.equal(probe.error, undefined);
    assert.equal(probe.status, failure === "" ? 0 : failure === "absent" || failure === partitions[0] ? 1 : 3);
    const count = failure === "" ? partitions.length : failure === "absent" ? 1 : partitions.indexOf(failure) + 1;
    assert.deepEqual(probe.stderr.trim().split("\n"), partitions.slice(0, count));
  }
});

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
