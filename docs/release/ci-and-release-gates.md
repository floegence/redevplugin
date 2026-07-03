# CI And Release Gates

ReDevPlugin release artifacts are the only supported integration surface for
host products. A host product should consume a matching published Go module,
npm package, Rust runtime bundle, compatibility manifest, contract hashes, and
release evidence set.

## Local And CI Gates

Go checks that can be affected by a workspace must run with `GOWORK=off`.

Core local checks:

```bash
GOWORK=off go test ./...
GOWORK=off golangci-lint run ./...
npm ci
npm run check
npx playwright install chromium
./scripts/check_redevplugin_runtime_contract.sh --ci
./scripts/check_redevplugin_platform.sh --ci
REDEVPLUGIN_INSTALL_AUDIT_TOOLS=1 ./scripts/check_redevplugin_release_audit.sh
./scripts/check_redevplugin_stress.sh --fast --summary dist/redevplugin-stress-fast.json
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`check_redevplugin_platform.sh` and
`check_redevplugin_runtime_contract.sh` explicitly accept `--ci`, support
`--help`, reject unknown arguments, and export `GOWORK=off` internally. The
`--ci` flag is an explicit no-op so documentation, local runs, and CI can share
the same command shape.

## Contract Gates

`scripts/check_redevplugin_runtime_contract.sh --ci` validates:

- OpenAPI/HTTP route/TypeScript SDK binding coverage;
- compatibility manifest schema and emitted compatibility manifest shape;
- manifest, package signature, token/ticket, bridge, error-code, release
  manifest, IPC, WASM ABI, worker invocation, network grant, and target
  classifier contract snippets;
- executable Go/Rust runtime IPC golden fixtures for handshake/version
  mismatch, replay, unknown-frame, missing-field, and runtime-generation
  mismatch cases;
- release artifact verifier fixture behavior, including rejection of an
  unchecked extra tarball;
- Rust IPC, runtime, target classifier, and WASM ABI tests when Cargo is
  available.

`scripts/check_redevplugin_platform.sh --ci` validates:

- Go package tests;
- CLI validate/package/sign/install/dev lifecycle smoke paths;
- compatibility manifest verification;
- bridge SDK checks;
- TypeScript typecheck;
- browser demo tests;
- real runtime browser smoke through the Go Host library, HTTP adapter, Rust
  runtime, WASM worker, storage broker, and network broker.

## Stress Gates

`scripts/check_redevplugin_stress.sh` supports `--fast`, `--full`, `--release`,
and `--summary PATH`.

- `--fast` runs race-sensitive Go packages and `pkg/stress`.
- `--full` adds browser demo, runtime contract, and release bundle smoke.
- `--release` aliases full mode for release-blocking use.

The script always emits a JSON summary. `stress_evidence` contains structured
counters for stream backpressure, stream close/cancel fail-closed checks,
operation cancel dispatch success/failure persistence, connectivity
classifier/grant denials, runtime revoke ACK p95 latency, KV and SQLite storage
quota pressure, SQLite sidecar/sparse bypass checks, and CSP report flood rate
limiting. CI uploads summaries as artifacts, and tagged release workflows
include release-mode stress evidence in the published checksum and signature
evidence chain.

## Release Bundle

`scripts/build_redevplugin_release.sh` creates a release bundle containing:

- `bin/redevplugin`;
- `bin/redevplugin-runtime`;
- `compatibility.json`;
- contract artifacts under `contracts/`;
- npm package tarball under `npm/`;
- `release-manifest.json`;
- `SHA256SUMS`;
- generated third-party notices and lockfile evidence.

The build stamps one release version into the Go compatibility matrix, npm
package, and Rust runtime hello handshake. The bundle verifier checks
compatibility, release manifest hashes, `SHA256SUMS`, runtime hello, npm package
version, required contract files, and generated license evidence.

## Release Manifest And Compatibility

`release-manifest-v1.schema.json` is the machine contract for release bundle
file lists and checksums. Release manifests exclude themselves and
`SHA256SUMS`, require safe sorted paths, lowercase SHA-256 hashes, byte sizes,
nullable runtime targets, and ISO date-time generation metadata.

The compatibility manifest includes contract artifact IDs, versions, paths, and
hashes for released OpenAPI, plugin schemas, IPC/WASM contracts, release
manifest schema, error codes, network grants, worker invocation payloads, and
target classifier fixtures.

Host products should run:

```bash
redevplugin verify-compatibility compatibility.json contracts
```

before consuming a dependency set.

## Signed Release Artifacts

Tagged GitHub Releases publish:

- runtime `.tar.gz` bundles;
- `redevplugin-release-stress.json`;
- outer `SHA256SUMS`;
- Sigstore keyless `.sig` and `.bundle` files for each runtime tarball, the
  stress summary, and `SHA256SUMS`.

`scripts/verify_redevplugin_release_artifacts.sh <artifact-dir>` verifies the
outer checksums, required stress evidence categories, key counters and
thresholds, including TCP mock database, WebSocket round-trip, size-denial, and
cancelled-read evidence, signature file presence, cosign bundle presence, and
cosign keyless identity unless explicitly run with `--skip-cosign` for local
fixtures.

## Dependency Audit

`scripts/check_redevplugin_release_audit.sh` runs:

- `npm audit --audit-level=moderate`;
- `GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@latest ./...`;
- `cargo deny check`.

When `cargo-deny` is not installed, set `REDEVPLUGIN_INSTALL_AUDIT_TOOLS=1` to
let the script install it for the run.

## Host Product Consumption

Host products must not build ReDevPlugin from an unpublished sibling checkout or
consume local path dependencies. A release-ready host integration should:

1. select published Go/npm/runtime artifact versions;
2. verify release artifact checksums and signatures;
3. verify stress evidence counters/thresholds and third-party notice evidence;
4. verify compatibility manifest hashes against the selected contracts;
5. bundle the runtime artifact into the host's installer or desktop package;
6. keep host-side release gates aligned with the consumed ReDevPlugin version.
