# CI And Release Gates

ReDevPlugin release artifacts are the only supported integration surface for
host products. A host product should consume a matching published Go module,
npm package, Rust runtime bundle, compatibility manifest, contract hashes, and
release evidence set.

## Local And CI Gates

Go checks that can be affected by a workspace must run with `GOWORK=off`.
The CI Go job initializes the Rust toolchain with `rustup show` before
`go test ./...` because the CLI scaffold integration test builds the released
Rust runtime as part of the Go package test suite.

CI actions are pinned to immutable commit SHAs and top-level permissions default
to `contents: read`. The Go job checks `gofmt`, `GOWORK=off go list ./...`,
`GOWORK=off go test ./...`, and
the pinned `golangci-lint` version. The TypeScript job runs ESLint, typecheck,
build, unit/demo/browser tests, plus the bridge replay/cancellation gate.

Core local checks:

```bash
GOWORK=off go list ./...
GOWORK=off go test ./...
GOWORK=off golangci-lint run ./...
npm ci
npx playwright install chromium
npm run check
./scripts/check_redevplugin_runtime_contract.sh --ci
./scripts/check_redevplugin_platform.sh --ci
REDEVPLUGIN_INSTALL_AUDIT_TOOLS=1 ./scripts/check_redevplugin_release_audit.sh
./scripts/check_redevplugin_stress.sh --fast --summary dist/redevplugin-stress-fast.json
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The tagged release workflow has one `quality-release` dependency shared by npm
packing, native runtime packing, npm publication, and GitHub Release
publication. It repeats the complete Go format/test/lint, TypeScript unit/demo/
browser and bridge-boundary, Rust format/clippy/test/deny, runtime-contract, and
platform-contract gates before any immutable package or public release is
created. Release audit and release-mode stress remain independent mandatory
dependencies so neither can be hidden by the aggregate quality job.

`check_redevplugin_platform.sh` and
`check_redevplugin_runtime_contract.sh` explicitly accept `--ci`, support
`--help`, reject unknown arguments, and export `GOWORK=off` internally. The
`--ci` flag is an explicit no-op so documentation, local runs, and CI can share
the same command shape.

## Contract Gates

`scripts/check_redevplugin_runtime_contract.sh --ci` validates:

- OpenAPI/HTTP route/TypeScript SDK binding coverage, including release-reference
  install/update routes that keep official package bytes out of trusted browser
  requests;
- generated opaque render-policy consistency across the bridge schema, Go
  package builder, and TypeScript trusted renderer;
- compatibility manifest schema and emitted compatibility manifest shape;
- manifest, package signature, token/ticket, bridge, error-code, release
  manifest, IPC, WASM ABI, worker invocation, network grant, and target
  classifier contract snippets;
- executable Go/Rust runtime IPC golden fixtures for handshake/version
  mismatch, replay, unknown-frame, missing-field, and runtime-generation
  mismatch cases;
- release artifact verifier fixture behavior, including exact four-target and
  signed-file sets plus rejection of every extra tar or non-tar asset;
- npm registry readback mutation fixtures for tarball SHA-512, SLSA subject,
  repository, workflow path/ref, tag, and source commit;
- Rust IPC, runtime, target classifier, and WASM ABI tests when Cargo is
  available.

`scripts/check_redevplugin_platform.sh --ci` validates:

- Go package tests;
- positive generated-plugin package fixtures for minimal, networked, storage,
  and method-contract manifests through the shared CLI validate/package path;
- malicious generated-plugin package fixtures, including npm lifecycle scripts,
  npm dependency fields, Cargo build scripts, proc macros, native linker config,
  and Cargo dependency sections;
- CLI validate/package/sign/install/dev lifecycle smoke paths;
- compatibility manifest verification;
- bridge SDK checks;
- TypeScript typecheck;
- browser demo tests;
- real runtime browser smoke through the Go Host library, HTTP adapter, Rust
  runtime, opaque iframe, classic Dedicated Worker, parent-only asset/stream
  transport, storage broker, and network broker.

## Stress Gates

`scripts/check_redevplugin_stress.sh` supports `--fast`, `--full`, `--release`,
and `--summary PATH`.

- `--fast` runs race-sensitive Go packages and `pkg/stress`.
- `--full` adds browser demo, runtime contract, release bundle smoke, and a
  four-target published-release verifier fixture.
- `--release` aliases full mode for release-blocking use.

The script always emits a JSON summary. `stress_evidence` contains structured
counters for stream backpressure, stream close/cancel fail-closed checks,
operation cancel dispatch success/failure persistence, connectivity
classifier/grant denials, runtime revoke ACK p95 latency, KV and SQLite storage
quota pressure, and SQLite sidecar/sparse bypass checks. CI uploads summaries as artifacts, and tagged release workflows
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
- generated third-party notices and lockfile evidence;
- the root MIT `LICENSE`;
- `docs/release/a2-tdd-evidence.md` so changelog evidence links remain valid in
  standalone bundles;
- `notices/THIRD_PARTY_LICENSES.json` plus actual redistributed license, notice,
  and copyright texts under `notices/licenses/`.

The release workflow builds the npm tarball once and passes that immutable file
to every runtime matrix build through `--npm-package`. The build stamps one
release version into the Go compatibility matrix, npm package, and Rust runtime
hello handshake. Release manifest v2 records the source commit, compatibility
digest, and the npm tarball path, SHA-256, SRI, and size. The bundle verifier
checks compatibility, release manifest hashes, `SHA256SUMS`, executable target
format, runtime hello, npm package version/license, every declared root and
subpath export target, actual self-referenced imports from the unpacked package,
required contract files, and
generated license evidence. License verification checks the exact legal-file
set and each manifest SHA-256; a dependency entry that names a license without
redistributed legal text fails the build. Each runtime matrix runner executes
its own Go and Rust binaries. The post-publication aggregate runner uses structural-only
verification for foreign targets: it validates ELF/Mach-O architecture, every
manifest and contract hash, npm identity, and compatibility content without
attempting to execute another operating system's binary.

## npm Package Publishing

The npm package exposes four deliberate import surfaces:

- `@floegence/redevplugin-ui` is the trusted-parent default allowlist and is
  equivalent to the explicit `/trusted-parent` entrypoint.
- `@floegence/redevplugin-ui/trusted-parent` contains host-shell management,
  surface ownership, transport, and policy clients. It does not export the
  plugin worker bridge client or the internal bootstrap HTML factory.
- `@floegence/redevplugin-ui/plugin` contains only `PluginBridgeClient` for
  untrusted plugin worker bundles. It cannot import management, surface-host,
  transport, token, or local-import APIs.
- `@floegence/redevplugin-ui/local-import` contains the explicit dev/admin raw
  package import client. Official release-reference product paths must not
  import or bundle it.

The release-bundle verifier imports every packed entrypoint, requires this
exact export set, checks the plugin runtime namespace, and scans the generated
declarations for trusted-parent and bearer-token leakage.

Tagged release workflows also publish `@floegence/redevplugin-ui` to the npm
registry with the same version as the Git tag. The publish job downloads the
single tarball already embedded in every runtime bundle, declares job-local
`id-token: write` permission for npm trusted publishing, and runs trusted
publishing with provenance. If that version already exists, the job compares
registry `dist.integrity` with the built tarball, downloads `dist.tarball`,
recomputes SHA-512, reads the npm attestation endpoint, and validates the SLSA
DSSE subject digest, repository, release workflow path/ref, tag, and source
commit. A mismatch or missing provenance fails closed. Both immutable packing and registry publishing
run with pinned `npm@11.18.0`, so tarball identity does not depend on the runner's
ambient npm version.

## Release Manifest And Compatibility

`release-manifest-v2.schema.json` is the machine contract for release bundle
provenance, file lists, and checksums. Release manifests exclude themselves and
`SHA256SUMS`, require the full source commit, compatibility digest, one npm
tarball identity, safe sorted paths, lowercase SHA-256 hashes, byte sizes,
nullable runtime targets, and ISO date-time generation metadata.

The compatibility manifest includes contract artifact IDs, versions, paths, and
hashes for released OpenAPI, plugin schemas, release metadata, source policy,
source revocations, IPC/WASM contracts, release manifest schema, error codes,
network grants, worker invocation payloads, and target classifier fixtures.

Any change to the release-reference install/update request schema, route set,
trust-state enum, token/ticket schema, or bridge contract must update the
machine-readable contract, route fixtures, SDK bindings, compatibility hash, and
focused contract tests in the same feature change.

Host products should run:

```bash
redevplugin verify-compatibility compatibility.json contracts
```

before consuming a dependency set.

## Signed Release Artifacts

Tagged GitHub Releases publish:

- runtime `.tar.gz` bundles;
- `redevplugin-release-stress.json`;
- `redevplugin-a2-acceptance.json`;
- `redevplugin-a2-supported.png` and `redevplugin-a2-unsupported.png`;
- outer `SHA256SUMS`;
- Sigstore keyless `.sig` and `.bundle` files for each runtime tarball, the
  stress summary, all three A2 evidence files, and `SHA256SUMS`.

`scripts/verify_redevplugin_release_artifacts.sh --tag vX.Y.Z <artifact-dir>`
verifies the exact four runtime archives and complete signed asset set, rejecting
any extra file. It also verifies outer checksums, required stress evidence categories, key counters and
thresholds, including TCP mock database, WebSocket round-trip, size-denial, and
cancelled-read evidence, A2 opaque-origin/exact sandbox/CSP/credential-isolation
assertions from the real Go Host/HTTP adapter/Rust runtime Chromium source, PNG
signatures for both screenshots, signature file presence, cosign bundle presence,
and cosign keyless identity bound to the exact tag unless explicitly run with
`--skip-cosign` for local fixtures.

The release workflow defaults to `contents: read`, grants OIDC only to the npm
and signing jobs, and grants `contents: write` only to the GitHub Release job.
Release actions and audit tools are pinned to immutable revisions or exact
versions; signing and public signature readback use `cosign v2.4.3`. A per-ref
concurrency group prevents concurrent publishers. Tag preflight fetches full
history, requires the tagged commit to be on `origin/main`, resolves lightweight
or annotated GitHub tag objects to the expected commit, and uses a strict GitHub
API check that distinguishes a 404 from permission, network, and server failures.
The npm and GitHub publication jobs repeat the immutable tag check immediately
before mutation. `gh release create` fails rather than editing an existing
release or replacing an asset.

After publication, `scripts/verify_published_release.mjs` downloads the
immutable release and verifies all four runtime targets, source commit,
compatibility bytes, identical embedded npm bytes, bundle manifests, and
runtime presence. The workflow downloads the npm registry tarball, verifies it
against the exact bytes embedded in every bundle, and validates SLSA DSSE source
identity from the npm attestation endpoint. It also downloads the Go module independently
from VCS and `proxy.golang.org`, requires the direct origin hash/ref to match the
release commit/tag, and compares both module `h1` and `go.mod` `h1` identities
before declaring the release complete. The final readback independently resolves
the public tag again and requires a published, non-draft GitHub Release for that
same tag and commit before declaring the release complete.

## Dependency Audit

`scripts/check_redevplugin_release_audit.sh` runs:

- `npm audit --audit-level=moderate`;
- `GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...`;
- `cargo deny check`.

When `cargo-deny` is not installed, set `REDEVPLUGIN_INSTALL_AUDIT_TOOLS=1` to
let the script install the pinned `cargo-deny@0.19.9` for the run.

## Host Product Consumption

Host products must not build ReDevPlugin from an unpublished sibling checkout or
consume local path dependencies. A release-ready host integration should:

1. select published Go/npm/runtime artifact versions;
2. verify release artifact checksums and signatures;
3. verify stress evidence counters/thresholds and third-party notice evidence;
4. verify compatibility manifest hashes against the selected contracts;
5. bundle the runtime artifact into the host's installer or desktop package;
6. keep host-side release gates aligned with the consumed ReDevPlugin version.
