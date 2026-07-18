# CI And Release Gates

ReDevPlugin release artifacts are the only supported integration surface for
host products. A host product should consume a matching published Go module,
npm package, versioned Rust Worker SDK, Rust runtime bundle, compatibility
manifest, contract hashes, and release evidence set.

## Local And CI Gates

Go checks that can be affected by a workspace must run with `GOWORK=off`.
The CI Go job initializes the Rust toolchain with `rustup show` before
`go test ./cmd/... ./examples/... ./pkg/...` because the CLI scaffold integration test builds the released
Rust runtime as part of the Go package test suite.

CI actions are pinned to immutable commit SHAs and top-level permissions default
to `contents: read`. The Go job checks `gofmt`, `GOWORK=off go list ./cmd/... ./examples/... ./pkg/...`,
`GOWORK=off go test ./cmd/... ./examples/... ./pkg/...`, and
the pinned `golangci-lint` version. The TypeScript job runs ESLint, typecheck,
build, UI unit tests, Examples generation checks, browser harness tests, plus
the bridge replay/cancellation gate.

Example and scaffold worker binaries use Linux/amd64 as the canonical Rust
build host. The committed `examples/plugins/worker-artifacts.lock.json` and
`cmd/redevplugin/scaffold_assets/worker-artifacts.lock.json` bind the exact WASM
bytes to the root workspace, pinned Rust toolchain, Worker SDK, generation
scripts, and the recursive local Cargo dependency source trees discovered from
Cargo metadata. Both generators share `scripts/canonical_wasm_builder.mjs`,
which remaps checkout and Cargo registry paths, pins the exact Rust release,
uses a clean native target directory, isolated Cargo home, and environment
allowlist, rejects Cargo configuration inherited from outside the repository,
and rejects any source snapshot change observed across compilation. Normal
`examples:check` and `scaffold:check` perform the native rebuild on the
canonical CI host and verify their source/artifact lock on every host. The explicit
`examples:generate` and `scaffold:generate` commands use a platform-specific
immutable Rust image digest when run elsewhere;
`examples:check:canonical` and `scaffold:check:canonical` force that same Docker
path for a full local reproduction of CI without accepting host-specific LLVM
output. CI runs both paths and requires byte parity. Normal package builds only
verify committed scaffold assets and never rewrite them implicitly. Release
packaging also verifies the scaffold before building the CLI, including runtime
matrix jobs that consume a prebuilt npm tarball, and the package job installs
the pinned WASM target before that check.

The authoritative local gate, also invoked by the `main` pre-push hook and the
main-branch CI equivalent job, is:

```bash
./scripts/check_redevplugin_pre_push.sh
```

The hook rejects main deletion, non-fast-forward updates, dirty worktrees,
feature worktrees, and local objects that do not match `HEAD`. It does not
cover GitHub-only publication, hosted multi-platform execution, registry
readback, artifact upload/download, Sigstore signing, or GitHub API checks.

The tagged release workflow has one `quality-release` dependency shared by npm
packing, native runtime packing, npm publication, and GitHub Release
publication. It repeats the complete Go format/test/lint, TypeScript UI unit,
Examples, browser-harness and bridge-boundary, Rust format/clippy/test/deny, runtime-contract, and
platform-contract gates before any immutable package or public release is
created. Release audit and release-mode stress remain independent mandatory
dependencies so neither can be hidden by the aggregate quality job.

`scripts/check_redevplugin_release_metadata.mjs` keeps the source release
coordinate closed before packaging. Local and branch CI derive the intended
version from the first `CHANGELOG.md` release section, then require the Go
development compatibility floor and the canonical `redevplugin-worker-sdk`
Cargo metadata to match. Tagged preflight repeats the same check against the
actual `vX.Y.Z` tag. Mutation tests reject tag, changelog, Go compatibility,
Worker SDK version, and canonical manifest-path drift.

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
  manifest, performance evidence, IPC, WASM ABI, worker invocation, network
  grant, all six host-capability artifact schemas, and target classifier
  contract snippets;
- shared Go/TypeScript restricted-schema conformance fixtures, typed capability
  business-error identity, paired operation/stream subscription handles, and
  atomic surface-scoped confirmation rejection;
- executable Go/Rust runtime IPC golden fixtures for handshake/version
  mismatch, replay, unknown-frame, missing-field, and runtime-generation
  mismatch cases;
- mandatory ephemeral runtime lease signing, non-empty Rust startup keyrings,
  Rust-side expiry and invocation-binding validation, and pre-artifact rejection;
- event-driven stream observation and revision-aware waiting, bounded event and
  byte backpressure, transactional ticket commit/rotate, terminal reads at token
  capacity, failure retry, and durable operation/stream terminal reconciliation
  across SQLite reopen;
- release artifact verifier fixture behavior, including exact four-target and
  signed-file sets plus rejection of every extra tar or non-tar asset;
- release manifest v3 Worker SDK identity, safe `.crate` structure, immutable
  tag documentation, and rejection of cross-target SDK byte drift;
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
- browser harness contract and smoke tests;
- real runtime browser smoke through the Go Host library, HTTP adapter, Rust
  runtime, opaque iframe, classic Dedicated Worker, parent-only asset/stream
  transport, storage broker, and network broker.

## Stress Gates

`scripts/check_redevplugin_stress.sh` supports `--fast`, `--full`, `--release`,
and `--summary PATH`.

- `--fast` runs race-sensitive Go packages and `pkg/stress`.
- `--full` starts from a clean `npm ci`, then adds browser harness, runtime
  contract, release bundle smoke, and a four-target published-release verifier
  fixture.
- `--release` adds validation of the exact generated release summary through
  the same structured validator used for downloaded GitHub Release assets. The
  validator requires the exact release category and step sets, including a
  successful `published_release_verifier`; omission, duplication, unexpected
  entries, or a non-zero required step fail closed.

The script always emits a JSON summary. `stress_evidence` contains structured
counters for stream backpressure and scoped terminal-close checks,
operation cancel ownership and inactive-operation non-redispatch, connectivity
classifier/grant denials, runtime revoke ACK p95 latency, KV and SQLite storage
quota pressure, and SQLite sidecar/sparse bypass checks. CI uploads summaries as artifacts, and tagged release workflows
include release-mode stress evidence in the published checksum and signature
evidence chain.

Host-owned stream terminal audit behavior is verified at the scoped adapter
sink boundary.

## Performance Gates

`scripts/check_redevplugin_performance.sh` supports `--fast`, `--smoke`,
`--full`, and `--release`.

- `--fast` runs deterministic admission, notification, backpressure, migration,
  TypeScript type, and renderer reconciliation tests in normal CI.
- `--full` runs the real Go Host and Rust runtime, 32-way invocation and cache
  scenarios, blocking-hostcall isolation, queued and running cancellation, a
  bounded 10,000-frame IPC burst, indexed scheduler and module-cache stress,
  paired namespace/package/HTTP/authorization measurements, real operation and
  stream `MemoryStore` snapshots, the fixed-capacity UDP limiter, 500 stream
  waiters, SQLite batch reads, Node reconciliation measurements, and a real
  Chromium opaque-surface renderer measurement. The weekly workflow uploads
  `performance-evidence-full.json`.
- `--smoke` executes every scenario and records actual measurements without
  enforcing absolute latency thresholds. It is used only by non-publishing
  bundle smoke tests.
- `--release` runs the same acceptance set with release gate identity before a
  bundle manifest or checksum is created.

`REDEVPLUGIN_PERFORMANCE_RUNTIME` may select an explicit executable for smoke
and full measurements. Release evidence rejects that override and always builds
`redevplugin-runtime` from the clean checked-out HEAD bound to `source_commit`.

`performance-contract-v1.json` is the single machine-readable definition of the
22 required scenarios and each scenario's sample count, metric name, unit,
comparator, and limit. The generator and bundle verifier both consume that
contract and reject any missing, extra, duplicate, or drifted metric. The
release workflow generates immutable release evidence once on `ubuntu-24.04`;
all runtime bundles validate and copy those exact bytes through
`--performance-evidence`. `--skip-execution` and `--allow-smoke` are independent
verifier permissions, and published bundles never enable `--allow-smoke`.

Relative acceptance targets use paired measurements from the same process and
input fixture and encode the current-to-reference ratio in basis points. The
package materialization scenario is the exception: it compares isolated child
process `MaxRSS` values so retained package bytes cannot be hidden by heap
accounting. Scheduler and module-cache complexity evidence records operations on
the actual request index, bounded tombstone compaction, and `BTreeSet` eviction
index instead of inferring algorithmic behavior from noisy wall-clock timings.
The UDP limiter combines a fixed 65,536-bucket capacity assertion with a paired
high-cardinality P95 measurement. Release evidence is emitted only by the owning
Go package or Rust runtime test after its behavioral assertions pass.

## Release Bundle

`scripts/build_redevplugin_release.sh` creates a release bundle containing:

- `bin/redevplugin`;
- `bin/redevplugin-runtime`;
- `compatibility.json`;
- `performance-evidence.json`;
- contract artifacts under `contracts/`;
- npm package tarball under `npm/`;
- versioned Rust Worker SDK crate under `sdk/`;
- `release-manifest.json`;
- `SHA256SUMS`;
- generated third-party notices and lockfile evidence;
- the root MIT `LICENSE`;
- `docs/release/a3-tdd-evidence.md` plus the complete signed
  `examples/host-capability/sample-documents-v1/` artifact;
- `notices/THIRD_PARTY_LICENSES.json` plus actual redistributed license, notice,
  and copyright texts under `notices/licenses/`.

The release workflow builds the npm tarball and Rust Worker SDK crate once and
passes those immutable files to every runtime matrix build through
`--npm-package` and `--worker-sdk-package`. The build stamps one release version
into the Go compatibility matrix, npm package, Worker SDK crate, and Rust
runtime hello handshake. Release manifest v3 records the source commit,
compatibility digest, npm tarball path/SHA-256/SRI/size, and Worker SDK
path/SHA-256/size. The bundle verifier
checks compatibility, performance evidence, release manifest hashes,
`SHA256SUMS`, executable target
format, runtime hello, npm package version/license, every declared root and
subpath export target, actual self-referenced imports from the unpacked package,
the Worker SDK package name/version/license/source/README and link-free archive
structure, required contract files, the A3 sample pin, per-file hashes, signed
manifest, generated-client identity, host-neutral vocabulary, and generated
license evidence. License verification checks the exact legal-file
set and each manifest SHA-256; a dependency entry that names a license without
redistributed legal text fails the build. Each runtime matrix runner executes
its own Go and Rust binaries. The post-publication aggregate runner uses
`--skip-execution` verification for foreign targets: it validates ELF/Mach-O architecture, every
manifest and contract hash, npm identity, and compatibility content without
attempting to execute another operating system's binary. Standalone TypeScript
consumer verification reads the exact compiler version, registry URL, and SRI
from each bundle's `notices/package-lock.json`, verifies the temporary
consumer's generated lock identity, and never depends on checkout-root
`node_modules` state. Ordinary branch release-bundle CI runs the complete
four-target isolation regression from a copied verifier root with an invalid
ambient npm registry. It also mutates one otherwise valid Worker SDK crate and
requires aggregate verification to reject the cross-bundle byte drift, so the
tag workflow is not the first place that detects an accidental checkout or
artifact identity dependency.

The SDK package job installs `wasm32-unknown-unknown` before packing. The
package builder extracts the final `.crate` into a clean directory and runs
`cargo check --locked --target wasm32-unknown-unknown`, using one temporary
Cargo home for dependency resolution, packaging, and verification. Publication
cannot depend on a previous job step's Cargo cache or ship a source artifact
that only compiles inside the repository workspace.

## npm Package Publishing

The npm package exposes four deliberate import surfaces:

- `@floegence/redevplugin-ui` is the trusted-parent default allowlist and is
  equivalent to the explicit `/trusted-parent` entrypoint.
- `@floegence/redevplugin-ui/trusted-parent` contains host-shell management,
  surface ownership, transport, and policy clients. It does not export the
  plugin worker bridge client or the internal bootstrap HTML factory.
- `@floegence/redevplugin-ui/plugin` contains exactly six runtime exports for
  untrusted plugin worker bundles: `PluginBridgeClient`, `PluginBridgeError`,
  `callCapabilitySync`, `callCapabilityOperation`, `callCapabilityStream`, and
  `isCapabilityBusinessError`. It cannot import management, surface-host,
  transport, token, stream-decoder, or local-import APIs.
- `@floegence/redevplugin-ui/local-import` contains the explicit dev/admin raw
  package import client. Official release-reference product paths must not
  import or bundle it.

The release-bundle verifier imports every packed entrypoint, requires this
exact export set, checks the plugin runtime namespace, and scans the generated
declarations for trusted-parent and bearer-token leakage. It also installs the
packed tarball into a standalone temporary consumer and runs `tsc --noEmit` on
the released host-capability sample without source aliases.

Ordinary branch CI builds a synthetic `0.0.0-ci.<run-number>` bundle. Only the
tagged release workflow builds and publishes the immutable tag-derived identity.
The published-release verifier remains independent of ambient checkout
dependencies and validates the final npm and Worker SDK artifacts from their
standalone consumer directories.

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

`release-manifest-v4.schema.json` is the machine contract for release bundle
provenance, file lists, and checksums. Release manifests exclude themselves and
`SHA256SUMS`, require the full source commit, compatibility digest, one npm
tarball identity, one Rust Worker SDK crate identity, safe sorted paths,
lowercase SHA-256 hashes, byte sizes, nullable closed platform runtime targets,
and ISO date-time generation metadata. Release builders map the four Rust build
triples explicitly to `darwin/amd64`, `darwin/arm64`, `linux/amd64`, or
`linux/arm64`; build triples are not platform target aliases.

The compatibility manifest includes contract artifact IDs, versions, paths, and
hashes for released OpenAPI, plugin schemas, release metadata, source policy,
source revocations, performance evidence, IPC/WASM contracts, release manifest
schema, error codes,
network grants, the host-capability contract/pin/manifest/compatibility/
signature/notices schemas, worker invocation payloads, and target classifier
fixtures.

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
compatibility bytes, identical embedded npm and Worker SDK bytes, bundle
manifests, and runtime presence. The workflow downloads the npm registry tarball, verifies it
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
