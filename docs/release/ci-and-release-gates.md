# CI And Release Gates

Published registries and machine contracts are the only supported ReDevPlugin
integration surface for host products. ReDevPlugin publishes versioned source
crates together with a matching Go module, npm packages, compatibility metadata,
contract hashes, and package publication evidence. Host products build the
runtime binary from exact published Rust source crates; local checkout wiring
and upstream OS runtime downloads are not supported.

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
verify committed scaffold assets and never rewrite them implicitly. Package
publication also verifies the scaffold before packing source artifacts, and the
package job installs the pinned WASM target before that check.

The authoritative local gate, also invoked by the `main` pre-push hook and the
main-branch CI equivalent job, is:

```bash
./scripts/check_redevplugin_pre_push.sh
```

The hook rejects main deletion, non-fast-forward updates, dirty worktrees,
feature worktrees, and local objects that do not match `HEAD`. It does not
cover GitHub-only publication, hosted multi-platform execution, registry
readback, artifact upload/download, Sigstore signing, or GitHub API checks.

The tagged release workflow has one `quality-release` dependency shared by Go,
npm, and Rust package publication plus GitHub Release completion publication.
It repeats the complete Go format/test/lint, TypeScript UI unit,
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

- the still-active compatibility-v7 release manifest v4 Worker SDK identity
  until the atomic v8 activation removes that runtime-bundle contract; the
  staged v2 package registry excludes it and is not exposed by the current Host
  compatibility API;
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
- package-set/publication verifier behavior, including exact registry package
  closure, safe `.crate` structure, immutable tag documentation, and rejection
  of extra or mismatched packages;
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
  contract, package extraction, isolated-registry, and packaged-source fake-host
  fixtures.
- `--release` adds validation of the exact generated release summary through
  the same structured validator used for registry readback and the completion
  manifest. Omission, duplication, unexpected entries, or a non-zero required
  step fail closed.

The script always emits a JSON summary. `stress_evidence` contains structured
counters for stream backpressure and scoped terminal-close checks,
operation cancel ownership and inactive-operation non-redispatch, connectivity
classifier/grant denials, runtime revoke ACK p95 latency, KV and SQLite storage
quota pressure, and SQLite sidecar/sparse bypass checks. CI uploads summaries as artifacts, and tagged release workflows
bind release-mode stress evidence into the package publication evidence chain.

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
- `--release` runs the same acceptance set with release gate identity before
  package publication evidence is created.

`REDEVPLUGIN_PERFORMANCE_RUNTIME` may select an explicit executable for smoke
and full measurements. Release evidence rejects that override and always builds
`redevplugin-runtime` from exact packaged source bytes bound to `source_commit`.

`performance-contract-v2.json` is the single machine-readable definition of the
25 required scenarios and each scenario's sample count, metric name, unit,
comparator, and limit. The generator and bundle verifier both consume that
contract and reject any missing, extra, duplicate, or drifted metric. Route
authorization evidence also embeds the pinned v0.5.1 and candidate profiles;
the verifier checks their canonical hashes and recomputes all comparison
metrics before accepting the bundle. The
release workflow generates immutable release evidence once on the pinned Linux
runner; registry-only conformance validates the exact evidence bytes.

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

## Platform Package Set

ReDevPlugin publishes one versioned platform package set:

- the Go module containing the Host library, adapters, HTTP integration, and
  generated DTOs;
- `@floegence/redevplugin-contracts` and
  `@floegence/redevplugin-ui` on the npm registry;
- the Rust source crates for contracts, IPC, WASM ABI, target classification,
  Worker SDK, and `redevplugin-runtime` on crates.io;
- generated OpenAPI, JSON schemas, compatibility metadata, contract hashes, and
  conformance fixtures.

The package set contains no OS runtime binary, target archive, installer,
product checksum, or product signature. Every Rust package is extracted into a
clean directory and checked with exact registry dependencies. Higher-level
crates resolve lower-level packages through an isolated registry fixture before
formal publication and through crates.io during release readback. Path, git, and
sibling overrides are rejected.

Host products build the runtime binary from verified published source crates
with their own fixed toolchain. The host product owns the resulting binary,
SBOM, provenance, signature, installer, and product archive. ReDevPlugin still
owns runtime admission and supervision, IPC, WASM execution, hostcalls, leases,
quotas, revocation, and diagnostics contracts.

## npm Package Publishing

The contracts npm package exposes one explicit root surface:

- `@floegence/redevplugin-contracts` contains the immutable canonical contract
  bodies, registry metadata, package set, synthetic registry contract, and
  typed lookup API. It is the only npm entrypoint that loads raw schemas.

The UI npm package exposes four deliberate import surfaces:

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

The package verifier imports every packed entrypoint, requires this
exact export set, checks the plugin runtime namespace, and scans the generated
declarations for trusted-parent and bearer-token leakage. It also installs the
packed contracts and UI tarballs into a standalone temporary consumer and runs
`tsc --noEmit` on the released host-capability sample without source aliases.
The UI package uses one exact contracts dependency, while its root,
`trusted-parent`, and `plugin` bundles are verified not to load contract bodies.

While the active v7 release-bundle verifier still exists, its unchanged v4
`npm_package` field continues to describe the UI tarball. The exact-version
contracts tarball is a bounded companion recorded by the existing closed
`files` list and `SHA256SUMS`; the verifier validates both packages and installs
them together offline. This is only a feature-branch transition to the v8
package-only workflow, which removes the legacy bundle and v4 manifest rather
than extending their wire format.

Ordinary branch CI builds synthetic package bytes and validates them in isolated
consumer directories. Only the tagged release workflow publishes the immutable
tag-derived identity. Registry readback remains independent of ambient checkout
dependencies.

Tagged release workflows publish both npm packages with the same version as the
Git tag. Publish jobs receive only prebuilt, digest-pinned tarballs, declare
job-local `id-token: write` permission for trusted publishing, and run without a
checkout or repository scripts. If a version already exists, the job compares
registry `dist.integrity` with the built tarball, downloads `dist.tarball`,
recomputes SHA-512, reads the npm attestation endpoint, and validates the SLSA
DSSE subject digest, repository, release workflow path/ref, tag, and source
commit. A mismatch or missing provenance fails closed. Both immutable packing and registry publishing
run with pinned `npm@11.18.0`, so tarball identity does not depend on the runner's
ambient npm version.

## Package Publication And Compatibility

`platform-package-set-v1` is the canonical coordinate set for Go, npm, and Rust
packages. It does not contain registry checksums or the source commit, avoiding
self-reference; those identities are verified from the registries and recorded
in `platform-package-publication-v1` only after readback succeeds.

The compatibility manifest includes contract artifact IDs, versions, paths, and
hashes for released OpenAPI, plugin schemas, release metadata, source policy,
source revocations, performance evidence, IPC/WASM contracts, package-set and
publication schemas, error codes,
network grants, the host-capability contract/pin/manifest/compatibility/
signature/notices schemas, worker invocation payloads, and target classifier
fixtures.

Any change to the release-reference install/update request schema, route set,
trust-state enum, token/ticket schema, or bridge contract must update the
machine-readable contract, route fixtures, SDK bindings, compatibility hash, and
focused contract tests in the same feature change.

Host products verify the package publication attestation, independently read
back every registry package, validate the compatibility digest, and only then
build a product runtime binary.

## GitHub Release Completion

Tagged GitHub Releases publish exactly one machine asset:

- `platform-package-publication-v1.json`, with the fixed publication content
  type and an OIDC artifact attestation bound to the exact release workflow and
  source commit.

ReDevPlugin GitHub Releases do not contain OS runtime binaries, runtime archives,
installers, or product signatures. They also reject npm tarballs, `.crate`
files, checksum collections, detached signatures, screenshots, and any second
machine asset. Human-readable release notes are not a trust anchor.

The release workflow defaults to `contents: read`. Build, test, pack, hash, and
verification jobs have no publication credentials. Registry, attestation, and
GitHub Release jobs have minimal isolated permissions, do not checkout or run
candidate code, and consume only artifact-ID and digest-pinned verified bytes.
A per-ref concurrency group prevents concurrent publishers. Tag identity and
main ancestry are rechecked immediately before every mutation.

After publication, the release verifier downloads the Go module, both npm
packages, and all Rust crates from their formal registries, verifies checksums,
provenance, source commit, dependency closure, contract digest, and package-set
identity, then runs the registry-only fake-host E2E offline. Only after that gate
passes is the completion manifest generated, attested, uploaded, and read back
by exact bytes. Partial or conflicting publication permanently fails that
version; existing package bytes are never overwritten.

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

1. select the published Go, npm, and Rust source crate versions from one package
   set;
2. verify registry checksums, provenance, source identity, dependency closure,
   publication completion evidence, and compatibility hashes;
3. build the runtime binary from verified registry source with a fixed,
   reproducible product toolchain and no sibling/path overrides;
4. generate and verify the product-owned binary descriptor, SBOM, provenance,
   and signature;
5. bundle that product runtime into the host installer or desktop package;
6. keep host-side release gates aligned with the consumed ReDevPlugin version
   while continuing to use the ReDevPlugin admission and supervisor APIs.
