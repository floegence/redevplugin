# Changelog

## v0.3.1

### Fixed

- Release stress validation now runs against the exact summary produced by
  `check_redevplugin_stress.sh --release` before signing or publication, using
  the same validator as downloaded GitHub Release assets.
- Stream backpressure evidence no longer expects direct stream-store closure to
  emit a Host audit event after terminal ownership moved to scoped adapter
  sinks. The Host subscription regression now explicitly proves that sink
  closure records `plugin.stream.closed`.
- ZIP fixtures sort map-backed paths before writing entries, eliminating the
  case-fold collision diagnostic flake seen in the first A3 main CI run.
- The `v0.3.0` tag published the npm package but did not produce a GitHub
  Release because its verifier retained the obsolete direct-store close-audit
  counter. `v0.3.1` is the first complete A3 release coordinate.

## v0.3.0

### Added

- Signed, exact-pinned external host capability contract artifacts with a
  restricted JSON Schema, compatibility metadata, deterministic plugin-side
  TypeScript client generation, and host-neutral Documents sample.
- Closed machine schemas for the host-capability contract, pin, manifest,
  compatibility document, signature envelope, and notices list, all included in
  the generated compatibility registry and release bundle.
- Typed capability invocation bindings that carry plugin, surface, session,
  contract, permission, confirmation, quota, revision, target descriptor, and
  audit correlation evidence into host business adapters.
- Host-owned operation and stream sinks, route-local cancellation hooks,
  execution leases, quota fencing, and stable negative audit/diagnostic events.
- Shared Go/TypeScript restricted-schema conformance fixtures and generated
  business-error unions bound to capability identity and details-schema digest.
- A maintained [A3 TDD evidence record](docs/release/a3-tdd-evidence.md) and
  release-bundle verification of the signed sample artifact.

### Security

- Capability bundle verification rejects arbitrary URL/file refs, traversal,
  symlinks, hardlinks, file-set or digest drift, wrong publisher/key epochs,
  signature mismatch, stale compatibility, redirects, and stale generated
  clients before registry or dev-state mutation.
- Confirmation dispatch re-resolves and hashes the trusted target descriptor;
  changed targets, requests, sessions, methods, policy revisions, or revoke
  epochs fail closed and consumed confirmations cannot be replayed.
- Trusted-parent confirmation rejection is surface- and bridge-scoped, removes
  the pending intent atomically, records `confirmation_rejected` audit and
  diagnostic evidence, and never dispatches the business adapter.
- Operation and stream ids are allocated before adapter dispatch and are never
  bearer authorization. Sink writes revalidate the live execution lease and
  are rejected after terminal state, timeout, disable, or revoke.
- Runtime `http_stream` requests inherit the Host-owned subscription id from
  the invocation; plugin-selected ids and invocations without a Host id fail
  closed before broker execution.
- Every process supervisor now creates an ephemeral Ed25519 signing key and
  supplies a mandatory non-empty Rust keyring. Rust independently rejects
  expired leases and any signed-lease mismatch with the worker invocation's
  plugin, execution handles, audit, surface/session, or runtime audience before
  replay consumption or artifact access.
- Worker leases bind the exact invocation through `params_sha256` and a
  fixed-order, length-prefixed invocation target hash. Rust recomputes both,
  and the expiry-aware replay cache fails closed at a hard capacity.
- Capability artifact resolution rejects RFC 6890 special-use IPv4/IPv6
  ranges, including mapped IPv4, carrier-grade NAT, benchmark, documentation,
  translation, reserved, and local networks.
- Source security floors reject same-policy-epoch content replacement while
  excluding assessment-only timestamps from the canonical security hash.
- Stream reads serialize per stream and commit event consumption with the
  single-use ticket decision. Failed reads preserve the current ticket and
  events, open streams rotate exactly once, and drained terminal streams do not
  reserve or expose a replacement credential.
- Partial operation/stream terminal writes are durably reconciled in either
  direction on Host construction and later execution, including SQLite reopen.
- The first subscription terminal intent is latched before either store write;
  conflicting concurrent callers fail closed. Host startup terminates durable
  running/cancel-requested operations that have no live execution owner.
- Negative method audit/diagnostic persistence failures are returned together
  with the original rejection and never permit adapter dispatch.
- Registry, operation, and stream stores deep-copy nested execution state and
  returned event bytes so callers cannot mutate stored authority through shared
  memory.

### Changed

- `redevplugin host-capability generate-client` now consumes a verified artifact
  root, pin, and public key. `--check` compares the published generated client
  without rewriting it.
- `dev-install` validates packages and capability artifacts before creating an
  isolated staging directory, then atomically promotes the complete state root.
- Operation cancellation no longer performs a later global capability-registry
  lookup. A live route captures its optional cancel hook; inactive persisted
  operations keep durable `cancel_requested` state without redispatch.
- Execution records now declare `route_kind`; only capability routes carry an
  exact contract pin, while worker/core-action records carry explicit empty
  permission arrays.
- Generated operation clients expose `cancel()` only for cancelable contracts,
  subscriptions must be cancelable, and numeric/boolean enums and constants
  retain literal TypeScript types.
- Trusted-parent stream reads preserve a renewable opaque handle after an
  explicit Host rejection, but invalidate it after transport uncertainty,
  credential revocation, or malformed success data.

## v0.2.2

### Fixed

- npm release verification now accepts the npm 11 tarball-publication metadata
  shape where the optional `gitHead` field is absent, while still rejecting a
  conflicting `gitHead` when npm supplies one.
- Source identity remains mandatory and is verified from the signed SLSA
  provenance source digest, together with the immutable public tarball bytes,
  repository, workflow, and tag identity. The `v0.2.1` tag published the npm
  package with valid provenance but did not produce a GitHub Release because
  the obsolete mandatory `gitHead` check failed; `v0.2.2` is the first complete
  A2 release.

## v0.2.1

### Fixed

- npm trusted publishing now distinguishes a missing package version by the
  `npm view` exit status before comparing registry integrity, so npm 11 E404
  JSON cannot be mistaken for an already-published tarball.
- The release workflow contract rejects the faulty `--json || true` probe that
  prevented `v0.2.0` from publishing. The `v0.2.0` tag produced no npm package
  or GitHub Release. The `v0.2.1` tag published the npm package but did not
  produce a GitHub Release because its registry verifier required npm's optional
  `gitHead` metadata.

## v0.2.0

### Added

- Version 2 manifest, release metadata, token/ticket, bridge, OpenAPI,
  compatibility, and release-manifest contracts with generated Go and
  TypeScript version/hash registries.
- Release-reference install and update APIs that verify signed release metadata,
  source policy, package identity, compatibility, and trust before registry
  mutation.
- `PluginSurfaceHost`, opaque surface prepare/dispose/cache APIs, typed plugin
  rendering and action events, parent-owned asset and stream transport, and a
  classic Dedicated Worker plugin runtime.
- One aggregate surface-opening deadline with server revoke, local teardown, and
  bounded retry-state accounting.
- Single-host fake and real-runtime browser demos with Chromium isolation,
  capability, confirmation, stream, and disposal conformance coverage.
- Structured A2 browser acceptance evidence and supported/unsupported
  screenshots for opaque-origin isolation, exact sandbox/CSP policy, credential
  absence, worker hardening, and deterministic disposal.
- A maintained [A2 TDD evidence record](docs/release/a2-tdd-evidence.md) covering
  red-to-green tests, generated contracts, release gates, and host/plugin API
  boundaries.

### Security

- Plugin iframes now use a generated `srcdoc` with exactly
  `sandbox="allow-scripts"`, a unique opaque origin, and a fail-closed CSP.
- `PluginSurfaceHost.create(...)` creates and owns a fresh hardened iframe;
  callers mount its read-only `element` and cannot provide a pre-existing frame.
- Plugin packages must declare exactly one package-local
  `text/redevplugin-worker` classic bundle. Package validation and the trusted
  renderer share a generated closed render policy and reject unsupported DOM,
  URL, script, storage, and network behavior before execution.
- Asset tickets, asset sessions, gateway credentials, stream tickets,
  confirmation tokens, plugin identity bindings, and owner/session hashes remain
  in the trusted parent. Plugin code receives only typed messages and opaque
  surface/stream handles.
- The initial gateway and asset lease is applied before renderer initialization;
  renewals rotate both credentials only after active transport requests drain,
  and any renewal failure closes the surface.
- The renderer retains a private runtime-control port and gives plugin code only
  the typed bridge port. Monotonic request ids, duplicate/replay rejection,
  timeout cancellation, and late-response handling fail closed. Runtime-control
  calls use captured bound methods, and the shared `MessagePort` prototype is
  sealed before plugin code executes.
- Gateway minting now requires both a completed closed-document preparation and
  a generation-bound `port_ack`. Dispose requests bind `bridge_nonce`, preventing
  a stale surface generation from deleting its replacement.
- Lazy assets are registry-path/size/content-type/SHA-256 verified on every read and bounded
  to 128 entries, 32 MiB cumulative bytes, and four concurrent reads.
- Manifest methods require compiled, closed request and response JSON Schemas;
  invalid requests never reach adapters or the runtime, and invalid responses
  fail with the stable contract-mismatch error.

### Changed

- Manifest surfaces now use host-neutral `view`, `command`, or `background`
  kinds plus optional intent; product activity/workbench/settings placement is
  no longer part of the platform manifest.
- Surface assets and streams are read through authenticated parent-only POST
  routes. Asset requests carry only a server-issued `binding_id`; the Host
  resolves the prepared path/digest binding and rejects arbitrary package paths.
  Plugin subdomains, cookie bootstrap, GET asset/stream routes, query credentials,
  and browser CSP-report ingestion are removed from the active v2 contract.
- Release automation packs the npm package once, embeds identical bytes in every
  runtime bundle, publishes those bytes with npm provenance, rejects mutable
  GitHub Release reruns, executes binaries on their native matrix runners, and
  verifies public GitHub, npm, Go direct/proxy identity, foreign executable
  structure, compatibility, checksum, and cosign readback.
- Release packing/publishing uses pinned `npm@11.18.0`, signing uses pinned
  `cosign v2.4.3`, and publication revalidates lightweight/annotated tag identity
  before npm/GitHub mutation and after the non-draft GitHub Release exists.
- Release bundles carry an indexed, SHA-256-verified set of actual third-party
  license, notice, and copyright texts rather than license names alone.
- Release bundles and npm tarballs include the MIT license. Bundle verification
  imports every packed npm export, and registry readback downloads the public
  tarball and validates its SHA-512 plus SLSA subject, repository, workflow tag,
  and source commit.
- Surface session and token state are globally and per-owner/plugin bounded,
  reject duplicate active ids, cap token TTLs, index token ids, preserve bounded
  revoke floors fail closed, and prune expired records.

### Removed

- The browser-site origin store and its cleanup lifecycle.
- Active v1 sandbox bootstrap/assets/stream/CSP-report routes and the
  `allow-same-origin` iframe path, together with superseded v1 contract files.
