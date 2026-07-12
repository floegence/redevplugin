# Changelog

## v0.2.1

### Fixed

- npm trusted publishing now distinguishes a missing package version by the
  `npm view` exit status before comparing registry integrity, so npm 11 E404
  JSON cannot be mistaken for an already-published tarball.
- The release workflow contract rejects the faulty `--json || true` probe that
  prevented `v0.2.0` from publishing. The `v0.2.0` tag produced no npm package
  or GitHub Release; `v0.2.1` is the first published A2 release.

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
