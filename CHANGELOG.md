# Changelog

## v0.6.0

### Changed

- Stage the content-addressed `contract-registry-v2`,
  `platform-package-set-v1`, and package-only publication schema without
  activating the incomplete v8 compatibility surface. The staged aggregate
  covers a synthetic registry coordinate and excludes product runtime binaries,
  installers, signatures, and the retired runtime-bundle manifest.
- Add opt-in Go, npm, and Rust contract libraries generated from the same staged
  registry bytes. Their immutable lookup APIs expose 33 ordinary artifacts plus
  one synthetic registry contract, while the Host and UI entrypoints retain
  body-free dependency graphs until the atomic v8 activation. The temporary v7
  bundle gate validates exact-version local contracts and UI tarballs together
  without changing the legacy release-manifest wire.
- Stage closed root-delegation, release-source-policy v2, policy-pointer,
  release-revocation v2, and revocation-pointer schemas together with
  dependency-light Go, TypeScript, and Rust canonical signing APIs. Seven
  domain-separated preimages bind root delegation, package signatures, release
  metadata, policy documents and pointers, and revocation documents and
  pointers; timestamps are always caller supplied, pointer genesis uses one
  explicit zero sentinel, strict decoders reject non-canonical or trailing JSON,
  and one shared cross-language fixture proves every 7x6 substitution fails.
  The active v1 registry and compatibility-v7 surface remain unchanged until the
  atomic v8 activation.
- Replace browser-facing GET reads with closed POST query requests that require
  exact Origin, CSRF, route action, and explicit query-effect authorization.
  Query cancellation remains safely retryable and never reports a mutation
  outcome.
- Remove URL query strings from the platform API. Local package install and
  update now share one plugin-instance path; updates carry one canonical
  management revision header before package bytes are staged.
- Advance the public route contracts to `plugin-host-v5`,
  `plugin-platform-v7`, and `compatibility-manifest-v7`, with generated route
  fixtures carrying the closed `query|mutation` effect.
- Advance the immutable performance contract to `performance-contract-v2` and
  pin the v0.5.1 route-authorization comparison probe used for 1/100/1000
  authenticated request regression evidence.
- Advance performance evidence to `performance-evidence-v2`, embedding the
  baseline and candidate profiles so release verification can recompute every
  route-authorization regression metric from signed provenance.
- Replace surface-only revocation with an authenticated four-hash session fence,
  durable incomplete-drain reconciliation, exact resource indexes, all-shard
  runtime containment, and terminal acknowledgements. Publish the coordinated
  `session-scope-v1`, `token-ticket-v4`, `rust-ipc-v5`, and `error-codes-v5`
  contracts without exposing owner identity in HTTP DTOs.

## v0.5.1

### Fixed

- Synchronize the exact release stress-step contract with the dedicated
  connectivity-classifier evidence step, while preserving closed-set, order,
  duplicate, and successful-status validation in the signed stress summary.
- Enforce namespace quotas after cold usage loads and namespace listing so
  persisted SQLite sidecar or sparse-file growth fails closed after restart,
  and restore release evidence from the current owner-scoped generation path.
- The `v0.5.0` tag completed the release quality, audit, and immutable
  performance gates but produced no npm package or GitHub Release because the
  stress-summary validator still expected the earlier step set. `v0.5.1` is the
  first complete release of the v5 platform contract.

## v0.5.0

### Added

- Add immutable runtime descriptors and strict SemVer validation across install,
  update, downgrade, enable, surface opening, worker invocation, and runtime
  startup, including exact target, IPC, WASM ABI, and artifact SHA-256 checks.
- Add one closed runtime target contract shared by Go host APIs, persisted
  compatibility records, HTTP mappings, Rust IPC, generated TypeScript, and
  release verification. Rust build triples map explicitly to the four canonical
  platform targets and are never accepted as platform target aliases.
- Add durable pending/completed/exported security-audit journals for memory and
  SQLite hosts, startup reconciliation, stable event IDs, idempotent export, and
  explicit committed/not-committed/unknown mutation outcomes.
- Add explicit Host feature modules, the authorized `Host.Features(ctx)` contract, and
  `GET /_redevplugin/api/plugins/features`; unconfigured features now return
  `PLUGIN_FEATURE_NOT_CONFIGURED` instead of relying on placeholder adapters.
- Add fixed-seed Go fuzz gates and Rust property tests for packages, manifests,
  response normalization, strict JSON, IPC, stream state, SQLite tokenization,
  scheduler fairness, module cache limits, and target classification.
- Add invocation cancellation, Host/Rust negotiated runtime limits, per-plugin
  fair scheduling, capacity errors, and health metrics for active and queued
  invocations plus the compiled-module cache.
- Add a shared Wasmi engine and single-flight, deterministic LRU module cache
  keyed by artifact SHA-256 and WASM ABI version. Cache hits no longer read or
  transfer the worker artifact again within a runtime generation, and release
  builds preserve every recency-index mutation required for bounded eviction.
- Add `performance-evidence-v1` as a released machine contract. Full and release
  gates measure runtime concurrency, cache behavior, cancellation, event-driven
  streams, SQLite reads, keyed reconciliation, real Chromium rendering, and
  long tasks; every runtime bundle includes the resulting evidence before
  manifest hashing and signing.
- Extend immutable performance evidence with paired namespace allocation, HTTP
  keep-alive P95, package `MaxRSS`, SQLite authorization scaling, and real
  operation/stream `MemoryStore` snapshot measurements, plus bounded IPC burst,
  indexed scheduler, module-cache eviction, and fixed-capacity UDP limiter
  structural evidence.
- Add the closed `resource-scope-v1` ownership contract for host-issued user and
  environment scopes. Persistent ownership excludes short-lived session and
  channel hashes and rejects undeclared or ambiguous owner fields.
- Add explicit route and direct Host authorization contracts. HTTP requests pass
  authentication, origin, CSRF, and closed-action authorization, while embedded
  Host calls enforce the same platform action, resource, and session-derived
  owner boundary across surfaces, assets, RPC, confirmations, operations,
  streams, runtime management, data, settings, secrets, and platform metadata.

### Changed

- Bound the runtime IPC writer to an explicit 136-frame maximum derived from
  validated limits, batch at most 64 frames or 256 KiB per flush, propagate
  closed/write/flush/panic failures through stable process exit codes, and map
  those codes without stderr parsing in the Go supervisor. Rust IPC now exposes
  one typed `parse_frame_identity` API without a versioned alias.
- Make namespace usage cache misses share lifecycle-owned loaders whose database
  leases are released before completion is published, so waiter cancellation
  cannot cancel shared work and lifecycle mutations cannot observe stale
  namespace database references.
- Release per-plugin scheduler capacity before publishing a completed worker
  response, so an immediately following invocation cannot observe stale active
  state and receive a spurious capacity denial.
- Consolidate plugin-data workspace finalization and export verification into a
  symlink-safe rooted tree snapshot that reuses canonical hashes, file sizes,
  and entry metadata while failing closed on post-hash filesystem changes.
- Separate Go Host/domain DTOs from every HTTP request and response projection.
  Closed wire decoders now map release and secret inputs explicitly, public
  registry, permission, settings, operation, runtime, surface, intent, data,
  and diagnostics responses own recursively cloned values, and internal owner,
  bridge-channel, permission-actor, IPC-channel, connection-nonce, clock, and
  reader fields cannot enter the public contract through automatic JSON
  serialization.
- Index owner-scoped SQLite security-policy allowlists and denied methods as
  transactional relations so authorization reads only the requested method and
  permission IDs, reject partially missing relation schemas, remove redundant
  authorization indexes already covered by composite primary keys, and reduce
  SQLite stream delivery to one state snapshot before bounded event selection
  and pending-delivery mutation.
- Bind immutable plugin-data export objects to the authenticated resource scope
  and `plugin_instance_id` across catalog keys, disk paths, manifests, Host APIs,
  and HTTP/TypeScript requests. Cross-plugin access now returns not found, and
  existing rows or layouts without reliable plugin ownership require explicit
  owner-scope migration.
- Unify ambiguous persisted-owner failures across registry, plugin data,
  install stages, and secrets under the machine-readable
  `owner_scope_migration_required` sentinel. Runtime HTTP projections use the
  stable `PLUGIN_OWNER_SCOPE_MISMATCH` contract and never infer an owner.
- Replace unbounded package materialization and Base64 local imports with
  positive immutable read limits, bounded `ReaderAt` artifact descriptors,
  streaming package uploads, metadata-only worker hot paths, and symlink-safe
  rooted asset access.
- Replace package file cloning with explicit owned AssetStore writes. ZIP
  writers borrow caller packages without mutation, while successful or failed
  owned writes consume the materialized file maps and retain only one payload.
- Normalize every adapter result and business-error detail into a JSON data tree
  before redaction and response-schema validation, failing closed for cycles and
  non-JSON values without mutating the adapter-owned input.
- Require capability targets, execution bindings, operation and stream records,
  direct Host parameters, and business-error details to use the closed canonical
  Go JSON value set. A shared bounded recursive clone now owns every nested map
  and slice without JSON round trips; the public copy APIs are
  `CloneTargetDescriptor` and `CloneExecutionBinding`, each Host adapter receives
  an independent execution snapshot, cancellation is re-derived from the active
  lease, target resolution cannot mutate invocation arguments, execution revisions
  and quotas are bounded to JavaScript-safe integers, SQLite reopen uses a closed
  number-preserving decoder with exact binding IDs, and `NewBusinessError` returns
  validation errors instead of retaining unsupported or aliased adapter values.
- Bundle external JSON Schemas structurally into namespaced OpenAPI components;
  generated TypeScript contracts now preserve manifest, capability pin, and
  settings patch types without `$defs` leakage or `unknown` collapse.
- Replace append-and-copy in-memory observability retention with fixed-capacity
  rings and replace SQLite retention scans with bounded sequence-range deletes.
- Replace serialized runtime invocation IPC with one reader, one serialized
  writer, request routing by `request_id`, and runtime-origin hostcalls bound to
  their signed invocation through `parent_request_id`.
- Replace the global Host management lock with reference-counted per-plugin
  lifecycle read/write locks and optimistic release resolution, so unrelated
  plugins can install, update, open surfaces, and read streams concurrently.
- Replace polling stream reads with required `Observe` and revision-aware `Wait`
  store contracts. Memory streams now use per-stream locks and notifications;
  SQLite schema v4 persists revision, next sequence, and event counters and
  performs bounded batch reads without `MAX(sequence)` scans.
- Bound every stream by both bytes and event count. The default event limit is
  4096, the platform maximum is 65536, and either limit produces deterministic
  backpressure.
- Advance rendering to `plugin-ui-v5`: deterministic keyed text nodes,
  key/anchor structural patches, O(n log n) LIS reconciliation, copy-on-write
  validation, and atomic animation-frame DOM commits while preserving focus,
  IME, scroll, canvas, edit-revision, and first-commit behavior.
- Advance the coordinated public contract set to `plugin-host-v4`,
  `rust-ipc-v4`, `plugin-ui-v5`, `bridge-v5`, `plugin-platform-v6`,
  `manifest-v5`, opaque document v3, opaque transport v4,
  `release-metadata-v5`, compatibility manifest v6, `error-codes-v4`,
  `resource-scope-v1`, token/ticket v3, and release manifest v4. WASM ABI v2,
  worker invocation v3, and package signature v1 remain unchanged.
- Make `PluginPlatformClient.openSurfaceInSlot(...)` the only public trusted-parent
  opening path. Raw bootstrap opening, caller-created surface hosts, and direct
  slot adoption are no longer public API; replacement waits for the previous
  surface to revoke before a fresh iframe is created.
- Bind handle grants, storage and network hostcalls, and runtime revocation to
  authenticated resource scopes. Runtime revoke epochs are isolated by
  environment owner and plugin instance, and plugin input cannot override
  lease-derived owner fields.
- Regenerate the examples, scaffold, browser harness, Go DTOs, TypeScript
  contracts, Rust constants, fixtures, compatibility hashes, and release
  verification around the v6 platform contract.
- Carry explicit mutation outcomes through trusted-parent errors. Pre-aborted
  requests, body serialization failures, and synchronous fetch rejection are
  `not_committed`; failures after fetch returns a promise are `unknown`.
  `PluginMutationLifecycleError` retains that outcome when local teardown or
  shell observers also fail.
- Make generated and example plugin workers treat bridge disposal as an explicit
  lifecycle boundary: they stop scheduling renders before pending work is
  rejected and consume only the typed disposal error during startup teardown.
- Validate worker VNode tags, attributes, input types, and render limits against
  the generated opaque-surface policy before emitting a mount or patch.
- Add deterministic parallel surface replacement, first-commit visibility,
  structured quiesce timing, and reliable lifecycle persistence acknowledgments.
- Update the examples and scaffold to stable VNode keys, a single-call Memos
  bootstrap, and an explicit fresh/stale/expired SQLite forecast cache.
- Use Registry authorization snapshots and one generation-based PluginData
  authority for settings, storage, retained bindings, permissions, and policy.
- Require capability preflight plans to use the closed
  `redevplugin.capability.risk_plan.v1` contract, and resolve capability adapters
  only by exact signed contract pin.
- Replace the type-specific response redaction policy with
  `capability.PrepareResponseData`: adapter results and business-error details
  now pass through one fixed JSON normalization and redaction boundary before
  response-schema validation. Native Go trees are structurally budgeted before
  encoding, and both encoded input and the final redacted tree are strictly
  size- and shape-checked. Stateful custom `IsZero` response semantics are
  rejected without invocation.

### Fixed

- Persist only closed diagnostic and audit fields with typed failure code,
  component, operation, request/correlation identity, and mutation outcome.
  Public Host, HTTP, OpenAPI, and TypeScript diagnostic projections use closed
  typed details plus a dedicated committed/not-committed/unknown outcome enum;
  internal failure metadata and owner/session hashes never enter the response.
  Adapter and runtime causes, bearer/cookie values, URL queries, secret
  references, private runtime identifiers, and absolute paths are rejected at
  memory and SQLite sink boundaries; invalid persisted rows fail reopen.
- Make published npm integrity readback execute the same strict v4 manifest,
  version, source-commit, archive-matrix, and bundle verification as the release
  verifier. Release manifests now reject open or unordered file entries instead
  of normalizing them during verification.
- Inspect runtime, npm, and Worker SDK archives before extraction. Release
  verification now rejects wrong or multiple roots, top-level files, links,
  special files, duplicate members, and traversal paths before unpacking any
  bytes.
- Assert JSON Schema string formats in Go contract tests and use one strict
  RFC 3339 validator across performance evidence and release bundle tooling;
  invalid calendar dates, times, offsets, and timezone-free values fail closed.
- Bind environment-sensitive performance thresholds to explicit evidence runs.
  Normal debug, race, and property suites still exercise bounded queues and
  performance probes, while release evidence keeps the published thresholds
  unchanged.
- Make every HTTP route action map to an exact direct Host action, including
  surface preparation, bridge minting, asset and stream reads, RPC and
  confirmation flows, and platform metadata. Nested surface preparation and
  surface-scoped cancellation now enter private already-authorized
  implementations instead of repeating or bypassing Host authorization.
- Project every direct Host authorization as canonical typed primary and related
  resource targets. Persistent targets carry only Host-derived user or
  environment scopes, collection targets are explicit, and resource-specific
  targets cannot use empty or non-canonical identifiers.
- Require hosts to choose `plugin_instance_id` before local or release install;
  package APIs, HTTP, OpenAPI, and TypeScript no longer derive an implicit
  instance identity from package contents.
- Authorize release updates and intent invocation before registry or release
  discovery, and carry one canonical plugin instance identity through release
  policy, artifact resolution, trust verification, lifecycle locks, registry,
  and TypeScript surface teardown.
- Treat only explicit `ErrActionDenied` results from `AuthorizationAdapter` as
  policy denials. Operational adapter failures are redacted and exposed through
  the stable `PLUGIN_ADAPTER_FAILURE` contract instead of being mislabeled as
  permission failures.

- Require a private Host attestation before the HTTP adapter can expose a
  published capability business error. Business errors that bypass the exact
  capability validation path, including wrapped, joined, typed-nil, or forged
  values from other adapters, now fail closed as contract mismatches.
- Project adapter failures once into an immutable Host-owned RPC error before
  cleanup, rejection reporting, or HTTP mapping. Only allowlisted stable errors,
  RuntimeManager-attested worker failures, capability-attested business errors,
  and explicit mutation outcomes survive; adapter error objects and messages do
  not.
- Bind each immutable Host RPC error proof to the call that created it. A
  capability, CoreAction, target, or runtime adapter cannot replay a previously
  attested capability or worker failure into a later call.
- Bound trusted-parent error responses with the same bridge message limit as
  success responses and return `PLUGIN_JSON_LIMIT_EXCEEDED` without oversized
  details instead of allowing the sandbox receiver to time out silently.

### Removed

- Remove the direct `Host.ExchangeAssetTicket` entry point and its misleading
  request name. Hosts now use the single authorized
  `Host.PrepareSurface(PrepareSurfaceRequest)` operation, which atomically
  exchanges the ticket, validates the owner-bound asset session, and prepares
  the opaque document.
- Remove CLI release, SurfaceCatalog, and CoreAction placeholder adapters; CLI
  and example hosts now declare only modules they actually provide.
- Remove IPC v2 decoding, UI v4 rendering, polling stream stores, and legacy
  renderer compatibility paths. Current schemas reject incompatible
  Host/runtime/UI combinations without alternate decoders.

## v0.4.3

### Changed

- Memos is redesigned as a focused consumer notebook instead of an internal
  dashboard. It now uses a calm library-and-editor layout, pinned and recent
  groups, cancellable instant search, a distraction-free writing canvas,
  mobile-first list/editor navigation, and deliberate deletion confirmation.
- The Memos example now uses debounced autosave with immediate unsaved, saving,
  saved, and failure states. Failed persistence keeps the draft editable and
  blocks navigation, surface quiesce flushes the active draft, and destructive
  actions serialize with in-flight saves so notes cannot reappear after delete.
- The trusted renderer now serializes ARIA boolean attributes explicitly and
  keeps keyboard focus inside an active `aria-modal` dialog. Memos disables its
  background controls while deletion confirmation is open and restores focus
  when the user cancels.
- Browser acceptance coverage now verifies desktop and compact Memos layouts,
  title focus, readable editor width, stale-search rejection, search and pin
  behavior, deletion focus containment and failure recovery, autosave failure
  recovery, quiesce persistence, and the focused notebook information hierarchy.

## v0.4.2

### Fixed

- A2 browser acceptance evidence is now generated and release-validated through
  one shared contract. The live Chromium harness records the credentialless
  mode, strict request allowlist, absent WebSocket and Service Worker activity,
  opening and lazy-asset timing, real stream redemption, confirmation abort on
  surface disposal, and completed server-side disposal before release signing.

## v0.4.1

### Fixed

- The release stress job now installs the pinned Rust toolchain's
  `wasm32-unknown-unknown` target before the browser harness builds canonical
  example and scaffold workers. Release workflow contract tests enforce this
  ordering so a clean GitHub runner cannot reach the WASM build without its
  required target.

## v0.4.0

### Added

- A product-quality Examples Showcase that runs three installable plugins
  through the real Go Host, HTTP adapter, Rust runtime, opaque sandbox surface,
  and typed bridge: persistent Memos, saved-location Weather with brokered
  external HTTP, and the canvas-based Sky Strike game with keyboard, pointer,
  score, high-score, and FPS behavior.
- A public Rust worker SDK for ABI v2 request decoding, closed success/error
  responses, base64 helpers, storage file/KV/SQLite hostcalls, network
  hostcalls, and canonical worker exports. Every runtime bundle includes the
  same versioned `.crate` source artifact with first-class release-manifest
  identity and an immutable Git tag dependency guide.
- Host-mediated canvas and image surface primitives, with generated render
  policy limits and tests covering pointer input, animation, asset decoding,
  and deterministic disposal.
- Dedicated internal browser-harness and testdata trees so user-facing examples
  contain only usable plugins while conformance fixtures remain clearly
  separated from product demonstrations.

### Changed

- Worker execution now uses `redevplugin-wasm-worker-v2`: exported linear
  memory, allocator/deallocator functions, JSON request/response envelopes, and
  `(request_ptr, request_len) -> packed(response_ptr, response_len)` invocation.
- Storage handle grants are minted and injected by the Host for declared stores;
  plugins no longer receive or submit grant tokens through method parameters.
- `redevplugin examples-server` serves the product examples. URL state preserves
  the selected example across refresh and browser history,
  while desktop and mobile layouts share the same runtime behavior.
- The CLI scaffold emits one ABI v2 Rust worker and generated browser worker
  through a single canonical build path.
- Platform release bundles now use `redevplugin.release_manifest.v3`. The npm
  tarball and Rust worker SDK crate are each built once, embedded byte-for-byte
  in every runtime target bundle, and verified for cross-bundle identity.

### Fixed

- Sandboxed form submission now resolves nested content inside submit buttons,
  prevents native navigation, and dispatches one typed form action with bounded
  form data.
- Memos no longer exposes a completed save state before the active persistence
  promise has settled, preventing rapid new-note navigation from editing the
  previous memo.
- Memos now keeps a failed draft in the editor until persistence succeeds,
  Weather replaces the selected place only after a fresh forecast succeeds,
  and compact layouts keep primary controls within reachable touch targets.
- Sky Strike owns one cancellable frame timer, stops drawing while its surface
  is hidden, resumes from a fresh frame timestamp, and publishes phase, score,
  lives, FPS, and controls through the typed canvas accessibility contract.
- Showcase navigation retains focus while the previous sandbox surface
  quiesces, and Sky Strike releases stale pointer targets when keyboard control
  takes ownership.
- Release preflight now fails before packaging when the Git tag, first
  changelog release, Go compatibility floor, or canonical Worker SDK Cargo
  version disagree. The SDK package runner also compiles the extracted crate
  for `wasm32-unknown-unknown` before publication.
- Example and scaffold worker generation now emit canonical Linux/amd64 WASM
  through one path-remapped builder with a pinned compiler, clean target,
  isolated Cargo home, environment allowlist, immutable Docker image digest,
  recursive Cargo source snapshots, and native/Docker CI parity. External Cargo
  configuration, host-specific checkout, registry, cache, flags, or LLVM output
  cannot change accepted bytes, while stale or concurrently edited source and
  binary inputs still fail closed.
- Release SDK packaging installs the WASM target before checking scaffold
  assets, and every runtime bundle verifies the embedded scaffold even when it
  consumes a prebuilt npm tarball. Worker SDK packaging resolves and verifies
  dependencies in its own temporary Cargo home instead of relying on cache
  state left by an earlier build step.

### Security

- Plugin UI remains in a unique opaque-origin `sandbox="allow-scripts"` iframe;
  plugin code cannot access the parent DOM, cookies, browser storage, direct
  network APIs, or bearer credentials.
- Broker hostcalls accept only bounded request/response memory ranges, and the
  Rust runtime validates closed ABI v2 worker responses before returning data
  to the Host.
- Package validation compiles the complete WASM module with Wazero, while the
  Rust runtime independently validates all sections with `wasmparser` before
  export inspection or execution. Runtime `memory.grow` remains fenced by the
  signed invocation memory budget, and manifests cannot request more than the
  256 MiB platform ceiling.
- Surface shutdown sends a bounded quiesce request and waits up to 1.5 seconds
  for async plugin lifecycle observers to finish persistence before revoking
  the frame. A private 10-second renderer-worker heartbeat with a 5-second ACK
  deadline fails closed on a stalled worker.
- The trusted renderer enforces generated Canvas and decoded-image budgets:
  four canvases, 4096 pixels per dimension, 16,777,216 total canvas pixels, 120
  pointer events per second, 32 images, and 33,554,432 decoded image pixels.
  Raster images are identified from their bytes rather than filenames or MIME
  declarations. Plugin workers cannot construct extra `OffscreenCanvas` or
  image bitmaps.
- File, KV, and SQLite quota failures map to the same stable
  `PLUGIN_STORAGE_QUOTA_EXCEEDED` platform error and HTTP 413 status.
- `wasmi` uses portable dispatch for stable native debug and CI execution while
  retaining fuel limits, memory limits, signed leases, revoke epochs, and
  broker policy enforcement.

## v0.3.2

### Fixed

- Published-release verification now reads the exact TypeScript version,
  registry URL, and SRI from each bundle's `notices/package-lock.json`, installs
  that compiler inside the standalone temporary consumer, verifies the
  consumer lock identity, and invokes only the consumer-local `tsc`.
  Verification no longer depends on checkout-root `node_modules` state.
- The published-release verifier regression runs copied verifier scripts from
  an isolated temporary root with no repository dependencies. Normal branch CI
  runs that matrix, and mutation coverage rejects non-exact or malformed
  versions, non-official registry URLs, invalid or mismatched SRI, and missing
  TypeScript lock entries.
- Full and release stress gates start from `npm ci`; signed release stress
  evidence fails closed unless the standalone published-release verifier is
  present and successful alongside every other required release step.
- `v0.3.1` produced the signed GitHub Release, npm package, and four runtime
  bundles, but its final workflow stopped before registry readback because the
  verifier job had no checkout-root TypeScript installation. `v0.3.2` is the
  first A3 release coordinate whose complete Actions and public-readback train
  is designed to finish independently of ambient repository dependencies.

## v0.3.1

### Fixed

- Release stress validation now runs against the exact summary produced by
  `check_redevplugin_stress.sh --release` before signing or publication, using
  the same validator as downloaded GitHub Release assets.
- Stream backpressure evidence verifies terminal audit ownership at the scoped
  adapter sink. The Host subscription regression explicitly proves that sink
  closure records `plugin.stream.closed`.
- ZIP fixtures sort map-backed paths before writing entries, eliminating the
  case-fold collision diagnostic flake seen in the first A3 main CI run.
- The `v0.3.0` tag published the npm package but did not produce a GitHub
  Release because the signed stress summary and verifier expected different
  counter sets. `v0.3.1` produced the complete signed artifact set, but its
  final published-release verifier still depended on checkout-root TypeScript
  state.

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

### Security

- Plugin iframes now use a generated `srcdoc` with exactly
  `sandbox="allow-scripts"`, a unique opaque origin, and a fail-closed CSP.
- `PluginPlatformClient.openSurfaceInSlot(...)` creates and owns each fresh
  hardened iframe through a scope-bound opening lease; callers cannot obtain a
  raw bootstrap, adopt prepared options, or provide a pre-existing frame.
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
