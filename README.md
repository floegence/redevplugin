# ReDevPlugin

ReDevPlugin is the reusable plugin platform intended to be consumed by host
products through published Go modules, npm packages, Rust source crates, and
machine-contract artifacts. ReDevPlugin publishes versioned source crates for
the Rust runtime; host products build the runtime binary from exact
published Rust source crates and own the resulting product artifact.

This repository owns the host-neutral plugin platform core. Host products own
their product policy, UI shell integration, session adapters, and business
capabilities.

## Current Platform Snapshot

- Platform version source: `VERSION` (`3.0.0`)
- Go module: `github.com/floegence/redevplugin/v3`
- TypeScript packages: the opt-in raw contract body package
  `@floegence/redevplugin-contracts` and the sandbox/runtime SDK
  `@floegence/redevplugin-ui`
- Rust workspace and publication set: exactly `redevplugin-runtime` and
  `redevplugin-worker-sdk`
- Plugin author compatibility: manifest v9 with `plugin_api=1`. Older manifests
  and parallel UI/WASM compatibility axes are rejected rather than normalized.
- Host/runtime compatibility: `internal_wire=1`, checked once by the exact
  Hello/HelloAck handshake. Ordinary frames carry no version field.
- Canonical contracts use fixed paths, including
  `spec/openapi/plugin-platform.yaml` and
  `spec/internal/runtime-wire.schema.json`.
- Each release publishes one signed, staging-generated
  `PlatformReleaseManifest` containing the exact hashes of the Go, npm, crate,
  and contract artifacts. The manifest is not checked into an artifact whose
  hash it contains.
- The contract libraries also expose canonical release-signing DTOs and
  build, preimage, strict-decode, and verifier APIs for root delegation,
  packages, release metadata, source policy and its pointer, and revocation and
  its pointer. The seven signing usages are domain separated, timestamps are
  explicit inputs, and pointer genesis is fixed to epoch `0` plus the all-zero
  SHA-256 sentinel. These APIs live in `pkg/releasecontract` and the opt-in
  contracts packages; `pkg/releasetrust` consumes the one canonical release
  metadata contract.
- Source policy and revocation documents remain mutable security facts. They do
  not create an additional platform compatibility matrix.

## Localized Plugin Presentation

Manifest v9 requires an author-owned presentation catalog. The default locale
uses the manifest's plugin, publisher, surface, setting, and option labels;
authors may add up to 15 complete localized records. Localizations are keyed by
canonical BCP 47 tags and must cover every translatable field without missing,
extra, or duplicate surface, setting, or option references.

ReDevPlugin validates author text as NFC-normalized Unicode plain text, includes
the complete catalog in the canonical manifest and signature boundary, and
projects a normalized catalog plus its SHA-256 digest from verified inspection
and installed inventory APIs. The Go and TypeScript resolvers use exact match,
RFC 4647 parent lookup, then the author-declared default locale. They do not add
an English fallback or mix locales within one resolved presentation.
- `redevplugin release prepare`, `apply-signature`, `finalize`, and `verify`
  provide a resumable publisher flow for signed packages, release metadata,
  source policy, revocation, root delegation, and current release signatures.
  The external signer exchange contains only public key identities, signing
  subjects, preimage digests, and signatures; signer storage and invocation
  remain entirely outside this repository and its configuration.
- `pkg/remoterelease` adapts one reviewed, content-addressed release asset set
  to the release-document and Host artifact resolver
  interfaces. Downloads reuse `pkg/externalsource` public-DNS validation,
  pinned dialing, TLS verification, redirect checks, exact host allowlists,
  byte ceilings, and SHA-256 readback. A bounded in-memory content-addressed
  cache is shared by Host operations using that asset set; every hit revalidates
  size and digest, and corrupt entries are discarded and fetched again. Host
  products can therefore download packages directly from the release provider
  without a registry proxy.
- Host-neutral Go package boundaries for manifest validation, package IO,
  registry, host adapters, bridge, PluginData, runtime supervision, grants,
  capability adapters, HTTP routes, session context, and web security.
- Host capability contracts are published as signed exact-pin bundles containing
  a restricted schema, compatibility metadata, generated plugin-side client,
  notices, manifest, and signature. The Host verifies source-policy key usage,
  every file digest, publisher identity, compatibility floor, and the complete
  pin before a package can bind the capability. Capability artifact adapters
  declare each file as either a host-provided artifact with no network chain or
  a registry artifact with request-bound public-network evidence; missing or
  contradictory origin evidence fails closed.
- `plugindata.FileStore` is the single data authority behind lifecycle,
  non-secret settings, files, KV, SQLite, retained bindings, and opaque export
  bundles. It resolves every request through the current registry binding,
  enforces quotas and filesystem boundaries, and publishes generation changes
  with semantic revision checks.
- The settings package defines schema normalization and validation only.
  PluginData persists non-secret values with a values revision; the independent
  SecretStore contributes redacted binding metadata and never enters an export
  bundle.
- The Host-owned control database stores asynchronous work as one Execution and
  its ordered Events. Cursor reads are bounded by event and byte limits, waiters
  are notified without polling, and disable/uninstall transitions fence the same
  execution identity. Unknown or newer schemas fail closed.
- Observability stores include both in-memory and SQLite-backed implementations.
  Audit events are append-only through the host adapter contract. Owner-scoped
  diagnostic listing preserves filtering, defaults, newest-first ordering,
  retention limits, and generated event IDs across idempotent reopen.
- Secret binding stores include both in-memory and SQLite-backed
  implementations. They persist only plugin-instance, scope, secret-ref, bound
  state, and test/delete metadata, never secret plaintext, so hosts can keep the
  actual vault implementation product-owned while reusing common lifecycle
  state, filtering, cleanup, and durable current-schema storage.
- Confirmation intent stores include both in-memory and SQLite-backed
  implementations. They persist the server-held intent metadata and
  confirmation token id, request hash, plan hash, and expiry, but not the raw
  confirmation token; after a process restart, missing token-manager state makes
  any recovered intent fail closed instead of silently confirming.
- Host lifecycle APIs include idempotent `RecoverEnabled`, which lets an embedding
  product restore enabled plugin runtime state after restart by replaying
  connectivity policy installation and
  surface publication from the durable registry without re-enabling plugins.
  The mountable HTTP adapter exposes the same behavior at
  `POST /_redevplugin/api/plugins/runtime/recover-enabled`, so hosts can keep
  route mounting thin instead of reimplementing the refresh loop.
- Updates and downgrades require the target package to keep the exact current
  PluginData shape. A package that changes settings or storage schema must use a
  new plugin identity before release; the platform has no conversion or
  compatibility path.
- Plugin package IO keeps deterministic canonical package hashes separate from
  detached `signatures/package.sig` metadata. Signature files are retained for
  trust verification but are excluded from canonical package entries, asset
  serving, and the package hash to avoid self-referential signatures. The
  signature directory is closed-world: package IO rejects any signature entry
  other than `signatures/package.sig`.
- Package validation requires every surface entry to declare exactly one
  package-local `text/redevplugin-worker` classic bundled worker. The builder
  and trusted renderer consume one generated render policy, so unsupported
  elements, attributes, input types, URL-bearing markup, inline script/style,
  event handlers, `srcdoc`, embedded browsing contexts, excessive render trees,
  and direct Service Worker API references fail during package validation as an
  early diagnostic. Runtime hardening removes `navigator.serviceWorker` inside
  the opaque renderer/worker boundary, which remains authoritative even when a
  source-level reference is dynamically constructed. Script imports/exports are
  rejected because the worker must be a
  self-contained classic bundle. Surface icons must be packaged
  raster image assets, not SVG or external URLs, so product shells do not need
  to inline or sanitize plugin-provided SVG markup. The same validation path rejects
  shell/shebang scripts, native executable or dynamic-library artifacts,
  package-manager install lifecycle scripts, package-manager dependency fields,
  Cargo `build.rs` / build scripts, proc-macro crates, native linker
  configuration, and Cargo dependency sections so third-party packages cannot smuggle
  a native backend beside the sandbox UI and WASM workers. Package IO also
  rejects file counts, entry sizes, package-local path lengths, compression
  ratios, and total uncompressed sizes beyond configured limits. Validation failures
  use stable platform error codes (`PLUGIN_MANIFEST_INVALID`,
  `PLUGIN_PACKAGE_INVALID`, `PLUGIN_PACKAGE_TOO_LARGE`, or
  `PLUGIN_PACKAGE_PATH_FORBIDDEN`) and expose structured `error_details` such as
  `reason`, package `path`, and manifest JSON `pointer` through the HTTP adapter.
- Install and update flows do not accept caller-supplied `trust_state` values.
  Release-ref installs carry a release metadata ref plus hash, freeze source
  policy before artifact resolution, and then run trust assessment, while
  local-import flows carry explicit local import provenance. Runnable verified
  state requires a host-provided `PackageTrustVerifier`; unsigned local packages
  can be enabled only when host policy permits local generated plugins.
- Release inspection verifies an exact release reference before confirmation
  and returns Host-derived permission IDs, method bindings, and effects without
  installing a plugin. One `InstallCommit` atomically persists the record,
  PluginData binding, and default settings with `enable_state=enabled`. Required
  permissions are granted only when the request explicitly approves their
  signed IDs; missing grants make the affected open/capability action return
  `permission_required` without changing lifecycle state. Fetch, download,
  integrity verification, and commit progress use the shared Execution/Event
  stream. Runtime and surface publication are retryable derived work after the
  durable commit.
- External package admission accepts a public HTTPS package URL or GitHub
  repository through a process-local `inspect -> confirm -> install` transaction. The
  inspection returns immutable source, hash, signature, execution-approval,
  update-eligibility, and effective capability evidence for explicit review.
  Signature state does not decide basic manual installation: absent,
  unknown-signer, and temporarily unavailable assessments may be confirmed and
  remain manual-update-only. A successful commit installs the plugin as enabled;
  unapproved capabilities remain unavailable until the user grants them.
  Invalid or revoked signatures block installation and execution. Each opaque,
  expiring inspection stays bound to the exact authenticated owner/session; the
  installer reopens and revalidates public HTTPS, DNS, redirects, TLS identity,
  size, and exact bytes before the single Host control transaction. Only an
  explicit user disable writes `disabled_by_user`; trust, policy, permission,
  readiness, and runtime failures revoke derived resources without rewriting
  that intent.
- The host-neutral `pkg/trust` package provides an Ed25519 verifier and keyring
  interface for package signatures. Hosts still decide which keys, publishers,
  registries, or enterprise policies are trusted, but they can reuse the common
  canonical signature payload and verification checks.
- Package-signature schema tests keep `package-signature-v1.schema.json`
  aligned with the Go `pluginpkg.PackageSignature` envelope, Ed25519 algorithm
  constant, required hash fields, signature fields, and optional publisher,
  plugin, and signed-at metadata.
- The CLI can generate local Ed25519 signing keys and produce signed package
  artifacts without placing private keys in shell arguments. Start with
  `redevplugin scaffold <plugin-id> <display-name> <out-dir>`, package the
  generated UI plus one current `plugin_api=1` WASM backend worker, then sign it:
  `redevplugin keygen <key-id> <private.json> <public.json>` followed by
  `redevplugin sign <unsigned.redevplugin> <private.json> <signed.redevplugin>`.
  Development harnesses can then run
  `redevplugin install-verified <signed.redevplugin> <public.json>` to prove
  the Host trust-verifier path accepts the signed package.
- Release publishers that keep signing outside the CLI can run
  `redevplugin release prepare <config.json> <unsigned.redevplugin> <workspace>`,
  apply each closed response with
  `redevplugin release apply-signature <workspace> <response.json>`, then run
  `redevplugin release finalize <workspace> <out-dir>` and
  `redevplugin release verify <out-dir>`. For a declared presentation icon,
  `redevplugin release extract-presentation-icon <out-dir> <out-file>` repeats
  full release verification before writing the exact verified image and refuses
  to overwrite an existing target. Repeating a completed step with the same
  bytes is idempotent; a changed request, response, or output fails closed.
  Current release verification binds each response to its exact Ed25519 key,
  usage, and canonical signing preimage. SHA-256 or signature mismatches fail
  before publication.
  Capability contracts and exact pins are part of the host's closed local
  registry. ReDevPlugin validates that registry at startup and does not resolve
  or publish capability bundles through an independent distribution channel.
- `testdata/generated_plugins/minimal`, `networked`, `storage`, and
  `method-contract` are positive generated-plugin fixtures that the platform
  gate validates and packages through the same CLI path. `method-contract`
  covers dangerous confirmation, atomic confirmation rejection, risk preflight,
  asynchronous cancellation policy and delete-effect metadata.
  `testdata/generated_plugins/malicious-build/*`
  must fail packaging before any dependency install or build step can run.
- Mountable HTTP routes call a host-provided `websecurity.Guard` through the
  explicit `Authenticate`, `ValidateOrigin`, `ValidateCSRF`, and
  `AuthorizeRoute` stages. Every platform route requires the closed
  `trusted_host` origin policy, every unsafe method including asset and stream
  reads requires CSRF validation, and every route carries a closed
  `RouteAction`. The authenticated session and product-specific origin, CSRF,
  and authorization policy stay in the host product.
- `PluginPlatformClient.openSurfaceInSlot(...)` is the only public surface
  opening path. It owns the HTTP bootstrap, opening lease, replacement ordering,
  and fresh SDK-owned iframe, then returns a `PluginSurfaceHost` handle whose
  read-only `element` is available for product-shell metadata. The slot places
  the element and the SDK immediately applies `src="about:blank"`,
  `sandbox="allow-scripts"`, no same-origin capability, no plugin URL, and a
  fail-closed CSP. The trusted parent prepares the validated surface document,
  marks the server session prepared only after the closed document succeeds,
  transfers one secret-free `MessagePort`, waits for the current frame generation
  to acknowledge that port, then mints and applies the initial parent-only lease
  before renderer initialization. The iframe also carries an explicit
  Permissions Policy deny-list. One aggregate opening deadline covers frame
  load, prepare, acknowledgement, lease minting, first paint, and worker
  readiness; timeout revokes server state, tears down locally, and consumes one
  bounded reload-limiter attempt. It reads lazy assets and streams
  through parent-only POST routes. Asset reads accept only the opaque `binding_id`
  from the server-prepared document; the Host resolves and revalidates the bound
  registry path, size, content type, and SHA-256 against the returned bytes. Prepared documents
  allow at most 128 lazy assets and 32 MiB total, with at most four reads in
  flight. Plugin code receives opaque surface and stream handles, never
  asset tickets, stream tickets, gateway credentials, parent origins, cookies,
  or host storage.
- A trusted parent that rejects a dangerous-method confirmation first calls the
  surface-scoped rejection route. The Host validates the current gateway token,
  session, bridge channel, active fingerprint, policy/management revisions, and
  revoke epoch, then atomically removes the pending intent and records stable
  audit/diagnostic evidence before the plugin receives
  `PLUGIN_CONFIRMATION_REJECTED`.
- Contract tests that keep the Go HTTP route set, OpenAPI paths, route fixture,
  generated render policy, TypeScript SDK route coverage, and package validator
  aligned.
- Manifest v9 requires every method to declare closed request and response
  object schemas. Package validation compiles those schemas without remote
  references; Host dispatch validates requests before adapters/runtime and
  validates canonical redacted responses before returning them to plugin code.
- Manifest v9 surface declarations use only host-neutral `view`, `command`, or
  `background` kinds with optional `primary`, `secondary`, or `utility` intent.
  Activity bars, workbench panes, settings pages, and modal placement remain
  host-product decisions.
- Stable error-code contract tests keep the Go `pkg/security` catalog, OpenAPI
  envelope enum, iframe bridge schema, TypeScript SDK exports, and Rust IPC
  runtime-origin error constants aligned. The catalog separates server platform
  codes, bridge response codes, TypeScript client-side transport codes, and Rust
  IPC codes so product shells can branch on stable values without scraping
  localized messages.
- WASM author ABI schema tests keep `spec/plugin/wasm-abi.json` aligned with
  the Go package validator, Rust worker export validation, runtime linked
  hostcall modules, and the canonical worker invocation schema. `plugin_api=1`
  is the only author-visible compatibility input.
- Go package validation compiles the complete WASM module with Wazero before it
  accepts memory and export metadata. The Rust ABI crate independently runs
  `wasmparser::Validator::validate_all` before runtime execution, and the Wasmi
  store enforces the signed memory budget even when a worker calls
  `memory.grow`. The manifest platform ceiling is 256 MiB per worker; a Host
  may reject a lower value through its package trust policy.
- Plugin backend authors use the published `redevplugin-worker-sdk` crate at the
  same platform version. The signed platform release manifest binds its
  registry coordinate and checksum; hosts and plugin authors do not copy a
  bundled crate or wire a sibling checkout.
- Runtime wire tests keep startup `hello` / `hello_ack` frames bound to the
  Host-issued connection nonce, exact platform version, `internal_wire=1`, and
  runtime artifact identity, while worker invocation leases remain bound to `lease_nonce` for runtime
  replay rejection, require structured heartbeat ACK results for control-channel
  liveness, and require `revoke_epoch_ack` results to report the plugin
  instance, revoke epoch, and closed socket/stream/storage-handle counters.
  IPC golden fixtures under `testdata/contracts/ipc/` are read by Go Host tests
  and Rust IPC crate tests. They cover the current handshake/response shape plus
  Host/Rust wire mismatch, missing required fields,
  replayed request IDs, unknown frame types, and runtime-generation mismatch
  fail-closed paths.
- The current internal wire multiplexes invocations over one runtime process with one reader,
  one serialized writer, and a pending map keyed by `request_id`. Runtime-origin
  artifact and generic Hostcall frames carry `parent_request_id`, which the Go
  supervisor resolves back to the signed invocation audience before Host I/O.
  `cancel_invoke` removes queued work or marks running work canceled without
  invalidating the runtime generation. No independently versioned IPC contract
  or semantic storage/network frame family remains.
- `RuntimeLimits` is a Host-only Go configuration. Defaults derive 4-16 workers
  from `GOMAXPROCS`, cap the queue at 64, cap each plugin at 2-8 concurrent
  workers, and allow 64 compiled modules or 128 MiB of source WASM. Go waits for
  capacity before consuming an execution lease; Rust independently enforces the
  same closed bounds, including `per_plugin_concurrency <= worker_count`, with a
  fair per-plugin scheduler.
- One Wasmi engine is shared by the runtime generation. Validated modules are
  single-flight compiled and retained in a deterministic content-addressed LRU
  keyed by artifact SHA-256 and ABI version. Each invocation still receives an
  independent Store, Linker, memory limiter, and fuel budget. Health reports
  active/queued counts, effective limits, and cache hit/miss/compile/entry/byte
  metrics.
- Runtime lease replay protection is generation-local and enforced before
  worker IPC. A fresh runtime generation receives a fresh signing identity;
  duplicate leases fail closed without a local trust ledger.
- `ProcessSupervisor` generates a fresh ephemeral Ed25519 keypair for every
  supervisor instance, requires a non-empty public-key set in the startup
  `hello` frame, binds every worker lease to the current runtime audience, and
  signs every invocation. Callers cannot provide, disable, or override the
  signature or public key. The canonical payload excludes only `signature` and
  covers the display token ID, plugin metadata, active package
  fingerprint, issued timestamp, method, effect, execution mode, Host-owned
  execution id, audit correlation id, surface and owner context,
  descriptor hashes, quota limits, policy and management revisions, revoke
  epoch, expiry, `lease_nonce`, `key_id`, and runtime audience fields.
  The Go supervisor verifies that exact audience and signature before IPC. Rust
  independently rejects a missing keyring, invalid signature, expired lease, or
  any mismatch between the signed lease and the worker invocation's plugin,
  method/effect/execution, execution identity, audit, surface/session, or runtime
  binding before replay-cache consumption or artifact open. Worker-route
  dispatch emits a `plugin.runtime.lease.issued` Host audit event with
  lease/token IDs, runtime IDs, revision bindings, descriptor hashes, and expiry
  metadata.
- Rust runtime control-channel freshness is enforced inside the runtime as well
  as by the Go supervisor. After the heartbeat max-staleness window expires, the
  Rust runtime rejects new worker invocations before opening artifacts and
  rejects new storage/network broker hostcalls before dispatching Host IO.
- The Go runtime supervisor gives every runtime-origin hostcall a bounded
  context before invoking host adapters. Storage and network calls that carry
  `timeout_ms` use that value with a platform cap; artifact, handle-grant,
  storage file/KV, and network-grant calls use the default hostcall cap. The
  supervisor also sends default 2s heartbeat frames and invalidates the runtime
  when a heartbeat cannot be acknowledged within the 5s max-staleness window.
- Bridge contract checks that keep sandbox iframe message names,
  source/port-bound MessageChannel messaging, UI protocol version, and
  parent-only token boundaries aligned with the TypeScript SDK.
- The TypeScript package includes sandbox iframe bridge helpers and a host-side
  `PluginPlatformClient` for release-reference platform management routes:
  release-ref install/update, downgrade, enable/disable/uninstall, surface open, runtime
  start/health/recover-enabled/retry/stop, settings schema/read/patch, execution
  list/get/cancel, data export/import, permission grant/revoke/list, secret
  bind/test/delete, host-mediated intent list/invoke, and owner-scoped diagnostic
  event list. Audit events remain an internal host adapter contract and are not
  exposed by the generic HTTP/TypeScript platform surface. The raw package
  import/update surface is intentionally separated into
  `PluginLocalImportClient`, exported only from
  `@floegence/redevplugin-ui/local-import`, for explicit dev/admin local-import
  route sets. List helpers preserve the same data wrapper fields returned by the
  Go HTTP adapter, such as `executions`, `permissions`, and
  `diagnostic_events`, so host products can consume the SDK and raw HTTP contract
  consistently. The browser harness uses the platform client from the host page to
  exercise settings management without exposing management
  credentials to the sandboxed iframe. Host pages can also use
  `PluginSurfaceReloadLimiter` to cap consecutive automatic iframe reloads
  after crashes or load failures before showing a host-owned error state.
- Dispose uses a private quiesce/ack lifecycle. The SDK waits up to 1.5 seconds
  for async plugin lifecycle observers to flush state before revoking the
  surface, while a renderer-worker ping/pong heartbeat detects a stalled worker
  on a 10-second interval with a 5-second response deadline.
- Generated render policy limits a surface to four canvases, 4096 pixels per
  dimension, 16,777,216 total canvas pixels, and 120 pointer events per second.
  Raster type is detected from PNG, JPEG, GIF, or WebP bytes rather than the
  filename or declared MIME. Images are dimension-checked before decode and
  limited to 32 images and 33,554,432 decoded pixels. Plugin workers cannot
  allocate additional `OffscreenCanvas` instances or call `createImageBitmap`
  directly. Canvas apps use `updateCanvasAccessibility(...)` to bind concise
  live phase, score, lives, FPS, and control descriptions to the declared
  canvas without gaining general DOM mutation access.
- Typed form actions prevent sandbox navigation and serialize at most 128
  bounded string fields. Submit buttons work consistently when the click lands
  on nested icons or labels.
- The npm API boundary is split into six auditable entrypoints. The package
  root and `@floegence/redevplugin-ui/trusted-parent` expose the same
  trusted-parent allowlist for host shells. `@floegence/redevplugin-ui/plugin`
  exposes exactly six runtime values to untrusted plugin worker bundles:
  `PluginBridgeClient`, `PluginBridgeError`, `callCapabilitySync`,
  `callCapabilityOperation`, `callCapabilityStream`, and
  `isCapabilityBusinessError`. Stream decoding remains an internal detail of
  the typed capability helpers and is not a plugin entrypoint export.
  `@floegence/redevplugin-ui/jsx-runtime` and `jsx-dev-runtime` expose only the
  restricted automatic JSX VNode constructors and Fragment rejection marker;
  they do not expose DOM or trusted-parent capabilities.
  `@floegence/redevplugin-ui/local-import` exposes the explicit dev/admin raw
  package client and must not be imported by official release-reference product
  paths. The opaque bootstrap HTML factory remains internal and is not exported
  by any public entrypoint.
- Execution cancellation is a durable Host decision: `CancelExecution`
  records `cancel_requested`, emits audit evidence, and signals the live
  execution lease. The lease captures an optional route-local cancellation hook
  from the capability adapter, core action, or runtime supervisor when execution
  starts. An inactive persisted execution is never redispatched through a
  global registry lookup; its durable cancellation remains observable.
- Every asynchronous method returns one Host-owned execution ID. Progress,
  output, and terminal state are ordered Events under that identity and cursor.
  Any internal byte-stream handle remains an implementation detail and cannot
  create a second public lifecycle. Generated business-error guards also bind
  the capability ID, capability version, and details-schema SHA-256.
- Event reads use a cursor to prevent lost wakeups, wait without holding plugin
  lifecycle locks, and revalidate registry and token audience after each wait.
  Terminal state and the final event commit atomically in the Host-owned control
  database, so restart cannot expose contradictory public identities.
- Dangerous method confirmation uses server-held one-time intents. When a method
  declares a risk preflight method, the Host runs that read-only sync preflight
  during confirmation preparation, returns the redacted plan plus `plan_hash` to
  the trusted parent, and binds both `request_hash` and `plan_hash` into the
  parent-only confirmation token audience. The raw confirmation token is never
  returned to parent JavaScript, written to the confirmation intent store, or
  exposed to the sandboxed iframe.
- Capability adapters can return `capability.RiskPlan` from preflight methods to
  use the host-neutral `redevplugin.capability.risk_plan.v1` contract. The Host
  requires the current schema version, validates and normalizes the closed typed
  plan before hashing it, and rejects unknown or invalid risk fields fail-closed.
  The TypeScript SDK exports matching `PluginRiskPlan` / `PluginRiskFlag` types plus
  `isPluginRiskPlan()` so trusted parent UI can render the typed plan without
  brittle ad hoc shape checks.
- Capability, worker, and core-action method results pass through the Host-owned
  `capability.PrepareResponseData` boundary before they are returned to the
  plugin surface or HTTP adapter. The boundary budgets native Go structures
  before marshaling, converts their encoded representation to an independent,
  bounded JSON data tree, rejects ambiguous or non-JSON values, redacts
  sensitive keys plus container-shaped env, label, and mount secret values, and
  then revalidates the final tree against the same closed limits. Custom
  marshalers remain trusted host-adapter code: the platform bounds and validates
  their output but cannot isolate allocations or CPU used inside those methods.
  Response structs may use reflective `omitzero`, but custom `IsZero` methods are
  rejected because a second observation could change the wire shape.
  Business-error details use the same path and are exposed
  only after the Host attests them against the published capability contract.
  Adapter failures are likewise projected once into an immutable Host error:
  stable platform classifications and validated public details are preserved,
  while the original error graph and adapter-controlled error text are discarded
  before cleanup, diagnostics, or HTTP mapping.
- `VERSION` is the only editable platform-version source. Release checks require
  exact equality across the `/v3` Go module, npm packages, Rust crates, OpenAPI,
  tag, and registry readback.
- `scripts/generate_platform_release_manifest.mjs` runs only after the package
  artifacts have been frozen. It emits deterministic canonical bytes into an
  external staging directory, with top-level `platform_version`, `plugin_api`,
  `internal_wire`, and sorted `{name, sha256}` artifacts. The signed release
  asset is the one release index; no checked-in contract registry, package set,
  compatibility matrix, runtime descriptor, or performance publication is a
  second source of truth.
- The target-classifier fixtures remain executable security tests for public
  DNS, punycode hostnames, metadata hosts, RFC1918/ULA/link-local addresses, and
  IPv4-mapped IPv6 private addresses. They are security inputs, not independent
  compatibility axes.
- Connectivity brokers compile manifest-declared HTTP, WebSocket, TCP, and UDP
  connectors into grantable policies. The host-neutral network executor now
  consumes short-lived connection grants and performs bounded HTTP
  request/response calls, HTTP response streaming into the Host stream store,
  plus WebSocket, TCP, and UDP round trips with explicit timeout, cancellation,
  request-size, response-size, chunk-size, and stream-buffer limits. It revalidates
  grant expiry, transport, destination, and the target classifier at execution
  time so UI bridge calls and backend worker hostcalls can share the same
  fail-closed network boundary. Grants with an unknown target-classifier
  identity are rejected before any dial or broker dispatch. IPv4-mapped IPv6
  literals and resolved addresses are unmapped
  before blocked-range checks so mapped loopback/private/link-local targets
  cannot bypass IPv4 CIDR policy. Long-lived WebSocket subscriptions remain tied
  to the streaming envelope contract instead of the one-shot round trip API.
- Host tests include black-box runtime subprocess paths that invoke workers
  through the same `redevplugin.io` contract used by published plugins. They
  cover Host-owned storage namespaces plus bounded HTTP, WebSocket, TCP, and UDP
  resource operations without a second network-execute protocol.
- The Rust runtime requests a bound WASM artifact only on a compiled-module cache
  miss, validates the module through its private ABI module, executes it through
  the shared Wasmi engine and fair worker scheduler, and returns the result over
  multiplexed `invoke_worker_result` frames. Current `plugin_api=1` workers may
  import only the six functions in the `redevplugin.io` module. `rdp_call_v1`
  carries one closed `{plugin_api, operation, arguments}` envelope;
  `rdp_read_v1`, `rdp_write_v1`, `rdp_seek_v1`, `rdp_close_v1`, and
  `rdp_last_error_v1` operate on opaque resources returned by that control call.
  The runtime sends one generic Hostcall frame keyed by the signed invocation
  identity. The Host resolves that identity to the already verified method,
  permissions, resource scope, management revision, revoke epoch, and broker
  access before dispatching plugin-data storage or resource I/O. Storage files,
  KV, and SQLite remain Host-owned namespace operations; HTTP, WebSocket, TCP,
  and UDP use the same resource control/read/write path. There are no separate
  WASM storage/network imports or storage/network semantic IPC frame families.
  Before each dispatch the runtime verifies control-channel freshness and fails
  closed with `RUNTIME_CONTROL_CHANNEL_STALE` when the Host heartbeat or
  revocation window is stale. Revoke ACKs report resources actually closed by
  the runtime; purely Host-owned resources are revoked by the Host broker.
- `redevplugin inspect-data <state-root> [plugin-instance-id]` reports catalog
  bindings, export objects, namespaces, and byte/file quota usage without
  dumping plugin file contents or scanning an unowned filesystem root.
- Host data export/import uses one opaque `bundle_ref` for the complete declared
  non-secret dataset. Import validates publisher/plugin ownership, the settings
  schema, namespace kind/scope/schema version, content hash, and target quotas
  before atomically swapping the active generation. Secret bindings remain in
  the host secret store and are never included in an exported bundle.
- `redevplugin dev-install <state-root> <package>` creates a persistent local
  development state root for Flower-generated plugins. The matching
  `dev-enable`, `dev-open <surface-id>`, `dev-disable`,
  `dev-secret-bind <secret-ref> [user|environment]`,
  `dev-secret-test <secret-ref> [user|environment]`,
  `dev-secret-delete <secret-ref> [user|environment]`,
  `dev-permission-grant <permission-id>`,
  `dev-permission-revoke <permission-id> [reason]`,
  `dev-permission-list [--active-only]`,
  `dev-export-data`, `dev-import-data <bundle-ref>`,
  `dev-delete-export <bundle-ref>`, `dev-uninstall`, and `dev-status` commands
  call the real Host lifecycle APIs. The state root contains
  `registry.sqlite`, `plugin-data/`, `secrets.sqlite`, the installed package,
  and verified capability artifacts; it has no JSON mirrors of registry,
  authorization, settings, or secret state. Dev secret commands never store
  secret plaintext. Dev permission commands call the Host permission APIs, so policy
  revisions and revoke epochs move exactly as they do in an embedded host
  product. Dev data commands call the Host data lifecycle APIs and operate on
  cataloged opaque bundle refs. This gives generated plugins a local, auditable
  install -> enable -> open -> disable -> uninstall flow without importing any
  host-product internals. Dev uninstall always removes the copied package,
  plugin data, settings, secret bindings, and authorization records.
- `redevplugin examples-server <state-root> <runtime-path>` starts the
  user-facing Examples Showcase with Memos, Weather, and Sky Strike. Every
  example uses the Go Host, HTTP adapter, real Rust runtime, installable plugin
  package, and persisted plugin storage. Runtime identity is verified by the
  current Hello/HelloAck handshake; no public runtime descriptor is loaded.
  The examples server is a local
  conformance harness, not a production authentication or authorization
  implementation: it injects one synthetic session and accepts every valid
  platform action. An embedding product must provide its own authenticated
  session, origin, CSRF, and route-authorization guard. Memos is a complete
  private Markdown
  timeline: its always-available composer persists a safe draft before explicit
  publication, the feed renders controlled Markdown VNodes without admitting
  raw HTML, images, or arbitrary navigation, and search invalidates stale
  requests. Tags, local-date calendar facets, pinning, and archives share one
  bounded query contract. Published memo edits use serialized autosave; failed
  persistence preserves the active edit and blocks navigation, surface quiesce
  flushes pending drafts and edits, and compact layouts use a full-height
  explorer drawer with modal deletion confirmation. The Showcase asks
  `PluginPlatformClient.openSurfaceInSlot(...)` to create and place a fresh
  opaque `srcdoc` iframe in the selected slot; no caller-provided
  iframe, plugin server, subdomain, cookie bootstrap, GET asset
  route, or query credential exists. The trusted renderer loads a static
  validated document, starts one classic Dedicated Worker, and connects it to
  the parent through typed `MessagePort` channels. The separate
  `internal/browserharness` and `testdata/browser-harness` trees contain only
  platform conformance fixtures. `npm run test:browser-harness:smoke`
  proves opaque origin isolation, parent DOM/cookie/storage denial, blocked
  direct network and browser persistence APIs, first paint before lazy assets,
  RPC, parent-owned stream redemption, confirmation, Memos draft recovery,
  Markdown tasks, autosave, search, facets, pinning, archives, persistence,
  deletion recovery, and navigation protection, Weather
  network and saved-location behavior, atomic forecast replacement, Sky Strike
  canvas/FPS/input and semantic
  accessibility behavior,
  Rust runtime storage and network calls, and deterministic worker/iframe
  disposal. Memos requests at most 10 complete memo records per page and its
  worker clamps every caller to that same limit; a compiled-WASM regression
  proves a 61-item pinned timeline returns bounded 10-item pages and a one-item
  tail without an unbounded response. Committed
  example workers are canonical Linux/amd64 `wasm32-unknown-unknown` artifacts
  tied to the recursive local Cargo dependency source snapshot by
  `examples/plugins/worker-artifacts.lock.json`; `npm run examples:generate`
  uses an immutable Rust Docker image digest on non-canonical hosts, while
  `npm run examples:check:canonical` reproduces the exact canonical byte check. The
  CLI scaffold uses the same shared builder and records its backend worker in
  `cmd/redevplugin/scaffold_assets/worker-artifacts.lock.json`; use
  `npm run scaffold:generate` and `npm run scaffold:check:canonical` for that
  artifact. Linux native checks use the exact pinned Rust release, a clean
  target directory, isolated Cargo home, and an environment allowlist; external
  ancestor Cargo configuration is rejected. The local complete gate compares
  those bytes with the immutable Docker build and rejects source changes during
  compilation.
- Host-mediated plugin intents are exposed end to end through the Go Host
  library, HTTP adapter, OpenAPI route contract, and `PluginPlatformClient`.
  Host products can list enabled runnable intents and invoke a chosen intent
  without iframe gateway tokens while still preserving local policy evaluation,
  permission grants, audit events, and dangerous-method fail-closed behavior.

ReDevPlugin intentionally does not import Redeven internals and does not
provide a local sibling integration path for host products.

## Documentation

- [Runtime architecture](docs/architecture/plugin-platform-runtime.md)
- [Security model](docs/security/plugin-platform-security.md)
- [Plugin surface SDK](docs/ui/plugin-surface-sdk.md)
- [CI and release gates](docs/release/ci-and-release-gates.md)
- [A3 TDD evidence](docs/release/a3-tdd-evidence.md)

## Release Integrity

ReDevPlugin publishes `redevplugin-runtime` and `redevplugin-worker-sdk` source
crates together with a matching Go module, npm packages, generated contracts,
compatibility metadata, and package publication evidence. Host products build
the runtime binary from the exact published runtime crate after independently
verifying registry checksums, source identity, dependency metadata, and the
contract-set digest.

Tagged publication builds every package once in unprivileged jobs, publishes in
dependency order, and reads the packages back from the Go proxy/sumdb, npm
registry, and crates.io. Registry-only fake-host E2E then builds the runtime from
the downloaded crate sources and exercises the Go Host, TypeScript SDK, IPC,
WASM, brokers, streams, revocation, and shutdown without sibling wiring. A
partial or mismatched registry publication is fail-closed and cannot be repaired
by overwriting an existing version.

Only after registry readback and conformance succeed does the GitHub Release
contain exactly one attested `platform-release-manifest.json` asset. ReDevPlugin
GitHub Releases do not contain OS runtime binaries,
runtime archives, installers, or product signatures. They also do not attach npm
tarballs, `.crate` files, product checksums, or runtime signing bundles. Registry
integrity and provenance remain authoritative for package bytes; the release
manifest binds their readback SHA-256 values and canonical contract hashes to
the one platform version.

The host product owns the resulting binary, SBOM, provenance, signature,
installer, and product archive. ReDevPlugin continues to own runtime admission,
the Go supervisor, IPC, WASM execution, hostcalls, leases, quotas, revocation,
and diagnostics contracts; building the product binary does not authorize a
host-local supervisor or protocol fork.

## Local Checks

Before pushing `main`, install the repository hook once:

```bash
git config core.hooksPath .githooks
```

The hook runs the authoritative complete local gate before `main` reaches the
remote. It only accepts a clean, fast-forward update from the checked-out `main`
branch whose `HEAD` exactly matches the pushed object. Feature-branch pushes do
not run the gate; attempts to push a feature ref to remote `main` are rejected.
The main-branch Quick CI is a separate bounded source-format and script-syntax
confirmation; it does not duplicate browser, runtime, package, performance, or
stress coverage. Run the complete gate directly when investigating a failure:

```bash
./scripts/check_redevplugin_pre_push.sh
```

GitHub-only release publication, tag identity, artifact upload/download,
multi-runner runtime execution, npm/Go registry readback, Sigstore signing, and
GitHub API checks remain in the release workflows because they require GitHub
credentials or hosted runner infrastructure.

Rust checks require a local Rust toolchain:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

`check_redevplugin_runtime_contract.sh` also runs connectivity and runtimeclient
Go tests plus the target-classifier fixture checks so grant validation, the Go
classifier, and the shared JSON cases cannot drift. Target classification has
no separately published Rust crate.

`check_redevplugin_stress.sh` always emits a JSON summary. The `stress_evidence`
field records structured counters from `pkg/stress`, including event
backpressure denials, execution cancellation, and inactive-execution
non-redispatch,
connectivity grant/classifier denials, runtime revoke ACK p95 latency,
redirect/DNS rebinding denials, HTTP proxy/CONNECT/header hardening, TCP mock
database round trips, TCP size denials, TCP cancelled reads, UDP source-pin
mismatch drops, UDP rate-limit denials, WebSocket round trips, WebSocket size
denials, WebSocket cancelled reads, KV byte quota pressure, file-count quota,
and SQLite sidecar/sparse bypass checks. The exact-main pre-push gate retains
that local summary as release evidence for host-neutral broker/backpressure,
execution cancellation, runtime-control, storage, and
sandbox telemetry behavior. Non-Linux hosts require Docker so the Linux-only
runtime revoke evidence is collected instead of skipped.
