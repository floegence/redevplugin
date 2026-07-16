# ReDevPlugin

ReDevPlugin is the reusable plugin platform intended to be consumed by host
products through published Go, TypeScript, Rust runtime, and
machine-contract artifacts.

This repository owns the host-neutral plugin platform core. Host products own
their product policy, UI shell integration, session adapters, and business
capabilities.

## Current Platform Snapshot

- Go module: `github.com/floegence/redevplugin`
- TypeScript package: `@floegence/redevplugin-ui`
- Rust workspace: `redevplugin-runtime`, the public
  `redevplugin-worker-sdk`, and support crates
- Contracts: OpenAPI, manifest schema, package-signature schema,
  release-metadata schema, source-policy schema, source-revocations schema,
  token/ticket schema, iframe bridge and render policy, opaque surface document
  and transport schemas, compatibility and release manifest schemas, IPC schema,
  WASM ABI schema, worker invocation payload schema, stable error-code schema,
  and target classifier fixture
- Host-neutral Go package boundaries for manifest validation, package IO,
  registry, host adapters, bridge, storage, runtime supervision, grants, cleanup,
  capability adapters, HTTP routes, session context, and web security.
- Host capability contracts are published as signed exact-pin bundles containing
  a restricted schema, compatibility metadata, generated plugin-side client,
  notices, manifest, and signature. The Host verifies source-policy key usage,
  every file digest, publisher identity, compatibility floor, and the complete
  pin before a package can bind the capability.
- Storage brokers include both an in-memory test broker and a filesystem-backed
  broker that creates per-plugin-instance namespace directories under a
  host-selected state root, enforces byte and file-count quota accounting,
  rejects symlink escape attempts, supports export/import archives, and makes
  uninstall data deletion or retention observable on disk.
- Stream stores include both in-memory and SQLite-backed implementations. The
  SQLite store persists stream records and buffered events, enforces the same
  backpressure behavior, drains read events from the buffer, marks streams
  orphaned during plugin disable/uninstall transitions, and uses a package-local
  schema migration marker with newer-schema fail-closed behavior.
- Settings stores include both in-memory and SQLite-backed implementations. The
  SQLite store persists setting records and export archives, reuses the shared
  validation/default/secret-redaction lifecycle, restores settings across
  process restarts, and keeps retained bind/import behavior durable without
  storing secret plaintext.
- Observability stores include both in-memory and SQLite-backed implementations.
  The SQLite store persists audit and diagnostic events, preserves the same
  filtering, defaults, newest-first ordering, retention limits, and generated
  event IDs as the in-memory store, and uses a package-local schema migration
  marker with newer-schema fail-closed behavior.
- Secret binding stores include both in-memory and SQLite-backed
  implementations. They persist only plugin-instance, scope, secret-ref, bound
  state, and test/delete metadata, never secret plaintext, so hosts can keep the
  actual vault implementation product-owned while reusing common lifecycle
  state, filtering, cleanup, and newer-schema fail-closed behavior.
- Confirmation intent stores include both in-memory and SQLite-backed
  implementations. They persist the server-held intent metadata and
  confirmation token id, request hash, plan hash, and expiry, but not the raw
  confirmation token; after a process restart, missing token-manager state makes
  any recovered intent fail closed instead of silently confirming.
- Host lifecycle APIs include `RefreshEnabledPlugins`, which lets an embedding
  product restore enabled plugin runtime state after restart by replaying
  storage/settings initialization, connectivity policy installation, and
  surface publication from the durable registry without re-enabling plugins.
  The mountable HTTP adapter exposes the same behavior at
  `POST /_redevplugin/api/plugins/runtime/refresh-enabled`, so hosts can keep
  route mounting thin instead of reimplementing the refresh loop.
- Manifest validation binds settings and storage migration metadata to the
  declared schema versions: bootstrap migrations may start at `from_version: 0`,
  but every migration must point `to_version` at the active schema version and
  carry a non-empty `steps_hash`, non-negative estimates, and a monotonic version
  range before a package can be installed.
- Host update and downgrade flows compare the currently installed settings and
  storage schema versions with the target package. Updates must describe the
  exact current-to-target migration, and downgrades require the current version's
  migration descriptor to be reversible before the registry can switch versions.
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
  generated UI plus one ABI v2 WASM backend worker, then sign it:
  `redevplugin keygen <key-id> <private.json> <public.json>` followed by
  `redevplugin sign <unsigned.redevplugin> <private.json> <signed.redevplugin>`.
  Development harnesses can then run
  `redevplugin install-verified <signed.redevplugin> <public.json>` to prove
  the Host trust-verifier path accepts the signed package.
- Host capability producers use
  `redevplugin host-capability build <config.json> <out-dir>`. Consumers verify
  the published bundle with
  `redevplugin host-capability verify <artifact-root> <pin.json> <public.json>`
  and export its pinned client with
  `redevplugin host-capability generate-client <artifact-root> <pin.json> <public.json> <out.ts> [--check]`.
  The generator never accepts an unsigned raw schema or a sibling checkout.
  Contract, pin, manifest, compatibility, signature, and notices artifacts each
  have a closed versioned JSON Schema. Verification regenerates the TypeScript
  client from the signed contract and requires byte-for-byte identity before a
  capability contract can enter the registry.
- `testdata/generated_plugins/minimal`, `networked`, `storage`, and
  `method-contract` are positive generated-plugin fixtures that the platform
  gate validates and packages through the same CLI path. `method-contract`
  covers dangerous confirmation, atomic confirmation rejection, risk preflight,
  operation/subscription cancel policy, and delete-effect metadata.
  `testdata/generated_plugins/malicious-build/*`
  must fail packaging before any dependency install or build step can run.
- Mountable HTTP routes call a host-provided `websecurity.Guard` for origin and
  CSRF policy. The guard returns the host-neutral `trusted_parent` or `deny`
  decision plus an authenticated request scope; product-specific origin roles
  and concrete session semantics stay in the host product.
- `PluginSurfaceHost.create(...)` is the only public construction path. It
  creates a fresh SDK-owned iframe, exposes it as the read-only `element` for
  product-shell placement, and immediately applies `src="about:blank"`,
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
- Manifest v2 requires every method to declare closed request and response
  object schemas. Package validation compiles those schemas without remote
  references; Host dispatch validates requests before adapters/runtime and
  validates canonical redacted responses before returning them to plugin code.
- Manifest v2 surface declarations use only host-neutral `view`, `command`, or
  `background` kinds with optional `primary`, `secondary`, or `utility` intent.
  Activity bars, workbench panes, settings pages, and modal placement remain
  host-product decisions.
- Stable error-code contract tests keep the Go `pkg/security` catalog, OpenAPI
  envelope enum, iframe bridge schema, TypeScript SDK exports, and Rust IPC
  runtime-origin error constants aligned. The catalog separates server platform
  codes, bridge response codes, TypeScript client-side transport codes, and Rust
  IPC codes so product shells can branch on stable values without scraping
  localized messages.
- WASM worker ABI schema tests keep `wasm-worker-v2.schema.json` aligned with
  the Go package validator, Go compatibility version, Rust ABI crate constants,
  Rust IPC worker export validation, Rust runtime linked hostcall modules, and
  the worker invocation schema export enum.
- Go package validation compiles the complete WASM module with Wazero before it
  accepts memory and export metadata. The Rust ABI crate independently runs
  `wasmparser::Validator::validate_all` before runtime execution, and the Wasmi
  store enforces the signed memory budget even when a worker calls
  `memory.grow`. The manifest platform ceiling is 256 MiB per worker; a Host
  may reject a lower value through its package trust policy.
- Plugin backend authors use `redevplugin-worker-sdk` from the immutable release
  tag. Each runtime bundle contains the identical
  `sdk/redevplugin-worker-sdk-<version>.crate` source artifact, and release
  manifest v3 records its version, SHA-256, and size for audit or offline
  vendoring.
- Rust IPC schema tests keep startup `hello` / `hello_ack` frames bound to the
  Host-issued channel nonce, runtime generation, IPC version, and WASM ABI
  version, keep worker invocation leases bound to `lease_nonce` for runtime
  replay rejection, require structured heartbeat ACK results for control-channel
  liveness, and require `revoke_epoch_ack` results to report the plugin
  instance, revoke epoch, and closed socket/stream/storage-handle counters.
  IPC golden fixtures under `testdata/contracts/ipc/` are read by Go Host tests
  and Rust IPC crate tests. They cover the current handshake/response shape plus
  Host/Rust IPC version mismatch, WASM ABI mismatch, missing required fields,
  replayed request IDs, unknown frame types, and runtime-generation mismatch
  fail-closed paths.
- Runtime lease replay stores let hosts extend the Rust in-process replay check
  across runtime restarts and the full lease TTL window. `runtimeclient` provides
  memory and SQLite stores that record only a hash of `lease_id + lease_nonce`;
  `ProcessSupervisor` consumes the ledger before sending worker IPC and emits a
  replay diagnostic without opening the artifact on duplicate use.
- `ProcessSupervisor` generates a fresh ephemeral Ed25519 keypair for every
  supervisor instance, requires a non-empty public-key set in the startup
  `hello` frame, binds every worker lease to the current runtime audience, and
  signs every invocation. Callers cannot provide, disable, or override the
  signature or public key. The canonical payload excludes `lease_token` and
  `signature` and covers the display token ID, plugin metadata, active package
  fingerprint, issued timestamp, method, effect, execution mode, Host-owned
  operation and stream ids, audit correlation id, surface and owner context,
  descriptor hashes, quota limits, policy and management revisions, revoke
  epoch, expiry, `lease_nonce`, `key_id`, and runtime audience fields.
  The Go supervisor verifies that exact audience and signature before IPC. Rust
  independently rejects a missing keyring, invalid signature, expired lease, or
  any mismatch between the signed lease and the worker invocation's plugin,
  method/effect/execution, operation/stream, audit, surface/session, or runtime
  binding before replay-cache consumption or artifact open. Worker-route
  dispatch emits a `plugin.runtime.lease.issued` Host audit event with
  lease/token IDs, runtime IDs, revision bindings, descriptor hashes, and expiry
  metadata, but not the bearer `lease_token`.
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
  compatibility manifest read, release-ref install/update, downgrade,
  enable/disable/uninstall, surface open, runtime
  start/health/refresh-enabled/stop, settings schema/read/patch, operation
  list/get/cancel, data export/import, permission grant/revoke/list, secret
  bind/test/delete, host-mediated intent list/invoke, and audit/diagnostic event
  list. The raw package import/update surface is intentionally separated into
  `PluginLocalImportClient`, exported only from
  `@floegence/redevplugin-ui/local-import`, for explicit dev/admin local-import
  route sets. List helpers preserve the same data wrapper fields returned by the
  Go HTTP adapter, such as `operations`, `permissions`, `audit_events`, and
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
- The npm API boundary is split into four auditable entrypoints. The package
  root and `@floegence/redevplugin-ui/trusted-parent` expose the same
  trusted-parent allowlist for host shells. `@floegence/redevplugin-ui/plugin`
  exposes exactly six runtime values to untrusted plugin worker bundles:
  `PluginBridgeClient`, `PluginBridgeError`, `callCapabilitySync`,
  `callCapabilityOperation`, `callCapabilityStream`, and
  `isCapabilityBusinessError`. Stream decoding remains an internal detail of
  the typed capability helpers and is not a plugin entrypoint export.
  `@floegence/redevplugin-ui/local-import` exposes the explicit dev/admin raw
  package client and must not be imported by official release-reference product
  paths. The opaque bootstrap HTML factory remains internal and is not exported
  by any public entrypoint.
- Operation cancel requests are durable Host decisions: `CancelOperation`
  records `cancel_requested`, emits audit evidence, and signals the live
  execution lease. The lease captures an optional route-local cancellation hook
  from the capability adapter, core action, or runtime supervisor when execution
  starts. Persisted inactive operations are never redispatched through a global
  registry lookup; their durable cancel request remains observable.
- Capability operation methods return one Host-owned operation id.
  Subscription methods return a paired Host-owned operation id and stream id;
  stream tickets bind both, while plugin workers receive only an opaque stream
  handle plus the operation id. Generated business-error guards also bind the
  capability id, capability version, and published details-schema SHA-256.
- Stream reads are serialized per stream. Long polling uses non-destructive
  `Peek`, then the final store read and single-use ticket commit run under one
  authorization boundary. A failed read preserves both events and the current
  ticket; an open stream atomically rotates to the next ticket; a fully drained
  terminal stream consumes the current ticket without reserving a replacement.
  Plugin revision and surface-session bindings are revalidated after waiting and
  before the final mutation.
- Operation and stream terminal states are reconciled as one paired lifecycle.
  The first terminal intent is latched before either durable store is written;
  a conflicting retry fails closed. Host startup terminates running or
  cancel-requested records that have no live execution owner, and refuses
  contradictory terminal operation/stream pairs.
  Either store may reach terminal state first; Host startup and subsequent
  execution entrypoints repair the other side, including after a SQLite reopen,
  before releasing the live execution lease.
- Dangerous method confirmation uses server-held one-time intents. When a method
  declares a risk preflight method, the Host runs that read-only sync preflight
  during confirmation preparation, returns the redacted plan plus `plan_hash` to
  the trusted parent, and binds both `request_hash` and `plan_hash` into the
  parent-only confirmation token audience. The raw confirmation token is never
  returned to parent JavaScript, written to the confirmation intent store, or
  exposed to the sandboxed iframe.
- Capability adapters can return `capability.RiskPlan` from preflight methods to
  use the host-neutral `redevplugin.capability.risk_plan.v1` contract. The Host
  validates and normalizes that typed plan before hashing it, rejects unknown or
  invalid risk fields fail-closed, and still accepts legacy generic preflight
  objects that do not declare a risk-plan schema version. The TypeScript SDK
  exports matching `PluginRiskPlan` / `PluginRiskFlag` types plus
  `isPluginRiskPlan()` so trusted parent UI can render the typed plan without
  brittle ad hoc shape checks.
- Capability, worker, and core-action method results pass through the Host-owned
  `capability.DefaultResponseRedactionPolicy` before they are returned to the
  plugin surface or HTTP adapter. The default policy clones structured
  `data` payloads, including typed risk-plan `details`, and redacts sensitive
  keys plus container-shaped env, label, and mount secret values while preserving
  safe identifiers such as token IDs and secret refs, hashes, and fingerprints.
- `redevplugin version` emits a host-consumable compatibility manifest with the
  current platform version matrix plus SHA-256 hashes for the released OpenAPI,
  manifest, signature, release-metadata, source-policy, source-revocations,
  token/ticket, bridge, opaque-surface document and transport, compatibility,
  release-manifest, IPC, WASM,
  network-grant, worker invocation, all six host-capability artifact schemas,
  error-code, and target-classifier contracts. Network grant schema, release manifest schema,
  and target-classifier fixture versions are tracked independently so hosts can
  distinguish grant envelope drift, bundle manifest drift, and classifier rule
  drift. The target-classifier fixture now carries executable allow/deny cases
  for public DNS, punycode hostnames, metadata hosts, RFC1918/ULA/link-local
  addresses, and IPv4-mapped IPv6 private addresses, with Go and Rust tests
  reading the same JSON contract.
- `spec/plugin/contract-registry-v1.json` is the generated complete inventory of
  those public contract IDs, paths, versions, and SHA-256 identities; Go and
  TypeScript registries are generated from the same source set.
- Release-manifest schema tests keep `release-manifest-v3.schema.json` aligned
  with the release bundle build script and verifier: `release-manifest.json`
  records the source commit, compatibility digest, exact npm tarball identity,
  exact Rust worker SDK crate identity, sorted file list, lowercase SHA-256
  hashes and byte sizes, excludes itself and `SHA256SUMS`, rejects unsafe paths,
  and drives generated checksums.
- Mounted hosts can also expose the same compatibility manifest through
  `GET /_redevplugin/api/plugins/platform/compatibility`, allowing a product to
  verify the loaded platform artifact set without shelling out to the CLI; the
  TypeScript `PluginPlatformClient.getCompatibility()` helper reads the same
  endpoint for browser-hosted product shells.
- `redevplugin verify-compatibility <compatibility.json> <artifact-root>` checks
  a released compatibility manifest against the current version matrix and the
  referenced contract artifact hashes. Host products can use this command before
  upgrading a published ReDevPlugin dependency set.
- Connectivity brokers compile manifest-declared HTTP, WebSocket, TCP, and UDP
  connectors into grantable policies. The host-neutral network executor now
  consumes short-lived connection grants and performs bounded HTTP
  request/response calls, HTTP response streaming into the Host stream store,
  plus WebSocket, TCP, and UDP round trips with explicit timeout, cancellation,
  request-size, response-size, chunk-size, and stream-buffer limits. It revalidates
  grant expiry, transport, destination, and the target classifier at execution
  time so UI bridge calls and backend worker hostcalls can share the same
  fail-closed network boundary. Grants whose `target_classifier_version` does
  not match the current compatibility matrix are rejected before any dial or
  broker dispatch. IPv4-mapped IPv6 literals and resolved addresses are unmapped
  before blocked-range checks so mapped loopback/private/link-local targets
  cannot bypass IPv4 CIDR policy. Long-lived WebSocket subscriptions remain tied
  to the streaming envelope contract instead of the one-shot round trip API.
- Host tests include a black-box runtime subprocess path that invokes a worker
  method, has the helper runtime request `network_execute` over IPC, mints the
  grant through the Host connectivity broker, records HTTP, streamed HTTP,
  WebSocket, TCP, and UDP executor request/response paths, and verifies that
  streamed HTTP responses return a Host-readable `stream_id` and stream ticket
  before returning the worker result.
- The Rust runtime now performs the first executable worker slice: it requests
  the bound WASM artifact from the Host over IPC, validates the WASM binary
  header and required function export through `redevplugin-wasm-abi`, executes
  the exported no-argument worker entrypoint with the embedded Wasmi engine, and
  returns a successful scaffold worker result over `invoke_worker_result`. It
  also exposes brokered storage and network hostcalls. Generated plugins now use
  the real linear-memory ABI by default:
  `redevplugin.storage/files(req_ptr, req_len, out_ptr, out_len) -> i32`,
  `redevplugin.storage/kv(req_ptr, req_len, out_ptr, out_len) -> i32`,
  `redevplugin.storage/sqlite(req_ptr, req_len, out_ptr, out_len) -> i32`, and
  `redevplugin.network/execute(req_ptr, req_len, out_ptr, out_len) -> i32`.
  The worker writes bounded JSON broker requests into WASM memory, the Rust
  runtime injects Host-owned identity, surface/session stream audience, policy,
  grant, revoke context, and the subscription invocation's Host-owned
  `stream_id`,
  executes the requests through the `storage_file`, `storage_kv`,
  `storage_sqlite`, and `network_execute` IPC paths, and writes JSON responses
  back into worker-provided output buffers. `network_execute.operation =
  "http_stream"` is currently a Host stream-store bridge: the Go supervisor
  streams HTTP response chunks into `stream.Store` and returns response
  metadata plus `stream_id`. Plugin request JSON cannot select that id; the Rust
  runtime injects it from the Host invocation and rejects missing or
  plugin-supplied values. This path is a Host-owned stream-store bridge rather
  than a Rust-owned persistent stream transport. Before each broker dispatch
  the runtime verifies control-channel freshness and fails closed with
  `RUNTIME_CONTROL_CHANNEL_STALE` when the Host heartbeat/revocation window is
  stale. Runtime revoke ACKs now return a structured result with closed
  socket/stream/storage-handle counters. The Rust runtime keeps an in-process
  registry for brokered storage handles, network socket leases, and Host
  stream-store bridge stream IDs; revoke epochs
  clear matching registry entries and report the actual closed counts. Resource
  classes that are purely Host-owned report zero because Rust has no matching
  handle to close. The earlier fixed `*_demo` imports and
  `redevplugin.network/http_request` alias are removed; ABI v2 workers import
  only the closed storage and `redevplugin.network/execute` hostcalls. Host integration tests build
  and exercise the real Rust runtime whenever a local Cargo toolchain is
  available, including FileBroker file writes, KV writes, SQLite DDL through the
  filesystem-backed broker, generated scaffold broker workers using the memory
  ABI, HTTP/WebSocket/TCP/UDP network memory hostcalls, and linear-memory HTTP
  executor paths.
- `redevplugin inspect-storage <storage-root> [plugin-instance-id]` reports
  filesystem broker namespaces plus byte and file-count quota/usage without
  dumping plugin file contents. Host products can wrap this for diagnostics
  while keeping the storage root selection in their own adapter layer.
- Host data export/import keeps storage archives and settings archives as
  separate refs. Storage imports require each archive namespace to match the
  target store kind and schema version before applying target quotas. Settings
  imports require the archive schema version to match the target manifest schema,
  validate non-secret fields against that target schema, and never restore secret
  plaintext or a bound-secret state; users must rebind secret refs after moving
  plugin data to another environment.
- `redevplugin dev-install <state-root> <package>` creates a persistent local
  development state root for Flower-generated plugins. The matching
  `dev-enable`, `dev-open <surface-id>`, `dev-disable`,
  `dev-secret-bind <secret-ref> [user|environment]`,
  `dev-secret-test <secret-ref> [user|environment]`,
  `dev-secret-delete <secret-ref> [user|environment]`,
  `dev-permission-grant <permission-id> [granted-by]`,
  `dev-permission-revoke <permission-id> [reason]`,
  `dev-permission-list [--active-only]`,
  `dev-export-data [--include-secrets]`,
  `dev-import-data [--archive-ref <ref>] [--settings-archive-ref <ref>] [--delete-existing|--merge]`,
  `dev-uninstall [--delete-data|--keep-data]`, and `dev-status` commands replay
  the saved package through the real Host lifecycle APIs while keeping the
  copied package, filesystem storage root, manifest-level settings, redacted
  secret-ref binding/test state, and permission grant/revoke records under the
  same state root. Dev secret commands never
  store secret plaintext; they only persist the declared `secret_ref`, scope,
  bound flag, and test status that the Host settings API can expose as redacted
  state. Dev permission commands call the Host permission APIs, so policy
  revisions and revoke epochs move exactly as they do in an embedded host
  product. Dev data export/import commands call the Host data lifecycle APIs and
  persist returned storage/settings archive refs under the same state root;
  settings archives never restore secret plaintext, so secret refs must still be
  rebound after moving data between environments. This gives generated plugins a local, auditable
  install -> enable -> open -> disable -> uninstall flow without importing any
  host-product internals. Uninstall removes the copied package; `--delete-data`
  also removes plugin storage namespaces, manifest settings, dev secret-ref
  state, and permission grants,
  while `--keep-data` marks declared plugin data retained and preserves redacted
  dev secret-ref state for the local developer profile. Permission grants are
  removed on every uninstall, including `--keep-data`, because authorization is
  tied to the installed plugin lifecycle rather than retained user data.
- `redevplugin examples-server <state-root> <runtime-path>` starts the
  user-facing Examples Showcase with Memos, Weather, and Sky Strike. Every
  example uses the Go Host, HTTP adapter, real Rust runtime, installable plugin
  package, and persisted plugin storage. Memos is a complete private Markdown
  timeline: its always-available composer persists a safe draft before explicit
  publication, the feed renders controlled Markdown VNodes without admitting
  raw HTML, images, or arbitrary navigation, and search invalidates stale
  requests. Tags, local-date calendar facets, pinning, and archives share one
  bounded query contract. Published memo edits use serialized autosave; failed
  persistence preserves the active edit and blocks navigation, surface quiesce
  flushes pending drafts and edits, and compact layouts use a full-height
  explorer drawer with modal deletion confirmation. The Showcase asks
  `PluginSurfaceHost.create(...)` to create a fresh
  opaque `srcdoc` iframe and mount only its `element`; no caller-provided
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
  `npm run examples:check:canonical` reproduces the exact CI byte check. The
  CLI scaffold uses the same shared builder and records its backend worker in
  `cmd/redevplugin/scaffold_assets/worker-artifacts.lock.json`; use
  `npm run scaffold:generate` and `npm run scaffold:check:canonical` for that
  artifact. Linux native checks use the exact pinned Rust release, a clean
  target directory, isolated Cargo home, and an environment allowlist; external
  ancestor Cargo configuration is rejected. CI compares those bytes with the
  immutable Docker build and rejects source changes during compilation.
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
- [A2 TDD evidence](docs/release/a2-tdd-evidence.md)
- [A3 TDD evidence](docs/release/a3-tdd-evidence.md)

## Release Integrity

Tagged GitHub releases build a platform-specific release bundle for each
supported runtime target only after release audit and stress gates pass. The UI
package and Rust worker SDK crate are each packed once. The exact same npm
tarball and `.crate` bytes are embedded in every runtime bundle, and the npm
tarball is published to npm. The
published evidence includes `redevplugin-release-stress.json`, the structured
`redevplugin-a2-acceptance.json` report, supported/unsupported browser
screenshots, `SHA256SUMS`, and the runtime `.tar.gz` bundles. `SHA256SUMS` covers
all of them, and every covered artifact plus `SHA256SUMS` is signed with
Sigstore keyless `cosign sign-blob`. Each signed artifact is uploaded with a
detached `.sig` file and a `.bundle` transparency-log bundle. Host products
should verify the checksum, stress counters, A2 opaque-origin/sandbox/CSP and
credential-isolation assertions, the signed A3 host capability sample inside
each runtime bundle, and the cosign bundle before consuming a
ReDevPlugin runtime artifact. Use
`scripts/verify_redevplugin_release_artifacts.sh --tag vX.Y.Z <artifact-dir>` after
downloading a release artifact set. Release packing/publishing uses pinned
`npm@11.18.0`, and signing/readback uses pinned `cosign v2.4.3`. The workflow
resolves lightweight or annotated GitHub tags to the immutable source commit,
rejects tags that are not on `origin/main`, uses a strict not-found-only
preflight plus atomic `gh release create`, and rechecks tag identity immediately
before npm and GitHub publication and after the non-draft Release exists. It
verifies an already-published npm version only after downloading the registry
tarball, recomputing SHA-512, and validating the SLSA DSSE subject, repository,
release workflow path/ref, tag, and source commit, then performs
public GitHub, npm, Go direct/proxy module identity,
runtime matrix, compatibility, checksum, and cosign readback. Runtime artifacts
execute on their native matrix runners; the aggregate readback checks foreign
ELF/Mach-O architecture and all signed content structurally.

Every release bundle also contains generated `THIRD_PARTY_NOTICES.md`, dependency
lockfiles, `notices/THIRD_PARTY_LICENSES.json`, and the actual redistributed
license/notice/copyright texts under `notices/licenses/`. The bundle verifier
checks the exact legal-file set and every recorded SHA-256, so license names
alone are not accepted as release evidence. The root MIT `LICENSE` is included
in both runtime bundles and the packed npm package.

Tagged releases also publish the matching `@floegence/redevplugin-ui` npm
package version. The release bundle still includes the npm tarball as checksum
evidence, but host products should consume the UI SDK from the npm registry by
semver instead of copying the bundled tarball or using a local checkout.
Worker authors should pin `redevplugin-worker-sdk` to the same immutable Git tag;
the bundled `.crate` is the signed source artifact for audit and offline
vendoring, not an instruction to wire a sibling checkout.

## Local Checks

```bash
GOWORK=off go list ./...
GOWORK=off go test ./...
npm ci
npx playwright install chromium
npm run check
npm run canonical-wasm:test
npm run examples:check:canonical
npm run scaffold:check:canonical
npm run examples
npm run test:browser-harness
npm run test:browser-harness:smoke
./scripts/check_redevplugin_runtime_contract.sh
./scripts/check_redevplugin_platform.sh
REDEVPLUGIN_INSTALL_AUDIT_TOOLS=1 ./scripts/check_redevplugin_release_audit.sh
./scripts/check_redevplugin_stress.sh --fast --summary dist/redevplugin-stress-fast.json
```

Rust checks require a local Rust toolchain:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

`check_redevplugin_runtime_contract.sh` also runs connectivity and runtimeclient
Go tests plus the Rust target-classifier fixture test so grant validation, the
Go classifier, Rust crate, and JSON contract cannot drift.

`check_redevplugin_stress.sh` always emits a JSON summary. The `stress_evidence`
field records structured counters from `pkg/stress`, including stream
backpressure denials plus stream close/cancel fail-closed checks, operation
cancel ownership and inactive-operation non-redispatch,
connectivity grant/classifier denials, runtime revoke ACK p95 latency,
redirect/DNS rebinding denials, HTTP proxy/CONNECT/header hardening, TCP mock
database round trips, TCP size denials, TCP cancelled reads, UDP source-pin
mismatch drops, UDP rate-limit denials, WebSocket round trips, WebSocket size
denials, WebSocket cancelled reads, KV byte quota pressure, file-count quota,
and SQLite sidecar/sparse bypass checks. CI uploads that summary as release evidence for host-neutral
broker/backpressure and stream close/cancel, operation cancel ownership,
runtime-control, storage, and sandbox telemetry behavior.
