# ReDevPlugin Security Model

Third-party plugins are untrusted. ReDevPlugin treats every plugin package,
manifest, sandbox document, WASM module, storage request, network request,
stream, token, and generated plugin as untrusted input until it passes
host-controlled validation, policy, quota, lifecycle, and revocation checks.

## Trust Boundary

The Host library is the security authority. Plugin UI and WASM workers must not
self-report identity, permissions, routes, vault access, storage roots, network
targets, or runtime generation. The Host derives those values from installed
registry records, session adapters, authorization snapshots, manifests, package hashes,
grants, and runtime state.

Host products provide concrete policy and adapters, but the reusable security
mechanics live here:

- manifest/package/signature validation;
- sandbox bootstrap and bridge token/session issuance;
- permission grants and security policy caps;
- confirmation requirements and stable error shapes;
- brokered storage/network access;
- runtime lease, revoke epoch, and generation checks;
- audit and diagnostic records.

## Package Validation

Package validation fails closed before a Host persists or enables a package.

ReDevPlugin rejects:

- unsafe package paths, traversal, root-absolute paths, and invalid separators;
- surface entries that are not package-local HTML assets;
- surface entries with query strings or fragments;
- surfaces without exactly one package-local `text/redevplugin-worker` classic
  bundle;
- worker imports/exports, unsupported render elements or attributes, unsafe
  input types, external/root-absolute/missing URL assets, inline script/style,
  event handlers, `srcdoc`, embedded browsing contexts, `meta refresh`, excessive
  render trees, or direct Service Worker API references in sandbox UI assets;
- SVG or external surface icons; icons must be package-local raster assets;
- shell/shebang scripts, native executable or dynamic-library artifacts,
  package-manager install lifecycle scripts, package-manager dependency fields,
  Cargo `build.rs` / build scripts, proc-macro crates, native linker
  configuration, and Cargo dependency sections;
- package sizes and paths that exceed configured limits.

Every manifest v4 method must provide request and response JSON Schemas whose
root is a closed object. Every nested schema that declares `type: object` must
also set `additionalProperties: false`. ReDevPlugin rejects remote `$ref`
resources, schema documents over 256 KiB, excessive schema depth/node counts,
and schemas that do not compile as draft 2020-12. The Host validates requests
before any capability, core-action, or WASM invocation. It canonicalizes and
redacts adapter/runtime data, then validates that plugin-visible response before
registering operation or stream handles.

Validation errors expose stable platform error codes and structured
`error_details` such as reason, package path, and manifest JSON pointer. Product
UI should branch on the stable code/details rather than scraping localized
messages.

## Signatures And Trust

Detached package signatures live in `signatures/package.sig`. Signature metadata
is retained for trust verification but excluded from canonical package entries
and canonical package hashes, avoiding self-referential signatures. The
`signatures/` directory is closed-world; any entry other than
`signatures/package.sig` is rejected during package build/read.

`pkg/trust` provides an Ed25519 verifier and keyring interface. Hosts decide
which publishers, keys, registries, local developer flows, host-artifact package
references, or enterprise policies are trusted. Management install and update
requests do not accept caller-supplied `trust_state` values; runnable verified
state is emitted only by a host-provided trust verifier.

Release-reference install and update routes are the preferred path for official
or registry-backed package distribution. The trusted host UI sends only a
`PluginReleaseRef` containing source, release metadata ref/hash, publisher,
plugin, version, and expected package/manifest/entries hashes. The host
`ReleaseSourcePolicyResolver` freezes the source policy snapshot before
`ReleaseArtifactResolver` runs. The artifact resolver receives that snapshot and
returns only signed release-metadata bytes, metadata-signature bytes, and an
untrusted package artifact handle. ReDevPlugin verifies the metadata signature,
closed-world decodes the canonical release, validates the resolver-scoped
distribution reference, reads the package, compares all hashes, passes the
package through the host trust verifier, stages the install/update, and only
then mutates the registry. A resolver may not return trusted parsed release
fields or turn arbitrary URLs, filesystem paths, localhost/LAN redirects, or
path traversal into installable artifacts.

## Sandbox UI Boundary

`PluginSurfaceHost.create(...)` creates every plugin frame itself; its public
options do not accept an existing iframe. The SDK-owned frame starts with
`src="about:blank"`, an explicit Permissions Policy deny-list for sensors,
capture, credentials, payments, USB/HID/serial, and other browser capabilities,
`no-referrer`, and exactly
`sandbox="allow-scripts"`. Without `allow-same-origin`, the document receives a
unique opaque origin. It is not navigated to a plugin URL, Host URL, localhost,
remote URL, or parent-created blob URL.

The trusted parent prepares a validated opaque surface document through a
same-origin POST route. The generated bootstrap applies a fail-closed CSP with
no direct network, frame, form, object, manifest, or base-URL capability. It
injects validated static HTML and nonce-bound CSS, creates lazy non-executable
asset blob URLs inside the opaque frame, and starts exactly one classic
Dedicated Worker from validated bundled bytes. IndexedDB, Cache Storage,
Service Workers, direct fetch, WebSocket, nested workers, dynamic import, eval,
Function constructors, and parent DOM/storage access are denied by the browser
boundary and renderer hardening. Package-time Service Worker scanning is an
early rejection for direct identifier, optional-chain, and bracket references;
runtime removal of the API is the authoritative boundary for dynamically
constructed source references.

Renderer resource ownership is bounded by the generated bridge policy. It
permits at most four transferred canvases, 4096 pixels per dimension,
16,777,216 aggregate canvas pixels, and 120 pointer events per second. Raster
type is derived from PNG, JPEG, GIF, or WebP bytes rather than a filename or
declared MIME, and dimensions are parsed before decode. At most 32 images and
33,554,432 decoded pixels are allowed. The worker global removes
`OffscreenCanvas` construction and `createImageBitmap`, so plugin code cannot
allocate an unaccounted secondary graphics surface. Resizing an already
transferred canvas is checked against the same budget.

The renderer sends a private ping every 10 seconds and requires the matching
worker pong within 5 seconds. A stalled or replaced worker fails the surface
closed. Disposal uses a unique quiesce id: the plugin bridge waits for all async
lifecycle observers, including persistence flushes, before acknowledging. The
trusted parent waits at most 1.5 seconds and then continues server revocation and
local teardown, so a plugin can finish bounded state writes but cannot hold the
surface open indefinitely.

Allowed forms are interaction containers, not navigation primitives. The
renderer captures submit events and nested submit-button clicks, calls
`preventDefault`, serializes at most 128 bounded string fields, and sends one
typed action over the private worker port. CSP `form-action 'none'` remains the
browser-level backstop.

One aggregate opening deadline bounds frame load, prepare, transferred-port
acknowledgement, initial lease minting, first paint, and worker readiness.
Timeout aborts in-flight parent requests, revokes the server-side surface,
destroys the local frame/ports, and consumes one shared reload-limiter attempt;
a later healthy host instance resets that bounded retry state.

Sandbox UI must not receive parent-only credentials such as asset tickets,
plugin gateway tokens, confirmation tokens, storage grants, network grants,
runtime-control tokens, or host management credentials. Browser bridge responses
are tested to avoid exposing these token classes.

## Bridge And Tokens

The parent transfers one secret-free bootstrap `MessagePort` to the current
iframe `contentWindow` and frame generation. Because the destination has an
opaque origin, that one bootstrap transfer uses `postMessage("*")`; it contains
no token, plugin identity, owner/session binding, or capability material. The
renderer must return a `redevplugin.surface.port_ack` for that exact frame
generation over the transferred port before the parent requests a gateway token. The
trusted renderer gives each plugin worker two ordered ports: a private
`runtime_control` port retained by the renderer and a `plugin_bridge` port
claimed by the plugin SDK. All subsequent lifecycle, render, RPC, cancel, asset,
stream, and confirmation traffic uses those ports. Authorization binds the
window source, frame generation, port, asset session, surface instance, bridge
nonce, active fingerprint, owner and session hashes, management revision, and revoke
epoch. `event.origin` is diagnostic context only.

Token and ticket kinds are described in `token-ticket-v2.schema.json`. Schema
tests bind every token kind to its required `use`, audience fields, and
token-id namespace:

- `asset_ticket`;
- `asset_session`;
- `plugin_gateway_token`;
- `confirmation_token`;
- `runtime_execution_lease`;
- `handle_grant`;
- `stream_ticket`.

Tokens are capabilities. A token that can be read by a different browser origin
or reused across the wrong audience is a security bug.

`plugin_gateway_token` is minted only after the iframe acknowledges the
generation-bound port, the Go Host completes and records closed surface
preparation, and the trusted parent submits a `handshake_transcript_sha256` bound to the
handshake fields and `bridge_channel_id`. The Go Host recomputes that transcript
before minting, so a stale or cross-channel handshake cannot obtain a parent-only
gateway token by replaying HTTP fields alone. The trusted-parent handshake is
an OpenAPI/HTTP DTO and is intentionally absent from the plugin-visible bridge schema.

Plugin gateway token validation failures use gateway-specific stable error
codes: `PLUGIN_GATEWAY_TOKEN_INVALID`, `PLUGIN_GATEWAY_TOKEN_REPLAYED`, and
`PLUGIN_GATEWAY_TOKEN_CHANNEL_MISMATCH`.

Confirmation tokens are server-held one-time tokens. The parent receives only a
confirmation intent id, an audit/display token id, the canonical request hash,
the confirmation plan hash, and the redacted plan payload when a declared
preflight method produced one. The token audience binds both `request_hash` and
`plan_hash`, so a confirmed call cannot swap either the request payload or the
plan that the parent approved.

Capability adapters may return `capability.RiskPlan` for dynamic preflight
plans. ReDevPlugin treats `redevplugin.capability.risk_plan.v1` as a
host-neutral closed-world contract: the current schema version is mandatory,
typed plans are normalized, validated, and redacted before their `plan_hash` is
computed, and every other payload shape fails closed.

Confirmation intents are stored through a Host-provided store with in-memory
and SQLite implementations. The store persists only intent metadata,
confirmation token id, request hash, plan hash, and expiry; it does not persist
the raw confirmation token capability. If a host process restarts with durable
intent metadata but without the matching in-memory token-manager record,
confirmation consumption fails closed.

Surface prepare/token/dispose, asset reads, and stream reads are parent-only POST
routes. Responses use `Cache-Control: no-store`, and the Host's origin/CSRF guard
must return the host-neutral `OriginTrustedParent` decision with a valid trusted
request scope. Product-specific origin names or roles are not part of the
ReDevPlugin adapter contract. Asset tickets, asset sessions, gateway tokens, and
stream tickets remain in parent memory. For a lazy asset, plugin code sends only
the opaque `binding_id` from the prepared document. The HTTP API does not accept
a caller-selected package path or digest: the Host resolves both from its cached
prepared document, checks the active fingerprint, entry path and entry digest,
then revalidates the asset digest before returning typed bytes over the private
port. Every read compares registry path, metadata size, content type, actual byte
length, and recomputed SHA-256. A prepared document permits at most 128 lazy assets and 32
MiB cumulative lazy bytes; the renderer and trusted parent allow at most four
concurrent reads. Unknown or stale bindings fail closed. The plugin worker receives random
`surface_handle` and `stream_handle` values; there are no query credentials,
browser-readable cookies, GET asset endpoints, or plugin-origin stream requests.

Surface sessions are explicitly bounded. `SurfaceTokenService` defaults to
4,096 active sessions globally and 64 per owner session; hosts may set lower or
higher positive limits through `SurfaceTokenOptions`. Duplicate bindings for the
same generation fail closed; a changed fingerprint, runtime generation, or
revision may atomically replace the stale binding within the same trusted scope.
Opening a surface prunes expired sessions before enforcing limits.
User-driven disposal must match both trusted scope and the current
`bridge_nonce`, so a stale generation cannot delete its replacement.
Disposal/revocation removes live sessions, and token minting prunes expired token
records. These bounds keep
random per-open surface ids from becoming an unbounded in-process resource.

Token records are independently bounded by `TokenManager`: 16,384 records
globally, 2,048 per plugin instance, a maximum 15-minute core TTL, and 4,096
monotonic plugin revoke floors by default. Token ids have a direct index, and
expired records are removed from all token/plugin/surface indexes before
capacity checks. Confirmation and stream-ticket TTLs are clamped to five
minutes; runtime and handle grants retain their stricter limits. Revoke-floor
capacity is never evicted: saturation returns an explicit error and locks minting
for plugin instances without an already retained floor, preserving fail-closed
revocation semantics.

Bridge lease renewal uses the current parent-held gateway token on the same
bridge channel. A successful renewal atomically replaces both the gateway token
and asset session, extends the server-side surface lease, and revokes the prior
credentials. Session teardown calls the authenticated `surfaces/revoke-scope`
route; owner and channel identity come only from the Host request context.
The initial lease is minted and applied before renderer initialization, so no
plugin asset request can race the revocation of the prepared asset session.
Renewal timers start only after the surface reaches ready state.

## Permissions And Policy

The Host evaluates security policy before permission grants. Registry-owned
authorization snapshots cap allowed permission IDs and deny method execution. Policy updates bump
revision and revoke epochs, refresh connectivity policy, and revoke runtime
capabilities. Runtime revocation ACKs are decoded as structured evidence, and
Host audit events include the closed socket/stream/storage-handle counters
reported by the runtime.

Permission grants are lifecycle-bound. Uninstall removes grants even when plugin
data is retained, because authorization is tied to the active installed plugin
instance, not to retained user data.

## Storage, Settings, And Secrets

Storage access is brokered by the Host. Plugins do not receive arbitrary
filesystem roots. File, KV, SQLite, export, import, quota, namespace, and
retained-data operations go through the single PluginData adapter.

PluginData validates and persists non-secret settings against the manifest
schema with a values revision. Secret settings are redacted and must be changed
through the independent secret lifecycle.

Secret binding stores only persist plugin instance, scope, secret reference,
bound/test/delete metadata, and timestamps. They never store secret plaintext,
tokens, passwords, or vault payloads. The concrete vault remains a host-owned
adapter.

## Capability Response Redaction

Business capability adapters are host-owned, but their method result data leaves
through ReDevPlugin. The Host applies `capability.DefaultResponseRedactionPolicy`
to capability, worker, and core-action `data` before returning it to a sandbox
surface or HTTP caller. The policy clones supported structured values and
redacts sensitive keys, environment assignments, label values, typed risk-plan
details, and mount paths that look like secrets while preserving safe display
identifiers such as
`*_id`, `*_ref`, `*_name`, `*_hash`, and fingerprints.

This redaction is a platform safety net. Capability adapters should still avoid
returning raw vault payloads, Docker/Podman environment secrets, private mount
paths, or credentials unless the response contract explicitly requires a
redacted representation.

## Network Access

Network access uses manifest-declared connector policies, target classification,
short-lived grants, and bounded Host executors. HTTP, WebSocket, TCP, and UDP
request paths revalidate transport, destination, grant expiry, target
classifier, request size, response size, cancellation, and timeouts at execution
time.

TCP execution is byte-stream transport only: host-neutral tests use a small mock
database request/response protocol to prove bounded round trips, but database
semantics stay inside the plugin protocol client rather than the broker.

Long-lived subscriptions belong to the stream envelope contract, not to
unbounded one-shot network execution.

## Runtime Revocation

Rust runtime execution is mediated by Host-owned runtime generation IDs,
Host-issued IPC channel nonces, runtime leases, revoke epochs, and worker
invocation payloads. The runtime must reject stale or invalid invocation context
before opening artifacts or executing workers. Startup `hello` and `hello_ack`
frames bind a fresh channel nonce so a stale runtime process cannot complete the
handshake by replaying only the generation and version fields. Worker invocation
frames must carry the Host-issued runtime lease nonce, and the runtime consumes
`lease_id + lease_nonce` before opening the worker artifact. Reusing the same
lease in a running runtime generation fails closed with `PLUGIN_LEASE_REPLAYED`.
The Go supervisor can also be configured with a runtime lease replay store. The
memory store protects one host process, while the SQLite store persists the
consumed `lease_id + lease_nonce` hash across runtime restarts until the lease
expires. A duplicate lease is rejected before worker IPC or artifact reads and
records a `plugin.runtime.lease.replayed` diagnostic. The stores persist only a
hash of the lease identifier and nonce.

WASM binary validation is duplicated across the process boundary by design.
The Go package validator compiles the entire module with Wazero before accepting
its memory and export contract. The Rust ABI crate independently runs
`wasmparser::Validator::validate_all` before export inspection or Wasmi
execution. A syntactically valid worker still receives the signed invocation
memory ceiling, and `memory.grow` beyond that budget fails closed at runtime.
The manifest cannot request more than 256 MiB per worker, and a Host package
trust policy may enforce a lower ceiling. Hosts can additionally configure an
Ed25519 runtime lease verifier on the Go supervisor. The verifier checks a
canonical `runtime_execution_lease` payload
that excludes the signature itself, while covering
the display token ID, plugin metadata, active package fingerprint, issued
timestamp, worker method, effect, execution mode, surface and owner context,
descriptor hashes, quota limits, policy and management revisions, revoke epoch,
expiry, `lease_nonce`, `key_id`, and runtime audience. Before the signature
check, the supervisor requires the lease audience to match the current runtime
instance, IPC channel ID, and handshake `connection_nonce`. Rejected signatures
record `plugin.runtime.lease.signature_rejected` and fail before worker IPC or
artifact reads. Worker-route dispatch records `plugin.runtime.lease.issued` with
lease/token IDs, runtime IDs, revision bindings, descriptor hashes, and expiry
metadata.
The supervisor can include the matching runtime lease public keys in the startup
`hello` frame. Once the Rust runtime receives a non-empty keyring, it verifies
worker lease signatures with the same canonical payload and rejects unsigned,
tampered, or unknown-key leases with `RUNTIME_LEASE_SIGNATURE_INVALID` before
consuming the in-process replay cache or opening artifacts.
When the Rust runtime asks the Go supervisor to serve artifact, handle-grant,
storage, or network hostcalls, the supervisor derives a bounded context before
calling host adapters. Request-level `timeout_ms` controls storage SQLite and
network execution within a platform cap; hostcalls without an explicit timeout
use the default hostcall cap.
Every runtime-origin request also carries `parent_request_id`. The supervisor
requires a live matching invocation and reuses only that invocation's signed
plugin, surface, session, target, grant, quota, revision, and revoke bindings.
A runtime cannot attach a hostcall to another invocation or continue broker IO
after cancellation. Queued cancellation removes work before execution; running
cancellation is checked at hostcall and completion boundaries without killing
the shared runtime process.

Compiled modules are cached only by verified artifact SHA-256 and WASM ABI
version. The cache contains no plugin grant or session authority, so revoke does
not change module identity; every Store, Linker, memory limiter, fuel budget,
lease check, and broker audience remains invocation-local. Artifact bytes are
read and rehashed on cache miss, compilation failures are not retained, and a
runtime restart clears the cache.
The Go supervisor also maintains a default 2s heartbeat over the same runtime
control channel. If the runtime cannot return a structured heartbeat ACK before
the 5s max-staleness window expires, the supervisor marks that generation not
ready, kills the process, and records an invalidation diagnostic.
The Rust runtime keeps its own control freshness state. If the latest valid
heartbeat or revocation control frame is older than the configured
max-staleness window, it rejects new worker invocations and broker hostcalls
with `RUNTIME_CONTROL_CHANNEL_STALE` before opening artifacts or dispatching
Host IO.
Successful runtime revocation ACKs include structured close counters so the
audit trail can distinguish a control-plane revoke from the runtime resources
that were actually closed. The current Rust runtime backs these counters with
an in-process registry for brokered storage handles, network socket leases, and
Host stream-store bridge stream IDs.

Host/Rust IPC, WASM ABI, worker invocation, error-code, network grant,
performance evidence, and compatibility manifests are versioned contracts.
IPC v2 and UI v4 are accepted only as negative fixtures; runtime drift must fail
closed through tests, compatibility checks, or diagnostics.

## Surface Diagnostics

The trusted renderer reports bounded initialization, worker load/error,
`messageerror`, contract validation, and disposal failures over the private
parent port. Diagnostics must not include bearer credentials or plugin-provided
HTML. The platform does not expose a browser CSP report endpoint; expected CSP
denials are verified by browser smoke tests, while actionable runtime failures
use typed parent diagnostics.

## Host Product Duties

Host products must:

- keep session, origin, CSRF, state root, vault, audit, diagnostics, runtime
  artifact, and business capability adapters explicit;
- map product-specific origin/session policy into `OriginTrustedParent` or
  `OriginDeny` and a valid request scope without adding product roles to the
  ReDevPlugin adapter;
- verify compatibility manifests and release artifacts before upgrades;
- avoid local sibling dependency wiring;
- present policy decisions and confirmations through product UI without
  bypassing ReDevPlugin permission, token, lease, broker, audit, and lifecycle
  chains;
- keep product-specific capability implementations outside ReDevPlugin core.
