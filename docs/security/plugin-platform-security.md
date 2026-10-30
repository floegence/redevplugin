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
- missing Web roots or HTML entries, reserved platform paths, or the removed
  worker-UI document format;
- SVG or external surface icons; icons must be package-local raster assets;
- shell/shebang scripts, native executable or dynamic-library artifacts,
  package-manager install lifecycle scripts, package-manager dependency fields,
  Cargo `build.rs` / build scripts, proc-macro crates, native linker
  configuration, and Cargo dependency sections;
- package sizes and paths that exceed configured limits.

Every manifest v9 method must provide request and response JSON Schemas whose
root is a closed object. Every nested schema that declares `type: object` must
also set `additionalProperties: false`. ReDevPlugin rejects remote `$ref`
resources, schema documents over 256 KiB, excessive schema depth/node counts,
and schemas that do not compile as draft 2020-12. The Host validates requests
before any capability, core-action, or WASM invocation. It canonicalizes and
redacts adapter/runtime data, then validates that plugin-visible response before
registering an execution or publishing its events. Successfully compiled schemas
are reused by exact content and resource identity in one bounded process-wide
cache. The cache never replaces schema-subset, size, admission, or permission
validation; caller mutations select new content and cannot modify prior validators.

Validation errors expose stable platform error codes and structured
`error_details` such as reason, package path, and manifest JSON pointer. Product
UI should branch on the stable code/details rather than scraping localized
messages.

## Signatures And Trust

All package entry points use one preimage from
releasecontract.PackageSignatureSigningPreimage: the signing domain prefix,
package usage, and canonical signature object with its signature field removed.
Ed25519 signs its SHA-256 digest. Local signing, release external-signer
requests, release verification, and Host admission share that exact operation.
The manifest hash already binds the plugin version. Source, channel, and
distribution authorization belong to the independently signed release metadata
and source policy; local package inspection does not guess them. Version 3.7.2
rejects both previous incompatible signature encodings. Affected packages must
be rebuilt and signed at a new immutable release coordinate; no trusted-key or
integrity bypass is provided.

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

The external-source downloader revalidates DNS and every redirect hop for every
request, pins dialing to the validated public addresses, preserves the original
TLS hostname, and scopes credentials to one exact origin. Connection reuse does
not weaken those checks: an idle transport is reusable only for the same scheme,
hostname, port, and sorted address pin set. A changed origin or DNS result gets a
new transport. The pool is bounded to 32 entries, closes idle connections after
30 seconds, and closes evicted idle transports without interrupting active
requests.

## Sandbox UI Boundary

Untrusted applications execute ordinary HTML and JavaScript on a fresh,
platform-bound origin per live container. The child hostname differs from the
host page; the host adapter provides DNS/TLS routing only. The platform owns
entry admission, asset validation, bridge setup, leases, and revocation. Child
origins must never mount product management routes or inherit product cookies.

The sandbox permits scripts, the child's own origin, and local form events.
CSP denies form navigation, nested frames, objects, base overrides, and external
resource connections. A Permissions Policy deny-list disables privileged
browser APIs. Connection-Allowlist confines browser connections to the response
origin. The trusted bootstrap validates its enforcement before any package
script executes, using successful self requests around a rejected redirect.
Unsupported browsers fail explicitly without a fallback rendering path. Tests
must independently verify real receiver-side network behavior; an HTTP header
or user-agent string is not evidence of enforcement.

Modules, dynamic imports, browser Workers, DOM events, Canvas, WebGL, WASM,
localStorage, and IndexedDB are ordinary application features. There is no
sealed Worker global or platform graphics allocation budget. Browser storage
belongs to this transient container origin, not the durable plugin namespace.
Service Worker script requests are rejected by the HTTP resource handler.
Executable resources must come from the exact installed package.

The bootstrap consumes a single-use entry token from the URL fragment and
removes it from history. A Secure, HttpOnly, SameSite=None, Partitioned cookie
carries a random resource credential. The cookie is bound to the origin and
current surface lease; it is not a management credential. Every resource read
revalidates the current owner/session, fingerprint, revision, revoke epoch,
package entry metadata, length, and digest. Replayed entry, wrong origin,
path traversal, expired sessions, and post-revocation reads fail closed.

A close request carries a unique quiesce ID. Async application lifecycle
observers may flush state before acknowledgement, within the parent's bounded
1.5-second deadline. Revocation then tears down the frame and ports. A plugin
cannot delay forced security revocation. Native document navigation invalidates
the current generation; a new host opening creates fresh authority.

Sandbox code never receives parent gateway tokens, asset tickets/sessions,
confirmation tokens, storage/network grants, runtime-control tokens, raw vault
secrets, or unrelated product authority. Browser bridge response tests enforce
these exclusions. DOM, focus, action, and selection observations are untrusted
presentation metadata and cannot authorize file export or capability calls.

## Bridge And Tokens

The parent accepts bootstrap signals only from the current iframe window and
exact allocated origin. It transfers one secret-free MessagePort to that
origin and requires acknowledgement of the exact frame generation before
requesting a gateway token. Later calls use the port and bind surface identity,
asset session, bridge nonce, active fingerprint, owner/session hashes,
management revision, and revoke epoch. The plugin claims a private application
port through the SDK; the trusted parent retains management authority.

Token and ticket kinds are described in `token-ticket-v4.schema.json`. Schema
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

Management prepare/token/dispose and stream reads remain parent-only POST
routes, authenticated through the Host origin/CSRF and route-authorization
pipeline. Application resources instead use the isolated Web HTTP handler and
its origin-bound HttpOnly cookie. This is the sole resource path: there is no
management asset-read endpoint or Base64 transfer protocol. Document requests
use the trusted loader; non-document resource misses return 404 rather than
HTML fallback. Resource responses use no-store and nosniff.

The trusted parent computes the handshake transcript with the pinned standard
@noble/hashes implementation. Length-prefixed, NUL-terminated UTF-8 and the
sha256 hexadecimal result remain identical on HTTP and HTTPS. Resource bytes
are hashed by the Go Host against verified package evidence before serving.
CSPRNG nonces require secure entropy and never fall back to predictable values.

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
credentials. Session teardown calls the authenticated `session/revoke-scope`
route; owner and channel identity come only from the Host request context.
The initial lease is minted and applied before application initialization, so no
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
instance, not to retained user data. Reinstalling the same stable plugin
instance preserves the tombstone's revoke epoch as the new credential floor.
New surface credentials can therefore be minted without lowering the floor or
reviving credentials that uninstall already revoked.

## Local Process Launch Identity

The process supervisor binds client-key reuse to an independent snapshot of the
validated launch request. It compares program, arguments, working directory,
environment additions/removals, secret references, and resource limits by field
for both pending and running launches. Moving bytes between arguments and
environment entries cannot preserve launch identity, and later caller mutations
cannot redefine the original request. Secret references and environment values
are not hashed for deduplication or exposed through process status.

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
through ReDevPlugin. The Host applies `capability.PrepareResponseData` to
capability, worker, and core-action `data` before returning it to a sandbox
surface or HTTP caller. Adapter values must first encode as one unambiguous JSON
value within the fixed 512 KiB, 64-level, and 32768-node limits. Native Go maps,
slices, arrays, pointers, and structs are budgeted before marshaling so an
already oversized or cyclic tree is rejected before later custom marshalers are
called. The Host then redacts sensitive keys, environment assignments, label
values, and mount paths while preserving safe display identifiers such as
`*_id`, `*_ref`, `*_name`, `*_hash`, and fingerprints. Redaction never converts
an invalid Go value into an acceptable response, and the final redacted tree is
rechecked so replacement text cannot expand it beyond the original limits.

Custom `MarshalJSON` and `MarshalText` implementations are executable
host-adapter code, not sandboxed plugin code. ReDevPlugin strictly bounds and
validates encoded bytes, but cannot prevent a host adapter from consuming
resources inside these methods before they return. Hosts must apply their normal
trust and review policy to adapter implementations; the response boundary does
not claim to sandbox host code. An `omitzero` response field with a custom
`IsZero` method is rejected without calling that method, eliminating a stateful
double-observation path. Reflective zero-value checks remain supported.

Published capability business-error details use the same normalization and
redaction path before details-schema validation. A private Host attestation is
the only proof accepted by the HTTP adapter; a host adapter cannot obtain a 422
capability response by constructing or wrapping `capability.BusinessError`
itself. Unattested, typed-nil, malformed, or oversized errors fail closed as a
contract mismatch without exposing adapter-controlled details.

Other adapter failures are reduced to an immutable Host-owned RPC failure before
execution cleanup or rejection reporting. The reduction preserves only stable
allowlisted platform classifications, worker fields attested only at the
`RuntimeManager.InvokeWorker` boundary, capability business details attested only
after published-contract validation, and `not_committed` or `unknown` mutation
outcomes. It never records the adapter's error string in method-rejection
diagnostics and never exposes the original error object to HTTP classification.

## Network Access

Network access uses manifest-declared connector policies, target classification,
short-lived grants, and bounded Host executors. HTTP, WebSocket, TCP, and UDP
request paths revalidate transport, destination, grant expiry, target
classifier, request size, response size, cancellation, and timeouts at execution
time.

TCP execution is byte-stream transport only: host-neutral tests use a small mock
database request/response protocol to prove bounded round trips, but database
semantics stay inside the plugin protocol client rather than the broker.

Long-lived subscriptions emit bounded Events under their Execution identity;
they do not widen one-shot network execution into an unbounded transport.

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

Compiled modules are cached only by verified artifact SHA-256 under the current
`plugin_api=1` WASM contract. The cache contains no plugin grant or session authority, so revoke does
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

Plugins declare only `plugin_api=1`. The Host and Rust runtime bind
`internal_wire=1` once during Hello/HelloAck, then use the canonical worker,
error-code, network-grant, and WASM contracts without a second compatibility
axis. Legacy identifiers are rejected; runtime drift fails closed before normal
frames or plugin work are accepted.

## Surface Diagnostics

The trusted loader and parent report bounded admission, preparation, handshake,
application-load, contract, and disposal failures. Diagnostics must not include
bearer credentials or application HTML. Browser network-denial diagnostics are
expected only when correlated to a deliberate test or admission probe; unrelated
console errors remain acceptance failures. Normal DOM and application errors
remain distinguishable from transport or permission failures.

## Host Product Duties

Host products must:

- keep session, origin, CSRF, state root, vault, audit, diagnostics, runtime
  artifact, and business capability adapters explicit;
- implement all four `websecurity.Guard` stages, return a complete authenticated
  session, validate trusted-host origin and CSRF policy, and authorize the closed
  route action without adding product roles to the ReDevPlugin adapter;
- verify the signed `PlatformReleaseManifest` and every exact release artifact before upgrades;
- avoid local sibling dependency wiring;
- present policy decisions and confirmations through product UI without
  bypassing ReDevPlugin permission, token, lease, broker, audit, and lifecycle
  chains;
- keep product-specific capability implementations outside ReDevPlugin core.
