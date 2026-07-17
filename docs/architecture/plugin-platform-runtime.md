# ReDevPlugin Runtime Architecture

ReDevPlugin is a host-neutral plugin platform. Host products import published
ReDevPlugin Go, TypeScript, Rust runtime, and machine-contract artifacts; they
do not copy source, wire sibling checkouts into builds, or reimplement platform
state machines.

## Ownership Boundary

ReDevPlugin owns reusable extension mechanics:

- package layout, canonical package hashing, detached signatures, validation,
  and asset storage;
- plugin registry, install/update/enable/open/disable/uninstall lifecycle,
  PluginData export/import, retained bindings, and unreferenced object recovery;
- permission grants, security policy evaluation, confirmation outcomes,
  stable errors, audit events, and diagnostics;
- opaque iframe bootstrap, validated surface documents, asset tickets and
  sessions, typed `MessagePort` bridge messages, operation and stream envelopes,
  and TypeScript SDK helpers;
- registry, PluginData, observability, secret binding metadata, operation,
  stream, confirmation-intent, and staged-install durable stores;
- Rust runtime IPC, WASM worker ABI validation, brokered storage/network
  hostcalls, runtime revocation state, and worker invocation payload contracts;
- OpenAPI, JSON schemas, compatibility manifests, release manifests, release
  bundle verification, and compatibility hash checks.

Host products own product policy and concrete adapters:

- session identity, origin and CSRF policy, state-root selection, audit sinks,
  diagnostics sinks, secret vaults, and runtime artifact resolution;
- product UI placement such as settings, activity bars, workbench panes, and
  native shell chrome;
- business capabilities such as containers, files, shells, databases, cloud
  APIs, or other product resources.

If a host needs more than adapter registration, route mounting, artifact
selection, or product UI around ReDevPlugin, the missing reusable behavior
belongs in ReDevPlugin first.

Manifest v5 methods are executable contracts, not descriptive metadata. Both
request and response schemas are closed draft 2020-12 object schemas compiled
during package validation. The Host keeps a bounded fingerprint+method LRU of
compiled validators, rejects request mismatches before dispatch, canonicalizes
and redacts adapter/runtime data, and rejects response mismatches before an
operation or stream becomes visible.

Manifest v5 surfaces express only host-neutral `view`, `command`, or
`background` roles plus optional `primary`, `secondary`, or `utility` intent.
They do not encode product placement. A host maps those roles into its own
navigation, workspace, settings, or command UI.

## Core Go Packages

The Go module `github.com/floegence/redevplugin` exposes the embeddable Host
library and platform contracts.

`pkg/bridge` owns token/ticket audiences, MessageChannel handshake state,
surface/stream credentials, and runtime leases. Active surface sessions are
bounded globally and per owner, duplicate ids are rejected, and expired
session/token state is pruned rather than retained indefinitely. A gateway
token cannot be minted until the Host has completed closed-document preparation
and marked that exact asset session prepared.

- `pkg/manifest` validates the plugin manifest model and cross-field
  references.
- `pkg/pluginpkg` reads and writes deterministic packages, builds validated
  opaque surface documents from the generated bridge render policy, rejects
  native backend artifacts, and exposes filesystem-backed asset storage.
- `pkg/host` coordinates lifecycle, permissions, policy, settings, storage,
  network grants, runtime execution, retained data, audit, and
  diagnostics through host-provided adapters. Official or registry-backed
  installs should use release references resolved by host-registered
  `ReleaseSourcePolicyResolver` and `ReleaseArtifactResolver` adapters; the Host
  still owns package reading, hash comparison, trust verification, staged
  install, registry mutation, audit, and diagnostics.
  Lifecycle mutation uses a reference-counted per-plugin lock registry: install,
  update, downgrade, enable, disable, and uninstall take the plugin write lock;
  surface opening and final stream commits take the read lock. Release
  resolution and package validation occur outside the lock and commit only after
  the registry revision is revalidated.
- `pkg/httpadapter` provides mountable host-neutral HTTP routes for platform
  management, surface prepare/token/dispose, parent-only POST asset and stream
  reads, compatibility, and diagnostics.
- `pkg/runtimeclient` manages the Rust runtime subprocess, negotiated capacity,
  multiplexed newline-delimited JSON IPC, invocation cancellation, and runtime
  health/cache metrics. A `Manager` must bind its required `RuntimeHostServices`
  exactly once before it can create or start shards; Host supplies the runtime
  stream sink from the same execution registry used by capability dispatch.
  Runtime configuration therefore cannot omit stream delivery or infer a shard
  count from a zero value.
- `pkg/plugindata` owns settings, storage generations, immutable exports, and
  retained bindings. `pkg/observability`, `pkg/secrets`, `pkg/stream`,
  `pkg/operation`, `pkg/installstage`, and `pkg/security` provide the remaining
  host-neutral contracts and durable state.
- `pkg/protocol` tests keep OpenAPI, schemas, route fixtures, Go DTOs,
  TypeScript SDK bindings, Rust IPC, WASM ABI, and compatibility hashes aligned.

The Host library must remain host-neutral. It must not import a host product,
know product navigation, or assume a particular vault, filesystem root,
business resource, desktop shell, or UI surface.

## Rust Runtime

The Rust workspace contains `redevplugin-runtime`, the public
`redevplugin-worker-sdk`, and support crates for IPC, target classification, and
WASM ABI validation. The runtime is launched by the Go Host through
`pkg/runtimeclient`. Worker authors pin the SDK to the same immutable Git tag as
the Host/runtime release. Every native runtime bundle embeds the exact same
versioned `.crate` source artifact and records its SHA-256 in release manifest
v3.

The current IPC model is supervised stdin/stdout newline JSON. The Host remains
the authority for identity, policy, grants, quotas, revocation, storage, and
network access. The runtime validates WASM worker shape, executes the exported
worker entrypoint with Wasmi, and performs brokered hostcalls through Host-owned
IPC request/response frames.

Rust IPC v3 uses one Go reader, one serialized pipe writer, and a pending map
keyed by `request_id`; a worker invocation no longer holds a process-wide IPC
mutex. Runtime-origin artifact, grant, storage, and network frames include
`parent_request_id`. Grant, storage, and network frames are accepted only while
the matching signed invocation is live and only within that invocation's
audience and broker permissions. Artifact loading additionally uses bounded
`compile_flight_register` and `compile_flight_complete` routes pre-registered by
the Host for the exact runtime generation, parent request, package, artifact,
digest, and WASM ABI. A registered compile flight may finish after its leader is
canceled without granting any other hostcall authority; unknown or mismatched
routes invalidate the runtime generation. Active hostcall and compile-flight
artifact route capacities equal the negotiated `worker_count`; canceled
hostcall retention equals `worker_count + queue_capacity`. Canceled routes do
not consume active capacity, and retention exhaustion invalidates the runtime
generation instead of silently evicting an authorization record.
`cancel_invoke` removes queued work or
marks running work canceled; the runtime acknowledges cancellation and remains
ready for unrelated work.

The Host must supply positive `RuntimeLimits`; `DefaultRuntimeLimits()` creates
an explicit value with worker count
`clamp(GOMAXPROCS, 4, 16)`, queue capacity to `min(worker_count * 4, 64)`, and
per-plugin concurrency to `min(max(worker_count / 2, 2), 8)`. Go admission waits
before consuming the execution lease. Rust enforces the same hello-negotiated
limits with a fixed worker pool and round-robin per-plugin queues. Capacity and
cancellation are reported separately as `RUNTIME_CAPACITY_EXCEEDED` and
`RUNTIME_INVOCATION_CANCELED`.

One Wasmi Engine is shared for the runtime generation. Validated modules are
single-flight compiled and cached by `(artifact_sha256, wasm_abi_version)` in a
deterministic LRU, with default limits of 64 modules and 128 MiB source WASM.
Cache hits do not request artifact bytes from the Host. Compilation failures are
not cached, revocation does not remove content-addressed modules, and process
restart clears the cache. Every invocation still creates a separate Store,
Linker, memory limiter, and fuel budget.

WASM validation is intentionally independent on both sides of the process
boundary. Go package validation compiles the complete module with Wazero before
accepting memory/export metadata. The Rust ABI crate runs
`wasmparser::Validator::validate_all` before export inspection or Wasmi
execution. The signed invocation memory budget is then applied to the Wasmi
store so a valid module still cannot use `memory.grow` beyond its grant. The
manifest contract rejects worker budgets above the 256 MiB platform ceiling;
host package trust policy may impose a smaller product limit.

The Go supervisor derives a bounded context for runtime-origin hostcalls before
entering host adapters. Storage SQLite and network execution use request
`timeout_ms` within the platform cap; artifact reads, handle-grant validation,
storage file/KV, and network grant minting use the default hostcall cap.
For `network_execute.operation = "http_stream"`, the supervisor registers a
Host-owned read stream with the worker invocation's surface/session audience,
the Rust runtime injects that invocation's `stream_id` into the broker request,
and the supervisor streams bounded HTTP response chunks into `stream.Store`,
closes or cancels the stream, and returns response metadata plus `stream_id`
over IPC. A plugin request cannot select a stream id; a missing Host id or any
plugin-supplied id fails closed. This is a Host stream-store bridge for
runtime-origin HTTP responses, not the Rust hot-path persistent stream
transport with credit, resume, or bidirectional flow control.

The supervisor maintains the control channel with `heartbeat` IPC frames. The
default interval is 2 seconds and the default max-staleness window is 5 seconds.
Heartbeat ACKs return the runtime generation, runtime timestamp, host timestamp
echo, and max-staleness window. If the runtime cannot acknowledge within the
window, the supervisor invalidates and kills that runtime generation.
The Rust runtime also tracks the last valid heartbeat or revocation control
frame. Once that max-staleness window is exceeded, it rejects new worker
invocations before opening artifacts and rejects new storage/network hostcalls
before dispatching Host IO.

`Health` includes the Host-side runtime instance ID, runtime generation ID, IPC
channel ID, handshake `connection_nonce`, active and queued invocation counts,
effective runtime limits, and module-cache hits, misses, compiles, entries, and
source bytes. The runtime audience fields are needed to mint a
`RuntimeExecutionLease` for the active process. `ProcessSupervisor` always
creates an ephemeral Ed25519 keypair, sends its non-empty public-key set in the
startup `hello` frame, overwrites any caller signature material, binds the lease
to the current process audience, and signs every worker invocation. The
canonical payload excludes the signature and covers the display token ID,
plugin metadata, active package fingerprint, issued timestamp, method, effect,
execution mode, Host-owned operation and stream ids, audit correlation id,
surface and owner context, target descriptor hashes, quota limits, policy
revisions, revoke epoch, expiry, `lease_nonce`, `key_id`, and runtime audience
fields. `MintRuntimeExecutionLease` returns separate `lease_id` and display
`token_id` values plus the same metadata, and worker-route dispatch records a
`plugin.runtime.lease.issued` Host audit event with the bound identifiers,
runtime audience, revisions, descriptor hashes, and expiry.

The Go supervisor verifies the current runtime audience and Ed25519 signature
before writing IPC. Rust requires the startup keyring and independently verifies
the signature, lease expiry, method/effect/execution mode, operation/stream
handle shape, audit correlation, plugin identity, surface/session scope, and
runtime generation against the worker invocation before consuming the replay
cache or opening an artifact. Signature failures use
`RUNTIME_LEASE_SIGNATURE_INVALID`; validly signed but expired or audience-
mismatched leases use `RUNTIME_LEASE_INVALID`.

Revocation uses `revoke_epoch` control frames. Successful `revoke_epoch_ack`
payloads return a structured result containing the plugin instance, revoke
epoch, and closed socket/stream/storage-handle counters. The Rust runtime
maintains an in-process registry for brokered storage handles, network socket
leases, and Host stream-store bridge stream IDs. A
revoke epoch removes the matching plugin resources from that registry and
reports the actual close counts.

The runtime contract is versioned by:

- `plugin_host_protocol_version`;
- `rust_ipc_version`;
- `wasm_abi_version`;
- `runtime_generation_id`, Host-issued IPC channel nonce, Rust in-process
  runtime lease nonce replay cache, optional Go supervisor memory/SQLite replay
  ledger for runtime restart and lease-TTL coverage, runtime-enforced heartbeat
  max-staleness, and revoke epoch state;
- compatibility manifest contract hashes.

The runtime IPC contract also has executable golden fixtures in
`testdata/contracts/ipc/`. Go Host tests and Rust IPC crate tests validate the
current `hello_ack` and runtime response frames and reject older/newer Rust IPC
versions, older/newer WASM ABI versions, missing request IDs, replayed request
IDs, unknown frame types, and mismatched runtime generations.

Any incompatible Host/runtime combination must fail closed with a diagnostic
error instead of silently running a plugin.

## TypeScript Surface Package

The package `@floegence/redevplugin-ui` provides `PluginSurfaceHost`, the trusted
opaque renderer, the plugin-side `PluginBridgeClient`, generated render-policy
constants, and a host-side `PluginPlatformClient`. It is a released npm artifact,
not copied into host products through local paths.

`PluginSurfaceHost.create(...)` is the sole public constructor. It creates and
owns a fresh iframe, hardens it before returning, and exposes only its read-only
`element` for host-product placement. Callers cannot supply an existing frame.
The frame uses explicit `src="about:blank"`, `sandbox="allow-scripts"`, a
Permissions Policy deny-list for browser capabilities, and a generated
`srcdoc`. It has a unique opaque
origin and a restrictive CSP. The
trusted renderer validates the prepared static document, injects nonce-bound
styles, starts one classic Blob-backed Dedicated Worker, and transfers separate
`runtime_control` and `plugin_bridge` ports. The parent transfers one distinct
bootstrap port to the current frame generation and waits for a generation-bound
`port_ack` before requesting the parent-only gateway lease; all later lifecycle, RPC,
cancel, render, asset, stream, and confirmation traffic is typed and port-bound.
The worker receives only opaque
surface and stream handles. Asset tickets, sessions, gateway credentials,
stream tickets, confirmation tokens, plugin identity bindings, and owner/session
hashes remain in the trusted parent.

Plugin UI v5 requires plugins to provide a globally unique, stable key for every
element and text VNode. The SDK rejects string text VNodes and never derives
identity from tree position or sibling index. Structural patches address keys
and sibling anchors through `insert_child`, `remove_child`, and `move_child`;
`set_text` addresses the plugin-provided text key directly.
The SDK indexes the current and next trees once and uses longest-increasing-
subsequence reconciliation for O(n log n) keyed movement. The renderer validates
the complete patch in a copy-on-write key-graph overlay, then commits the DOM in
one animation frame. Failed validation cannot partially mutate the DOM. Focus,
selection, IME, scroll, canvas identity, edit revisions, and first-commit
visibility retain their existing semantics.

Bridge v5 uses one closed render budget: 512 KiB of canonical JSON per message,
1,024 operations per atomic patch, 4,096 rendered nodes, and 32,768 JSON
structural nodes. The schema generates the matching SDK, renderer, package
validator, and performance-harness constants; no layer carries an independent
limit.

The renderer owns a private liveness channel to the plugin worker. It sends a
ping every 10 seconds and requires the matching pong within 5 seconds; timeout
fails the surface closed. During disposal the parent sends a unique quiesce id,
the plugin bridge awaits all async lifecycle observers, and the renderer returns
an acknowledgement before teardown. The parent bounds that persistence window
to 1.5 seconds before continuing revocation.

Canvas and decoded-image resources are governed by the generated bridge render
policy shared with Go package validation. A surface may transfer at most four
canvases, each dimension is at most 4096 pixels, aggregate canvas area is at
most 16,777,216 pixels, and pointer movement is capped at 120 events per second.
PNG, JPEG, GIF, and WebP are identified from their bytes, independent of the
package filename or declared MIME, and dimensions are read before decode. At
most 32 images and 33,554,432 decoded pixels are allowed. The hardened worker
cannot construct additional `OffscreenCanvas` values or call
`createImageBitmap`. Form actions prevent native sandbox submission and emit
one bounded typed payload even when a submit button contains nested visual
elements.

Lazy assets are addressed across the worker boundary by opaque `binding_id`
values derived by the package builder and carried in the prepared surface
document. The parent-side HTTP request contains that binding rather than a
caller-selected path. The Go Host resolves the bound path and digest from the
prepared-document cache keyed by active fingerprint, entry path, and entry
digest, then revalidates path, size, content type, and package bytes before returning them to the trusted
renderer.

## Contracts

Machine-readable contracts are first-class platform artifacts:

- `spec/openapi/plugin-platform-v5.yaml`;
- `spec/plugin/manifest-v5.schema.json`;
- `spec/plugin/package-signature-v1.schema.json`;
- `spec/plugin/release-metadata-v5.schema.json`;
- `spec/plugin/source-policy-v1.schema.json`;
- `spec/plugin/source-revocations-v1.schema.json`;
- `spec/plugin/token-ticket-v2.schema.json`;
- `spec/plugin/bridge-v5.schema.json`;
- `spec/plugin/opaque-surface-document-v3.schema.json`;
- `spec/plugin/opaque-surface-transport-v4.schema.json`;
- `spec/plugin/compatibility-manifest-v5.schema.json`;
- `spec/plugin/release-manifest-v3.schema.json`;
- `spec/plugin/performance-contract-v1.json`;
- `spec/plugin/performance-evidence-v1.schema.json`;
- `spec/plugin/ipc-v3.schema.json`;
- `spec/plugin/wasm-worker-v2.schema.json`;
- `spec/plugin/worker-invocation-v2.schema.json`;
- `spec/plugin/network-grant-v1.schema.json`;
- `spec/plugin/error-codes-v3.schema.json`;
- `spec/plugin/target-classifier-v2.json`;
- `spec/plugin/contract-registry-v1.json`, the generated inventory and SHA-256
  identity for every public contract above.

`redevplugin version` emits the compatibility manifest for the current artifact
set. `redevplugin verify-compatibility <compatibility.json> <artifact-root>`
checks the version matrix and contract hashes before a host product consumes a
published dependency set.

`PluginSurfaceHost.open()` applies one aggregate opening deadline across frame
load, surface preparation, port acknowledgement, initial lease minting, first
paint, and worker readiness. A deadline failure aborts parent transport,
revokes the server surface, clears the iframe and ports, and records one crash in
the shared reload limiter so a host can perform a bounded retry without retaining
stale authority.

The plugin-platform OpenAPI contract defines release-reference management routes
and opt-in local-import package routes. Local-import install/update requests are
for explicitly named local, developer, or import flows and still run through the
same manifest validator, trust verifier, staged install, lifecycle, audit, and
diagnostic path, but they are not part of the default route set. Official or
registry-backed product installs should call
`install-release-ref` / `update-release-ref` with a `PluginReleaseRef`; the host
source policy resolver freezes the source policy snapshot before the artifact
resolver runs. The artifact resolver receives that snapshot and returns only an
untrusted artifact handle plus signed release-metadata bytes and signature
bytes. ReDevPlugin verifies and closed-world decodes that metadata, derives the
canonical release, then verifies package hash, manifest, entries, package
signature/trust result, compatibility, and identity before mutating the
registry.

The manifest defines the complete PluginData shape. Update and downgrade may
switch package code only when the target shape hash is identical to the active
shape; a different settings or storage schema requires a new plugin identity.
Opaque bundle import verifies owner identity, shape hash, content hash, and the
target management revision before publishing a new generation.

## Runtime State Model

ReDevPlugin uses explicit authorities instead of implicit process memory:

- registry records track installed plugin package and lifecycle state;
- staged install records capture pre-commit install/update progress;
- PluginData keeps generation bindings, non-secret settings, files, KV, SQLite,
  retained data, and export object metadata;
- secret binding stores track secret references without secret plaintext;
- registry authorization snapshots drive permission, policy, and revoke epochs;
- confirmation intent stores keep dangerous-method approval state without
  persisting raw confirmation token capabilities and atomically consume either
  an approved intent or a scope-matched trusted-parent rejection;
- operation and stream stores keep observable long-running work and buffered
  events;
- observability stores persist audit and diagnostic events.

Memory and durable store APIs expose immutable value boundaries. Registry,
operation, stream, execution-binding, and event data returned to callers are
deep copies, so a host adapter or UI projection cannot mutate stored authority
through a retained map, slice, pointer, or byte buffer.

Operation cancellation is recorded before execution-side dispatch. The Host
marks the operation `cancel_requested`, writes audit evidence, and signals the
live execution lease. The lease captures the optional route-local
`OperationCanceler` when the capability adapter, core action, or runtime
supervisor starts the operation. A failing hook returns a dispatch error while
the durable request remains recorded. An inactive persisted operation has no
execution owner and is never redispatched through a capability registry.

Confirmation rejection follows the same ownership rule. The trusted parent
submits the opaque confirmation id through the bound surface route. The Host
validates the current gateway token and exact owner-session, surface, bridge,
fingerprint, policy, management, and revoke bindings before the confirmation
store atomically deletes the intent. A mismatched rejection leaves the intent
untouched. A successful rejection records `plugin.method.rejected` with the
stable `confirmation_rejected` reason and never enters the business adapter.

External host capability contracts are verified before package binding. One
exact pin covers the contract, manifest, signature, compatibility metadata,
generated TypeScript client, notices, publisher key id, policy epoch, and
revocation epoch. The Host freezes that pin together with plugin identity,
surface/session scope, permission and confirmation evidence, quota, revisions,
target descriptor hash, and audit correlation into `ExecutionBinding` before
calling a business adapter. Operation and stream records are allocated first;
the adapter receives only scoped sinks and cannot select ids or mutate global
stores. Every binding declares `route_kind`. Only `capability` bindings contain
an exact host capability contract pin; `worker` and `core_action` bindings omit
that field and carry explicit empty permission arrays instead of invalid zero
pins or JSON `null` evidence.

The artifact format is machine-defined by separate closed schemas for the
contract, pin, manifest, compatibility document, signature envelope, and
notices list. Release metadata and OpenAPI reuse the canonical pin schema rather
than copying its fields. Verification recomputes every digest, verifies the
manifest signature and epochs, regenerates the plugin-side TypeScript client,
and compares its bytes before registry mutation. Go and TypeScript validators
consume one restricted-schema conformance fixture so generated request,
response, target, and business-error details cannot drift across languages.

Operation methods allocate one operation record. Subscription methods allocate
both an operation record and a stream record before dispatch, and every worker,
lease, ticket, HTTP, trusted-parent, and plugin-side projection preserves that
paired ownership. Business adapters report host-owned errors through the
ReDevPlugin stable error envelope; capability id, capability version, details
schema digest, code, and validated details remain bound end to end.

Worker dispatch adds `params_sha256` to the closed invocation payload and
derives an `invocation:sha256:*` target from a fixed-order, length-prefixed
descriptor. That target is included in the signed runtime lease. Rust hashes
the exact received `params` JSON, rebuilds the descriptor, and requires one
exact match in `target_descriptor_hashes` before replay consumption or artifact
access. The replay cache retains lease ids only until their signed expiry and
has a fail-closed hard capacity.

Stream stores must implement non-destructive `Observe` and revision-aware
`Wait`; polling-only stores are not accepted. Append, close, and plugin-state
transitions increment the stream revision and notify waiters. Reads wait without
holding the lifecycle lock, then acquire the plugin read lock, revalidate the
registry and surface session, observe, perform one bounded read, and decide the
single-use ticket from `ReadObservation`. Failure preserves the event queue and
current ticket, an open or non-drained stream rotates to exactly one next ticket,
and a drained terminal stream commits without allocating a replacement. Records
track `next_sequence`, revision, buffered events, and both byte and event limits.
Operation and stream
terminal writes are independently durable; startup and later execution
entrypoints reconcile either partial terminal state, including after reopening
SQLite stores, before the live execution lease is released.

Method result `data` is normalized at the Host boundary. Capability, worker,
and core-action routes share `capability.PrepareResponseData` before data is
returned through `CallPluginMethod` or the mountable HTTP adapter. It performs
a structural budget pass over native Go values, followed by JSON marshal and
strict decode before redaction. The resulting independent data tree rejects
duplicate or prototype-sensitive keys, unsafe numbers, cycles, non-JSON values,
excessive depth, excessive node count, and oversized payloads. The redacted
canonical tree is checked a second time, so replacement values cannot expand the
public response beyond the same fixed limits. A custom `MarshalJSON` or
`MarshalText` implementation is host-adapter code; encoded output is checked by
the same strict decoder, while custom method execution remains inside the host
process and therefore outside the platform's resource isolation boundary.
Custom `IsZero` methods on `omitzero` response fields are rejected rather than
observed twice; ordinary `reflect.Value.IsZero` semantics remain supported.
Normal results and published business-error details use this same pipeline before
schema validation.

Errors crossing a method adapter boundary are traversed once without invoking
adapter `Error`, `Is`, or `As` methods and projected into a private immutable Host
failure. The projection retains only allowlisted platform sentinels, a validated
worker failure attested at `RuntimeManager.InvokeWorker`, an attested capability
business error, and an explicit mutation outcome. Operation cleanup, rejection
reporting, Go callers, and the HTTP adapter consume that projection; none of them
retain or revisit the adapter error graph. A capability, policy, registry, or
core-action adapter cannot forge either structured error type.

The platform does not claim cross-store database transactions. When a workflow
touches multiple stores, it must record durable stage, cleanup, audit, or
diagnostic evidence so repair and retry behavior remains explicit.

## Host Integration Shape

A host product should:

1. import published ReDevPlugin Go and TypeScript versions;
2. select a published `redevplugin-runtime` artifact for the current platform;
3. register session, origin, CSRF, storage-root, vault, audit, diagnostics,
   runtime artifact, and business capability adapters;
4. mount `pkg/httpadapter` routes or call the Go Host APIs directly;
5. expose product UI around the host-neutral SDK instead of forking platform
   protocols;
6. verify compatibility and release artifacts before upgrading.

Local sibling path wiring, `go.work`, `replace`, `file:`, `link:`,
`workspace:`, `portal:`, Rust path overrides, copied source trees, or hidden
build aliases are not supported integration paths.
