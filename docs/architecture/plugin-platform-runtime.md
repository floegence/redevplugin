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
- dedicated-origin Web bootstrap, verified application documents, asset tickets and
  sessions, typed `MessagePort` bridge messages, Execution/Event envelopes,
  and TypeScript SDK helpers;
- one Host-owned control database for installed facts, authorization,
  Execution/Event, confirmation, and runtime control state;
- one internal Host/runtime wire, WASM worker ABI validation, brokered resource
  I/O, runtime revocation state, and worker invocation payload contracts;
- canonical OpenAPI and JSON schemas, plus one externally staged and signed
  `PlatformReleaseManifest` containing the exact release artifact hashes.

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

Manifest v9 methods are executable contracts, not descriptive metadata. Both
request and response schemas are closed draft 2020-12 object schemas compiled
during package validation. Manifest decoding and Host calls share one process-wide
LRU keyed by exact serialized schema content and request/response resource identity.
It retains at most 1,024 compiled validators and 8 MiB of source keys; unsuccessful
compilations and oversized cache entries are not retained. Every call still checks
the closed subset and schema limits. Compiled validators own their content and
contain no plugin, session, permission, or trust authority. The Host rejects
request mismatches before dispatch, canonicalizes and redacts adapter/runtime
data, and rejects response mismatches before an execution result becomes visible.

Manifest v9 surfaces express only host-neutral `view`, `command`, or
`background` roles plus optional `primary`, `secondary`, or `utility` intent.
They do not encode product placement. A host maps those roles into its own
navigation, workspace, settings, or command UI.

## Core Go Packages

The Go module `github.com/floegence/redevplugin/v3` exposes the embeddable Host
library and platform contracts.

`pkg/bridge` owns token/ticket audiences, MessageChannel handshake state,
surface credentials, and runtime leases. Active surface sessions are
bounded globally and per owner, duplicate ids are rejected, and expired
session/token state is pruned rather than retained indefinitely. A gateway
token cannot be minted until the Host has completed closed-document preparation
and marked that exact asset session prepared.

- `pkg/manifest` validates the plugin manifest model and cross-field
  references.
- `pkg/pluginpkg` reads and writes deterministic packages, validates Web roots,
  HTML entries and exact package resources, rejects
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
  surface opening and final Event commits take the read lock. Release
  resolution and package validation occur outside the lock and commit only after
  the registry revision is revalidated. Every fresh or repeated installation,
  including external packages, commits through the same atomic plugin-data and
  tombstone transaction; external-package update persistence cannot create a
  new installed record.
- `pkg/releasetrust` owns current release-document verification. A validated,
  immutable source configuration and root Ed25519 key are the trust inputs.
  Release metadata and package signatures bind exact SHA-256 digests and the
  current source policy and revocation epochs. Invalid, expired, or revoked
  documents fail closed; no local trusted-time, transparency ledger, publisher
  continuity, or activation-lease state participates in admission.
- `pkg/releasepublisher` creates a recoverable sequence of public external
  signer requests, verifies closed Ed25519 responses, and emits an immutable
  release asset set plus its exact locator-to-asset projection. It never accepts
  signer commands, credential references, storage locations, or account data.
- `pkg/remoterelease` binds that locator projection to reviewed HTTPS URLs,
  exact sizes, and SHA-256 values. It implements the release-document and Host
  artifact resolver interfaces over the hardened
  `pkg/externalsource` downloader, including an exact allowed-host check before
  every redirect hop. Concurrent reads of one immutable asset digest share one
  in-flight fetch; every caller receives owned bytes only after the existing
  size and SHA-256 checks succeed. A canceled waiter does not cancel the owner,
  and failed or invalid results are not cached. Release providers retain
  package bytes; ReDevPlugin verifies them after direct download.
  The hardened downloader reuses an idle HTTPS connection only when a later
  request has re-resolved the same exact origin to the same sorted public IP
  pin set. Origin or pin changes use a distinct transport; the pool is bounded
  to 32 entries with a 30-second idle timeout.
- `pkg/httpadapter` provides mountable host-neutral HTTP routes for platform
  management, Execution/Event reads and cancellation, surface
  prepare/token/dispose, parent-only POST asset transport, and
  diagnostics.
- `internal/runtimeclient` manages the Rust runtime subprocess, exact
  `internal_wire=1` Hello/HelloAck binding, framed IPC, invocation cancellation, and runtime
  health/cache metrics. A `Manager` must bind its required `RuntimeHostServices`
  exactly once before it can create or start shards; Host supplies the same
  execution/event sink used by capability dispatch. Runtime configuration
  therefore cannot omit event delivery or infer a shard count from a zero value.
- `pkg/plugindata` owns settings, storage generations, immutable exports, and
  retained bindings. One Host-owned control SQLite owns installed plugin,
  authorization, execution/event, confirmation, and session lifecycle state.
- `host.NewEnvironmentResetOwnershipManifest`, `PreflightEnvironmentReset`,
  and `ResetEnvironment` form the stopped-environment destructive maintenance
  boundary. A cross-process Host lock excludes live execution. The canonical
  manifest accepts only fixed platform-owned categories and paths; tampering,
  symlinks, broad roots, or unknown categories fail closed. Reset removes no
  host-product file and initializes fresh control and PluginData stores without
  importing retained data, grants, catalog state, or execution records.
- `pkg/protocol` tests keep OpenAPI, schemas, route fixtures, Go DTOs,
  TypeScript SDK bindings, Rust IPC, WASM ABI, and compatibility hashes aligned.

### Release Document Cache

Hosts can open `remoterelease.OpenDocumentCache(ctx, absolutePath)` once per
state root and pass it as `AssetSetOptions.DocumentCache` to each immutable
release projection. Close it after the Host and release operations stop. A host
may continue without this optional cache if opening it fails.

The platform owns the SQLite layout in
`spec/internal/release-document-cache.sql`: lineage
`redevplugin_release_documents`, schema 1. It is a new disposable cache, not a
migration of the control database or installed plugin state. Empty interrupted
creation recovers transactionally; an unknown lineage, future schema, or extra
schema object fails without changing the existing database. Each document is at
most 1 MiB, with FIFO eviction at 128 entries or 8 MiB of payload. Transactions
preserve committed entries across interruption; the database page quota bounds
storage growth. Cache misses and read/write failures use the existing bounded
remote transport.

Only release documents are retained. A cache hit must match the **current**
reviewed asset projection's exact SHA-256 and size. Signature, expiry, policy,
revocation, owner and execution checks are unchanged and are performed by their
existing authorities. The cache contains no tokens, trust decisions or plugin
packages. It does not discover a newer release or make a stale market snapshot
fresh. A changed projection cannot reuse old bytes at the same locator.

Startup recovery can therefore validate already-downloaded trust documents
locally while the runtime starts, instead of repeating five sequential network
round trips after every process restart. Initial downloads and changed or
expired trust evidence retain their normal verification and failure behavior.

### Runtime Recovery

When `Host.Open` has no user session, the Host reads an internal persisted
worker catalog and starts bounded compilation prewarming immediately. This uses
the same verified process admission, security journal, health verification and
rollback path as explicit runtime startup. It does not create a synthetic
session, invoke a worker, issue a lease, activate connectivity, publish surfaces,
or complete an authorized recovery snapshot. Each plugin is rechecked under its
lifecycle read lock before compilation. Disabled, deleted, replaced and
non-runnable records are skipped. Four workers share a 25-second startup budget;
Host closure cancels and awaits the work. Empty catalogs leave the process lazy.
`plugin.runtime.prewarmed` records successful module preparation timestamps;
`plugin.runtime.prewarm_failed` reports bounded failure evidence. Neither event
is an authorization or recovery-ready signal.
The existing content-addressed runtime module cache shares compilation with
subsequent authenticated preparation without changing execution admission.

The Go Host is the only runtime recovery owner. `RecoverEnabled` reads the
authoritative installed records, restores enabled runtimes idempotently, and
publishes one revisioned `RecoverySnapshot`. User interfaces may read that
snapshot and explicitly retry a failed plugin, but they do not maintain a
second catch-up scheduler or infer recovery from catalog state. A new install
performs its own activation and never waits for a UI recovery pass.
A failed or canceled recovery publishes no partial surface snapshot. Signed
release and revocation facts remain authoritative; recovery never creates
fallback authorization.

Surfaces remain available while a backend is starting or unavailable. Before
dispatching an authorized worker method or resolving its confirmation target,
the Host waits for runtime startup, compatible binding, worker prewarming, and
connectivity policy installation. Concurrent calls for the same plugin share
this preparation; canceled waiters leave without dispatch. Successful
preparation is reused only for the exact environment owner, plugin fingerprint,
authorization revisions, and runtime binding. A new runtime generation requires
fresh preparation. Preparation does not retry an executed method or replace
execution admission, permission checks, or generation-bound confirmation.

The Host library must remain host-neutral. It must not import a host product,
know product navigation, or assume a particular vault, filesystem root,
business resource, desktop shell, or UI surface.

## Rust Runtime

The public Rust workspace boundary contains `redevplugin-runtime` and
`redevplugin-worker-sdk`. IPC framing and WASM ABI validation are private
runtime modules; target classification remains owned by the Go connectivity
layer. The runtime is launched by the Go Host through `internal/runtimeclient`.
Worker authors pin the SDK to the same immutable release as the Host/runtime.
ReDevPlugin publishes versioned source crates for this boundary. Host products
build the runtime binary from exact published Rust source crates after verifying
registry checksums, source identity, dependency metadata, and the platform
contract digest; they do not download an upstream OS binary or replace the
platform supervisor.

The current IPC model is supervised stdin/stdout newline JSON. The Host remains
the authority for identity, policy, grants, quotas, revocation, storage, and
network access. The runtime validates WASM worker shape, executes the exported
worker entrypoint with Wasmi, and performs brokered hostcalls through Host-owned
IPC request/response frames.

The current internal wire uses one Go reader, one serialized pipe writer, and a
pending map keyed by `request_id`; a worker invocation does not hold a
process-wide IPC mutex. Runtime-origin artifact and generic Hostcall frames
include `parent_request_id` and are accepted only while the matching signed
invocation is live. The Host resolves the invocation ID to its verified
audience, permissions, resource scope, broker access, revisions, and revoke
epoch before any I/O. Artifact loading additionally uses bounded
`compile_flight_register` and `compile_flight_complete` routes pre-registered by
the Host for the exact runtime generation, parent request, package, artifact,
digest, and plugin API. A registered compile flight may finish after its leader is
canceled without granting any other hostcall authority; unknown or mismatched
routes invalidate the runtime generation. Active hostcall and compile-flight
artifact route capacities equal the negotiated `worker_count`; canceled
hostcall retention equals `worker_count + queue_capacity`. Canceled routes do
not consume active capacity, and retention exhaustion invalidates the runtime
generation instead of silently evicting an authorization record.
`cancel_invoke` removes queued work or
marks running work canceled; the runtime acknowledges cancellation and remains
ready for unrelated work.

The Host must supply `RuntimeLimits` within the platform min/max contract;
`per_plugin_concurrency` must not exceed `worker_count`, and cached source WASM
is capped at 128 MiB. `DefaultRuntimeLimits()` creates an explicit value with
worker count `clamp(GOMAXPROCS, 4, 16)`, queue capacity to
`min(worker_count * 4, 64)`, and per-plugin concurrency to
`min(max(worker_count / 2, 2), 8)`. Go admission waits
before consuming the execution lease. Rust enforces the same hello-negotiated
limits with a fixed worker pool and round-robin per-plugin queues. Capacity and
cancellation are reported separately as `RUNTIME_CAPACITY_EXCEEDED` and
`RUNTIME_INVOCATION_CANCELED`.

OpenAPI and the IPC Draft 2020-12 schema publish identical per-field bounds and
document `per_plugin_concurrency <= worker_count`. Standard JSON Schema has no
property-relative numeric keyword, so the Go and Rust parsers are authoritative
for that cross-field rule; the schemas do not expand it into a conditional table.

One Wasmi Engine is shared for the runtime generation. Validated modules are
single-flight compiled and cached by artifact SHA-256 in a deterministic LRU,
with default limits of 64 modules and 128 MiB source WASM.
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

The Go supervisor derives a bounded context for runtime-origin Hostcalls before
entering host adapters. Workers import only `redevplugin.io`: `rdp_call_v1`
sends a closed `{plugin_api, operation, arguments}` control envelope, while the
read, write, seek, close, and last-error functions operate on opaque resource
handles. Storage files, KV, and SQLite control operations are dispatched by the
Host to the plugin-data namespace after validating the registered method access
and resource scope. HTTP, WebSocket, TCP, and UDP use the same current resource
control/read/write path. No separate storage, network, handle-grant, or network
grant frame families exist on the internal wire.

The supervisor maintains the control channel with `heartbeat` IPC frames. The
default interval is 2 seconds and the default max-staleness window is 5 seconds.
Heartbeat ACKs return the runtime generation, runtime timestamp, host timestamp
echo, and max-staleness window. If the runtime cannot acknowledge within the
window, the supervisor invalidates and kills that runtime generation.
The Rust runtime also tracks the last valid heartbeat or revocation control
frame. Once that max-staleness window is exceeded, it rejects new worker
invocations before opening artifacts and rejects new resource Hostcalls before
dispatching Host I/O.

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
execution mode, Host-owned execution id, audit correlation id,
surface and owner context, target descriptor hashes, quota limits, policy
revisions, revoke epoch, expiry, `lease_nonce`, `key_id`, and runtime audience
fields. `MintRuntimeExecutionLease` returns separate `lease_id` and display
`token_id` values plus the same metadata, and worker-route dispatch records a
`plugin.runtime.lease.issued` Host audit event with the bound identifiers,
runtime audience, revisions, descriptor hashes, and expiry.

The Go supervisor verifies the current runtime audience and Ed25519 signature
before writing IPC. Rust requires the startup keyring and independently verifies
the signature, lease expiry, method/effect/execution mode, execution identity,
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

Runtime teardown is fail-safe and never performs preflight, artifact
verification, or process startup. Plugin and session revocation treat a
never-started or already stopped shard as a zero-count terminal result after an
idempotent stop succeeds. Session aggregates omit stopped shards because no IPC
acknowledgement exists for them and set `RuntimeStopped`; a stop failure remains
an error so Host session fencing stays durably incomplete until reconciliation.
This keeps disable, uninstall, and session close usable when the configured
runtime artifact is absent without weakening active-runtime acknowledgement
checks.

The runtime connection binds one exact `internal_wire=1` through Hello and
HelloAck. Subsequent frames do not repeat a wire or ABI version. Plugin workers
select the current WASM ABI only through `plugin_api=1`; runtime generation,
Host-issued channel nonce, lease nonce replay cache, heartbeat staleness, and
revoke epoch remain per-connection security facts rather than compatibility
axes.

The runtime wire has executable golden fixtures in `testdata/contracts/ipc/`.
Go Host tests and Rust runtime tests validate the current Hello/HelloAck and
runtime response frames and reject wire mismatch before binding, missing request IDs, replayed request
IDs, unknown frame types, and mismatched runtime generations.

Any incompatible Host/runtime combination must fail closed with a diagnostic
error instead of silently running a plugin.

## TypeScript Surface Package

The released @floegence/redevplugin-ui package provides the surface slot and
host handle, plugin-side bridge, generated management client, and author test
helpers. Each plugin view is an ordinary Web document on a dedicated origin.
There is one current runtime path, with no virtual-node compatibility renderer.

The platform allocates a random hostname per live surface through the
host-provided SurfaceOriginAdapter, owns the single-use entry and short-lived
resource session, and exposes NewWebSurfaceHandler for the isolated origin.
Host products provide routing and TLS. Package resources are resolved and
revalidated by the platform, never by a product-local package parser.

The trusted bootstrap verifies browser network confinement before executing
application code. Source, exact origin, frame generation, and a transferred
MessagePort bind the parent handshake. Parent-only gateway credentials remain
outside application JavaScript. The application uses native DOM, events,
modules, Workers, Canvas, WebGL, WASM, and origin-local cache storage.
Privileged calls retain the same permission and execution contract.

PluginPlatformClient.openSurfaceInSlot owns replacement and teardown. Opening
is bounded independently of layout or paint. Async lifecycle observers receive
a bounded close opportunity; revocation and expired leases close authority.
Application interaction observations describe placement/focus intent only and
cannot authorize capabilities. Each file export receives a host decision.

See docs/ui/plugin-surface-sdk.md for supported APIs, browser admission,
resource policy, storage lifetimes, navigation limits, and the acceptance suite.

## Contracts

Machine-readable contracts are first-class platform artifacts:

- `spec/openapi/plugin-platform.yaml`;
- `spec/plugin/manifest-v9.schema.json`;
- `spec/plugin/plugin-api.json`;
- `spec/plugin/wasm-abi.json`;
- `spec/plugin/worker-invocation.schema.json`;
- `spec/internal/runtime-wire.schema.json`;
- `spec/plugin/package-signature-v1.schema.json`;
- `spec/plugin/release-metadata.schema.json`;
- `spec/plugin/release-root-delegation-v1.schema.json`;
- `spec/plugin/release-publisher-config-v1.schema.json`;
- `spec/plugin/publisher-release-ref-v1.schema.json`;
- `spec/plugin/external-signer-request-v1.schema.json`;
- `spec/plugin/external-signer-response-v1.schema.json`;
- `spec/plugin/release-source-policy-v3.schema.json`;
- `spec/plugin/release-source-policy-pointer-v2.schema.json`;
- `spec/plugin/release-revocation-v3.schema.json`;
- `spec/plugin/release-revocation-pointer-v2.schema.json`;
- `spec/plugin/token-ticket-v4.schema.json`;
- `spec/plugin/bridge.schema.json`;
- `spec/plugin/web-surface-document.schema.json`;
- `spec/plugin/web-surface-transport.schema.json`;
- `spec/plugin/runtime-admission-v1.schema.json`;
- `spec/plugin/process-containment-v1.schema.json`;
- `spec/plugin/runtime-exec-journal-v1.schema.json`;
- `spec/plugin/network-grant-v2.schema.json`;
- `spec/plugin/resource-scope-v1.schema.json`;
- `spec/plugin/session-scope-v1.schema.json`;
- `spec/plugin/session-scope-maintenance-v1.json`;
- `spec/plugin/error-codes.schema.json`;
- `spec/plugin/target-classifier-v2.json`.

The release generator enumerates the exact `spec/` tree and records each file's
SHA-256 in the externally staged `PlatformReleaseManifest`. There is no separate
contract registry, compatibility matrix, package set, or runtime descriptor.

The performance quality gate measures route authorization with nine adjacent,
balanced AB/BA baseline/candidate pairs. Concurrency one retains
per-request P95 and P99 latency evidence. Concurrency 100 and 1000 use complete
batch elapsed time per request so scheduler and VM pauses affecting individual
goroutines cannot masquerade as handler tail regressions. Each comparison
attempt records the fixed run order, exact raw profiles, canonical hashes,
runner environment, and deterministic noise qualification. Only a noisy
attempt may retry, at most three attempts are permitted, and the accepted
attempt must be the final qualified attempt. Performance configuration and
evidence remain test inputs; they are not public contracts or release artifacts.

The HTTP connection reuse probe uses nine fixed repetitions of 64 paired
AB/BA batches with four requests per batch. It compares the median of the
nine pooled P95 values with the median of the nine connect P95 values, using
the unchanged 70% limit. Every repetition is measured before the assertion;
there is no retry-until-pass policy. One pooled connection and exactly one
connection per unpooled request remain mandatory.

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
registry-backed product installs obtain display-ready presentation and permission
evidence from the market, then call `executions/release-installs` once with the
exact `PluginReleaseRef` and its declaration digests. ReDevPlugin recomputes the
canonical release-reference identity digest before accepting the task. The host
source policy resolver freezes the source policy snapshot before the artifact
resolver runs. The artifact resolver receives that snapshot and returns only an
untrusted artifact handle plus signed release-metadata bytes and signature bytes.
ReDevPlugin verifies and closed-world decodes that metadata, derives the canonical
release, then verifies package hashes, signatures, trust, compatibility, identity,
and the declared permission summary before registry mutation. Updates continue to
use `update-release-ref`.

The manifest defines the complete PluginData shape. Update and downgrade may
switch package code only when the target shape hash is identical to the active
shape; a different settings or storage schema requires a new plugin identity.
Opaque bundle import verifies owner identity, shape hash, content hash, and the
target management revision before publishing a new generation.

## Runtime State Model

Ordinary settings require only Core. A requested owner scope without secret
fields returns an empty `secret_metadata` array without contacting a vault. If
that scope declares secret fields, the configured Secrets module is their sole
metadata authority; a missing module returns the existing feature-not-configured
error. Settings patches resolve this metadata before committing values, so a
known unavailable secret authority rejects the operation without changing the
settings revision. Secret binding and settings values retain separate authority.

ReDevPlugin uses explicit authorities instead of implicit process memory:

- control records track installed plugin package, lifecycle, grants, runtime,
  and Execution/Event state;
- PluginData keeps generation bindings, non-secret settings, files, KV, SQLite,
  retained data, and export object metadata;
- secret binding stores track secret references without secret plaintext;
- registry authorization snapshots drive permission, policy, and revoke epochs;
- confirmation intent stores keep dangerous-method approval state without
  persisting raw confirmation token capabilities and atomically consume either
  an approved intent or a scope-matched trusted-parent rejection;
- observability stores persist audit and diagnostic events.

Authenticated session shutdown has two distinct durable stages. Revocation
fences the exact four-hash session scope and drains platform admissions;
finalization is allowed only after the independently versioned lifecycle
maintenance adapter proves that the exact authenticated channel is terminal.
The Go-only maintenance API can start a fresh close, resume an existing
teardown, or finalize a completed fence without browser authorization state.
Legacy lifecycle adapters keep their completed fences and never opt into this
automatic path implicitly.

Finalization persists the adapter phase as `finalizing`, cleans platform-owned
tombstones, and then deletes the exact platform fence. Fence deletion is the
commit point. Adapter record removal is idempotent post-commit cleanup, so a
lost response or cleanup failure can resume without recreating session
authority. Startup compares the exact adapter and fence snapshots and rejects
unknown phases, missing records, identity mismatches, or any state combination
outside `spec/plugin/session-scope-maintenance-v1.json` without mutation.

Memory and durable store APIs expose immutable value boundaries. Registry,
execution, execution-binding, and event data returned to callers are
deep copies, so a host adapter or UI projection cannot mutate stored authority
through a retained map, slice, pointer, or byte buffer.

Execution cancellation is recorded before execution-side dispatch. The Host
marks the execution `cancel_requested`, writes audit evidence, and signals the
live execution lease. The lease captures the optional route-local
cancel hook when the capability adapter, core action, or runtime supervisor
starts the execution. A failing hook returns a dispatch error while the durable
request remains recorded. An inactive persisted execution has no
execution owner and is never redispatched through a capability registry.

Confirmation rejection follows the same ownership rule. The trusted parent
submits the opaque confirmation id through the bound surface route. The Host
validates the current gateway token and exact owner-session, surface, bridge,
fingerprint, policy, management, and revoke bindings before the confirmation
store atomically deletes the intent. A mismatched rejection leaves the intent
untouched. A successful rejection records `plugin.method.rejected` with the
stable `confirmation_rejected` reason and never enters the business adapter.

Host capability contracts are registered in a closed local registry before
package binding. One exact pin covers the contract bytes and identity. The Host
freezes that pin together with plugin identity,
surface/session scope, permission and confirmation evidence, quota, revisions,
target descriptor hash, and audit correlation into `ExecutionBinding` before
calling a business adapter. One execution record is allocated first;
the adapter receives only scoped sinks and cannot select ids or mutate global
stores. Every binding declares `route_kind`. Only `capability` bindings contain
an exact host capability contract pin; `worker` and `core_action` bindings omit
that field and carry explicit empty permission arrays instead of invalid zero
pins or JSON `null` evidence.

The local registry format is machine-defined by closed contract and pin
schemas. Release metadata and OpenAPI reuse the canonical pin schema rather
than copying its fields. Registration recomputes the contract digest before any
binding is accepted. Go and TypeScript validators consume one restricted-schema
conformance fixture so generated request, response, target, and business-error
details cannot drift across languages.

Every asynchronous method allocates one execution record before dispatch.
Progress, output, and terminal state are ordered Events under its cursor; an
internal transport stream may buffer bytes but cannot define another public
identity or lifecycle. Every worker, lease, HTTP, trusted-parent, and plugin-side
projection preserves that execution identity. Business adapters report
host-owned errors through the
ReDevPlugin stable error envelope; capability id, capability version, details
schema digest, code, and validated details remain bound end to end.

Worker dispatch adds `params_sha256` to the closed invocation payload and
derives an `invocation:sha256:*` target from a fixed-order, length-prefixed
descriptor. That target is included in the signed runtime lease. Rust hashes
the exact received `params` JSON, rebuilds the descriptor, and requires one
exact match in `target_descriptor_hashes` before replay consumption or artifact
access. The replay cache retains lease ids only until their signed expiry and
has a fail-closed hard capacity.

Event reads use an opaque cursor and revision-aware waiting; polling-only public
observation is not accepted. Appends and terminal transitions advance the same
Execution/Event cursor and notify waiters. Reads wait without holding the
lifecycle lock, then revalidate registry and surface-session authority before
returning one bounded batch. A failed read preserves the event queue and cursor.
Execution terminal state and its final Event are committed through the same
control transaction before the live execution lease is released.

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

1. import the published ReDevPlugin `/v3` Go module and matching TypeScript packages;
2. verify the signed `PlatformReleaseManifest` and exact artifact hashes;
3. build the runtime binary from verified published source crates with a fixed
   product toolchain, then sign and bundle that product-owned binary;
4. register session, origin, CSRF, storage-root, vault, audit, diagnostics, and
   business capability adapters;
5. mount `pkg/httpadapter` routes or call the Go Host APIs directly;
6. expose product UI around the host-neutral SDK instead of forking platform
   protocols;
7. require exact platform release identity before upgrading.

Local sibling path wiring, `go.work`, `replace`, `file:`, `link:`,
`workspace:`, `portal:`, Rust path overrides, copied source trees, or hidden
build aliases are not supported integration paths.

### Startup preparation diagnostics

Sessionless Worker prewarming emits `plugin.runtime.prewarmed` after validated
module compilation or `plugin.runtime.prewarm_failed` when catalog, runtime,
or module preparation fails. These events use the closed observability
presentation contract and the normal durable and host-projected sinks. They
carry stable plugin identities and the `startup_prewarm` operation, never raw
adapter errors or synthetic authenticated session identities. A completion event
reports compilation only; it does not authorize execution or publish a surface.

## Explicit retained-data recovery

The Host exposes inspect, commit, and read-only status operations for a retained
installation and a different, explicitly disabled installation of the same
publisher, plugin, and data shape. Inspection binds both generation/binding
identities, the target management revision and active fingerprint, and the
stable authenticated environment/user owners. Commit expires after 15 minutes;
status remains usable after a Host restart and authenticates the same owners.

The existing catalog transaction exchanges the generation references without
moving files. The previous target generation stays retained under the source
installation identity. Both binding revisions advance in their own identity
lineage; target management revision and revoke epoch advance atomically.
Recovery takes both instance write locks, waits for existing readers, and keeps
publication/collection serialized. Expired source data and stale source, target,
shape, fingerprint, or owner evidence fail before commit. Concurrent cleanup
using the previous retained binding cannot delete its replacement.

A commit is never replayed. Lost responses are reconciled by comparing the exact
expected post-state through the status query; subsequent conflicting lifecycle
changes return PLUGIN_RETAINED_RECOVERY_CONFLICT. SQLite commit errors whose
outcome cannot be proven are unknown mutations. Failed transactions retain both
original bindings. The control schema and Rust wire are unchanged.

Recovery leaves the target disabled and transfers no grants, credentials,
approvals, tokens or live surfaces. Hosts present the retained source and current
target before the explicit action, then offer enablement separately. Retained
user-scoped namespaces keep their original user ownership inside the generation.
