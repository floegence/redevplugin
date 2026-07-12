# ReDevPlugin Runtime Architecture

ReDevPlugin is a host-neutral plugin platform. Host products import published
ReDevPlugin Go, TypeScript, Rust runtime, and machine-contract artifacts; they
do not copy source, wire sibling checkouts into builds, or reimplement platform
state machines.

## Ownership Boundary

ReDevPlugin owns reusable extension mechanics:

- package layout, canonical package hashing, detached signatures, validation,
  and asset storage;
- plugin registry, install/update/enable/open/disable/uninstall lifecycle, data
  export/import, retained data, and cleanup orchestration;
- permission grants, security policy evaluation, confirmation outcomes,
  stable errors, audit events, and diagnostics;
- opaque iframe bootstrap, validated surface documents, asset tickets and
  sessions, typed `MessagePort` bridge messages, operation and stream envelopes,
  and TypeScript SDK helpers;
- storage, settings, observability, secret binding metadata, permission,
  cleanup, retained-data, and staged-install durable stores;
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

Manifest v2 methods are executable contracts, not descriptive metadata. Both
request and response schemas are closed draft 2020-12 object schemas compiled
during package validation. The Host keeps a bounded fingerprint+method LRU of
compiled validators, rejects request mismatches before dispatch, canonicalizes
and redacts adapter/runtime data, and rejects response mismatches before an
operation or stream becomes visible.

Manifest v2 surfaces express only host-neutral `view`, `command`, or
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
  network grants, runtime execution, retained data, cleanup, audit, and
  diagnostics through host-provided adapters. Official or registry-backed
  installs should use release references resolved by host-registered
  `ReleaseSourcePolicyResolver` and `ReleaseArtifactResolver` adapters; the Host
  still owns package reading, hash comparison, trust verification, staged
  install, registry mutation, audit, and diagnostics.
- `pkg/httpadapter` provides mountable host-neutral HTTP routes for platform
  management, surface prepare/token/dispose, parent-only POST asset and stream
  reads, compatibility, and diagnostics.
- `pkg/runtimeclient` manages the Rust runtime subprocess and newline-delimited
  JSON IPC frames.
- `pkg/storage`, `pkg/settings`, `pkg/observability`, `pkg/secrets`,
  `pkg/permissions`, `pkg/stream`, `pkg/operation`,
  `pkg/installstage`, `pkg/retaineddata`, `pkg/cleanup`, and `pkg/security`
  provide memory and durable store implementations or shared lifecycle state.
- `pkg/protocol` tests keep OpenAPI, schemas, route fixtures, Go DTOs,
  TypeScript SDK bindings, Rust IPC, WASM ABI, and compatibility hashes aligned.

The Host library must remain host-neutral. It must not import a host product,
know product navigation, or assume a particular vault, filesystem root,
business resource, desktop shell, or UI surface.

## Rust Runtime

The Rust workspace contains `redevplugin-runtime` and support crates for IPC,
target classification, and WASM ABI validation. The runtime is launched by the
Go Host through `pkg/runtimeclient`.

The current IPC model is supervised stdin/stdout newline JSON. The Host remains
the authority for identity, policy, grants, quotas, revocation, storage, and
network access. The runtime validates WASM worker shape, executes the exported
worker entrypoint with Wasmi, and performs brokered hostcalls through Host-owned
IPC request/response frames.

The Go supervisor derives a bounded context for runtime-origin hostcalls before
entering host adapters. Storage SQLite and network execution use request
`timeout_ms` within the platform cap; artifact reads, handle-grant validation,
storage file/KV, and network grant minting use the default hostcall cap.
For `network_execute.operation = "http_stream"`, the supervisor registers a
Host-owned read stream with the worker invocation's surface/session audience,
streams bounded HTTP response chunks into `stream.Store`, closes or cancels the
stream, and returns response metadata plus `stream_id` over IPC. This is a
Host stream-store bridge for runtime-origin HTTP responses, not the Rust
hot-path persistent stream transport with credit, resume, or bidirectional flow
control.

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
channel ID, and handshake `connection_nonce` needed to mint a
`RuntimeExecutionLease` for the active process. When a host configures
`ProcessSupervisorOptions.RuntimeLeaseVerifier`, the supervisor requires a
worker lease to carry that exact audience before verifying the Ed25519
signature. The canonical signing payload excludes the bearer token and covers
the display token ID, plugin metadata, active package fingerprint, issued
timestamp, method, effect, execution mode, surface and owner context, target
descriptor hashes, quota limits, policy revisions, revoke epoch, expiry,
`lease_nonce`, `key_id`, and runtime audience fields. `MintRuntimeExecutionLease`
returns separate `lease_id` and display `token_id` values plus the same metadata,
and worker-route dispatch records a `plugin.runtime.lease.issued` Host audit
event without persisting the bearer lease token.
`ProcessSupervisorOptions.RuntimeLeasePublicKeys` sends the matching public keys
to Rust in the startup `hello` frame. A runtime that receives at least one key
verifies worker lease signatures before replay-cache consumption and before
artifact open; failures use `RUNTIME_LEASE_SIGNATURE_INVALID`.

Revocation uses `revoke_epoch` control frames. Successful `revoke_epoch_ack`
payloads return a structured result containing the plugin instance, revoke
epoch, and closed actor/socket/stream/storage-handle counters. The Rust runtime
maintains an in-process registry for worker actor entries, brokered storage
handles, network socket leases, and Host stream-store bridge stream IDs. A
revoke epoch removes the matching plugin resources from that registry and
  reports the actual close counts. Counters remain zero for resource classes
  that are purely Host-owned and therefore have no Rust-side handle to close.

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

Lazy assets are addressed across the worker boundary by opaque `binding_id`
values derived by the package builder and carried in the prepared surface
document. The parent-side HTTP request contains that binding rather than a
caller-selected path. The Go Host resolves the bound path and digest from the
prepared-document cache keyed by active fingerprint, entry path, and entry
digest, then revalidates path, size, content type, and package bytes before returning them to the trusted
renderer.

## Contracts

Machine-readable contracts are first-class platform artifacts:

- `spec/openapi/plugin-platform-v2.yaml`;
- `spec/plugin/manifest-v2.schema.json`;
- `spec/plugin/package-signature-v1.schema.json`;
- `spec/plugin/release-metadata-v2.schema.json`;
- `spec/plugin/source-policy-v1.schema.json`;
- `spec/plugin/source-revocations-v1.schema.json`;
- `spec/plugin/token-ticket-v2.schema.json`;
- `spec/plugin/bridge-v2.schema.json`;
- `spec/plugin/opaque-surface-document-v1.schema.json`;
- `spec/plugin/opaque-surface-transport-v1.schema.json`;
- `spec/plugin/compatibility-manifest-v2.schema.json`;
- `spec/plugin/release-manifest-v2.schema.json`;
- `spec/plugin/ipc-v1.schema.json`;
- `spec/plugin/wasm-worker-v1.schema.json`;
- `spec/plugin/worker-invocation-v1.schema.json`;
- `spec/plugin/network-grant-v1.schema.json`;
- `spec/plugin/error-codes-v1.schema.json`;
- `spec/plugin/target-classifier-v1.json`;
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

Manifest storage and settings migration metadata is part of that contract. A
bootstrap migration may use `from_version: 0`, but the manifest validator and
schema contract require each migration's `to_version` to match the active
settings or store `schema_version`, require monotonic version ranges, and reject
empty step hashes or negative estimates. Hosts can therefore detect migration
intent from the package manifest instead of inferring it from ad hoc product
logic. During update, the Host compares the installed settings/storage schema
versions to the target package and rejects a registry switch unless the target
manifest describes the exact current-to-target migration. During downgrade, the
Host validates the current version's migration descriptor and requires it to be
reversible before restoring the older version snapshot.

Archive import is also fail-closed on schema boundaries. Storage archive
namespaces must match the target store kind and schema version before the Host
applies the target namespace and quota, and settings archives must match the
target settings schema version before any values are imported into the target
field set.

## Runtime State Model

ReDevPlugin uses explicit stores instead of implicit process memory:

- registry records track installed plugin package and lifecycle state;
- staged install records capture pre-commit install/update progress;
- storage and settings stores keep plugin data and redacted settings state;
- secret binding stores track secret references without secret plaintext;
- permission and security policy stores drive authorization and revoke epochs;
- confirmation intent stores keep dangerous-method approval state without
  persisting raw confirmation token capabilities;
- operation and stream stores keep observable long-running work and buffered
  events;
- retained-data and cleanup stores make keep-data/delete-data outcomes auditable;
- observability stores persist audit and diagnostic events.

Operation cancellation is recorded before execution-side dispatch. The Host
marks the operation `cancel_requested`, writes audit evidence, then calls the
optional `OperationCanceler` adapter with the operation, plugin, method, surface,
bridge-channel, reason, and requested-at context. A missing adapter means the
Host has recorded the request but has no runtime/capability-specific cancel
hook. A failing adapter returns a dispatch error to the caller while preserving
the durable `cancel_requested` state for later retry or reconciliation.

Method result `data` is also normalized at the Host boundary. Capability,
worker, and core-action routes share the same `capability.DefaultResponseRedactionPolicy`
before data is returned through `CallPluginMethod` or the mountable HTTP adapter,
so product-owned adapters can rely on one platform response-safety pass for
common env, label, mount, token, password, credential, and secret fields.

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
