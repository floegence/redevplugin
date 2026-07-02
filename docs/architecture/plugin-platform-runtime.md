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
- sandbox bootstrap, asset tickets, asset sessions, bridge messages, operation
  and stream envelopes, and TypeScript SDK helpers;
- storage, settings, browser-site origin, observability, secret binding
  metadata, permission, cleanup, retained-data, and staged-install durable
  stores;
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

## Core Go Packages

The Go module `github.com/floegence/redevplugin` exposes the embeddable Host
library and platform contracts.

- `pkg/manifest` validates the plugin manifest model and cross-field
  references.
- `pkg/pluginpkg` reads and writes deterministic packages, validates package
  assets, rejects native backend artifacts, and exposes filesystem-backed asset
  storage.
- `pkg/host` coordinates lifecycle, permissions, policy, settings, storage,
  network grants, runtime execution, retained data, cleanup, audit, and
  diagnostics through host-provided adapters.
- `pkg/httpadapter` provides mountable host-neutral HTTP routes for platform
  management, sandbox bootstrap/assets, streams, CSP reports, compatibility, and
  diagnostics.
- `pkg/runtimeclient` manages the Rust runtime subprocess and newline-delimited
  JSON IPC frames.
- `pkg/storage`, `pkg/settings`, `pkg/browsersite`, `pkg/observability`,
  `pkg/secrets`, `pkg/permissions`, `pkg/stream`, `pkg/operation`,
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

The runtime contract is versioned by:

- `plugin_host_protocol_version`;
- `rust_ipc_version`;
- `wasm_abi_version`;
- `runtime_generation_id`, Host-issued IPC channel nonce, runtime lease nonce
  replay cache, and revoke epoch state;
- compatibility manifest contract hashes.

Any incompatible Host/runtime combination must fail closed with a diagnostic
error instead of silently running a plugin.

## TypeScript Surface Package

The package `@floegence/redevplugin-ui` provides sandbox iframe bridge helpers
and a host-side `PluginPlatformClient` for management routes. It is a released
npm artifact, not copied into host products through local paths.

The bridge package keeps parent-only credentials out of plugin UI responses. The
management client is for trusted host pages, while sandboxed plugin UI talks to
the parent through exact-origin bridge messages and short-lived token/session
routes issued by the Host.

## Contracts

Machine-readable contracts are first-class platform artifacts:

- `spec/openapi/plugin-platform-v1.yaml`;
- `spec/plugin/manifest-v1.schema.json`;
- `spec/plugin/package-signature-v1.schema.json`;
- `spec/plugin/token-ticket-v1.schema.json`;
- `spec/plugin/bridge-v1.schema.json`;
- `spec/plugin/compatibility-manifest-v1.schema.json`;
- `spec/plugin/release-manifest-v1.schema.json`;
- `spec/plugin/ipc-v1.schema.json`;
- `spec/plugin/wasm-worker-v1.schema.json`;
- `spec/plugin/worker-invocation-v1.schema.json`;
- `spec/plugin/network-grant-v1.schema.json`;
- `spec/plugin/error-codes-v1.schema.json`;
- `spec/plugin/target-classifier-v1.json`.

`redevplugin version` emits the compatibility manifest for the current artifact
set. `redevplugin verify-compatibility <compatibility.json> <artifact-root>`
checks the version matrix and contract hashes before a host product consumes a
published dependency set.

## Runtime State Model

ReDevPlugin uses explicit stores instead of implicit process memory:

- registry records track installed plugin package and lifecycle state;
- staged install records capture pre-commit install/update progress;
- storage and settings stores keep plugin data and redacted settings state;
- browser-site records track sandbox origin registration and cleanup status;
- secret binding stores track secret references without secret plaintext;
- permission and security policy stores drive authorization and revoke epochs;
- operation and stream stores keep observable long-running work and buffered
  events;
- retained-data and cleanup stores make keep-data/delete-data outcomes auditable;
- observability stores persist audit and diagnostic events.

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
