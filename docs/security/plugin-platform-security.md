# ReDevPlugin Security Model

Third-party plugins are untrusted. ReDevPlugin treats every plugin package,
manifest, sandbox document, WASM module, storage request, network request,
stream, token, and generated plugin as untrusted input until it passes
host-controlled validation, policy, quota, lifecycle, and revocation checks.

## Trust Boundary

The Host library is the security authority. Plugin UI and WASM workers must not
self-report identity, permissions, routes, vault access, storage roots, network
targets, or runtime generation. The Host derives those values from installed
registry records, session adapters, policy stores, manifests, package hashes,
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
- external, root-absolute, missing, inline script/style, event handler,
  `srcdoc`, `base`, `meta refresh`, or Service Worker dependencies in sandbox UI
  HTML/assets;
- SVG or external surface icons; icons must be package-local raster assets;
- shell/shebang scripts, native executable or dynamic-library artifacts,
  package-manager install lifecycle scripts, package-manager dependency fields,
  Cargo `build.rs` / build scripts, proc-macro crates, native linker
  configuration, and Cargo dependency sections;
- package sizes and paths that exceed configured limits.

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
which publishers, keys, registries, local developer flows, bundled packages, or
enterprise policies are trusted. A management request's `trust_state` is a
requested outcome, not proof; runnable verified or bundled states require a
host-provided trust verifier.

## Sandbox UI Boundary

Plugin UI runs in sandboxed iframes through ReDevPlugin bootstrap, asset
ticket/session, and bridge protocols.

Sandbox asset responses include `Cache-Control: no-store`, restrictive CSP,
reporting, permissions, referrer, CORP, nosniff, and service-worker scope
headers. The Host supplies exact frame ancestors when embedding plugin surfaces.
Asset requests reject browser Fetch Metadata that explicitly marks the request
as cross-site.

Sandbox UI must not receive parent-only credentials such as asset tickets,
plugin gateway tokens, confirmation tokens, storage grants, network grants,
runtime-control tokens, or host management credentials. Browser bridge responses
are tested to avoid exposing these token classes.

## Bridge And Tokens

Bridge messages use exact target origins. Wildcard `postMessage` target origins
are forbidden in the TypeScript SDK checks.

Token and ticket kinds are described in `token-ticket-v1.schema.json`. Schema
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

`plugin_gateway_token` is minted only after the trusted parent validates the
iframe handshake and submits a `handshake_transcript_sha256` bound to the
handshake fields and `bridge_channel_id`. The Go Host recomputes that transcript
before minting, so a stale or cross-channel handshake cannot obtain a parent-only
gateway token by replaying the visible handshake object alone.

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
host-neutral closed-world contract: typed plans are normalized, validated, and
redacted before their `plan_hash` is computed, while legacy generic plan objects
without that schema version remain supported for compatibility.

Confirmation intents are stored through a Host-provided store with in-memory
and SQLite implementations. The store persists only intent metadata,
confirmation token id, request hash, plan hash, and expiry; it does not persist
the raw confirmation token capability. If a host process restarts with durable
intent metadata but without the matching in-memory token-manager record,
confirmation consumption fails closed.

Sandbox bootstrap, package asset, and stream routes use token-specific stable
error codes when their credentials fail validation: `PLUGIN_ASSET_TICKET_INVALID`,
`PLUGIN_ASSET_SESSION_INVALID`, and `PLUGIN_STREAM_TICKET_INVALID`.

Stream responses set `Cache-Control: no-store`, `Referrer-Policy:
no-referrer`, `X-Content-Type-Options: nosniff`, and
`Cross-Origin-Resource-Policy: same-origin` so `stream_ticket` query credentials
are not cached or forwarded through referrer headers, and stream bodies cannot
be reused as cross-origin subresources.

Stream requests reject cross-site Fetch Metadata when browsers provide
`Sec-Fetch-*` headers. The route only accepts same-origin `Sec-Fetch-Site`,
`cors` or `same-origin` `Sec-Fetch-Mode`, and an omitted or `empty`
`Sec-Fetch-Dest`, so navigation, iframe, script, and other subresource-shaped
requests fail closed. When a sandbox origin has been registered for the surface,
stream reads also bind the request `Origin` to that sandbox origin before
consuming the stream ticket.

## Permissions And Policy

The Host evaluates security policy before permission grants. Policy stores can
cap allowed permission IDs and deny method execution. Policy updates bump
revision and revoke epochs, refresh connectivity policy, and revoke runtime
capabilities. Runtime revocation ACKs are decoded as structured evidence, and
Host audit events include the closed actor/socket/stream/storage-handle counters
reported by the runtime.

Permission grants are lifecycle-bound. Uninstall removes grants even when plugin
data is retained, because authorization is tied to the active installed plugin
instance, not to retained user data.

## Storage, Settings, And Secrets

Storage access is brokered by the Host. Plugins do not receive arbitrary
filesystem roots. File, KV, SQLite, export, import, quota, namespace, and
retained-data operations go through Host APIs and stores.

Settings stores validate non-secret settings against the manifest schema. Secret
settings are redacted and must be changed through the secret lifecycle.

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
records a `plugin.runtime.lease.replayed` diagnostic. The stores do not persist
the raw lease token or raw nonce.
Hosts can additionally configure an Ed25519 runtime lease verifier on the Go
supervisor. The verifier checks a canonical `runtime_execution_lease` payload
that excludes the bearer `lease_token` and the signature itself, while covering
the display token ID, plugin metadata, active package fingerprint, issued
timestamp, worker method, effect, execution mode, surface and owner context,
descriptor hashes, quota limits, policy and management revisions, revoke epoch,
expiry, `lease_nonce`, `key_id`, and runtime audience. Before the signature
check, the supervisor requires the lease audience to match the current runtime
instance, IPC channel ID, and handshake `connection_nonce`. Rejected signatures
record `plugin.runtime.lease.signature_rejected` and fail before worker IPC or
artifact reads. Worker-route dispatch records `plugin.runtime.lease.issued` with
lease/token IDs, runtime IDs, revision bindings, descriptor hashes, and expiry
metadata; the cleartext bearer `lease_token` is never written to audit details.
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
an in-process registry for worker actor entries, brokered storage handles,
network socket leases, and Host stream-store bridge stream IDs; counters remain
zero for future Rust hot-path resource classes that do not yet have runtime-owned
handles.

Host/Rust IPC, WASM ABI, worker invocation, error-code, network grant, and
compatibility manifests are versioned contracts. Drift must fail closed through
tests, compatibility checks, or runtime diagnostics.

## CSP Reports And Diagnostics

The CSP report endpoint accepts only CSP/browser JSON content types, limits body
size and JSON depth, and applies per sandbox origin, active fingerprint, and
source IP rate limits before diagnostics are appended.

CSP reports are diagnostics. They are not management API calls and must not mint
tokens, change lifecycle state, grant permissions, or bypass authentication.

## Host Product Duties

Host products must:

- keep session, origin, CSRF, state root, vault, audit, diagnostics, runtime
  artifact, and business capability adapters explicit;
- verify compatibility manifests and release artifacts before upgrades;
- avoid local sibling dependency wiring;
- present policy decisions and confirmations through product UI without
  bypassing ReDevPlugin permission, token, lease, broker, audit, and lifecycle
  chains;
- keep product-specific capability implementations outside ReDevPlugin core.
