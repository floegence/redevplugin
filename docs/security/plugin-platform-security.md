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
- shell/shebang scripts, native executable or dynamic-library artifacts, and
  package-manager install lifecycle scripts;
- package sizes and paths that exceed configured limits.

Validation errors expose stable platform error codes and structured
`error_details` such as reason, package path, and manifest JSON pointer. Product
UI should branch on the stable code/details rather than scraping localized
messages.

## Signatures And Trust

Detached package signatures live in `signatures/package.sig`. Signature metadata
is retained for trust verification but excluded from canonical package entries
and canonical package hashes, avoiding self-referential signatures.

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

Plugin gateway token validation failures use gateway-specific stable error
codes: `PLUGIN_GATEWAY_TOKEN_INVALID`, `PLUGIN_GATEWAY_TOKEN_REPLAYED`, and
`PLUGIN_GATEWAY_TOKEN_CHANNEL_MISMATCH`.

Sandbox bootstrap, package asset, and stream routes use token-specific stable
error codes when their credentials fail validation: `PLUGIN_ASSET_TICKET_INVALID`,
`PLUGIN_ASSET_SESSION_INVALID`, and `PLUGIN_STREAM_TICKET_INVALID`.

Stream responses set `Cache-Control: no-store` and
`Referrer-Policy: no-referrer` so `stream_ticket` query credentials are not
cached or forwarded through referrer headers.

Stream requests reject cross-site Fetch Metadata when browsers provide
`Sec-Fetch-*` headers. When a sandbox origin has been registered for the
surface, stream reads also bind the request `Origin` to that sandbox origin
before consuming the stream ticket.

## Permissions And Policy

The Host evaluates security policy before permission grants. Policy stores can
cap allowed permission IDs and deny method execution. Policy updates bump
revision and revoke epochs, refresh connectivity policy, and revoke runtime
capabilities.

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

## Network Access

Network access uses manifest-declared connector policies, target classification,
short-lived grants, and bounded Host executors. HTTP, WebSocket, TCP, and UDP
request paths revalidate transport, destination, grant expiry, target
classifier, request size, response size, and timeouts at execution time.

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
When the Rust runtime asks the Go supervisor to serve artifact, handle-grant,
storage, or network hostcalls, the supervisor derives a bounded context before
calling host adapters. Request-level `timeout_ms` controls storage SQLite and
network execution within a platform cap; hostcalls without an explicit timeout
use the default hostcall cap.

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
