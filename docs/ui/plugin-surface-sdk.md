# Plugin Surface SDK

The TypeScript package `@floegence/redevplugin-ui` contains host-neutral UI
surface and SDK helpers for ReDevPlugin. It is published as an npm artifact and
must be consumed by host products through versioned package releases, not local
workspace or sibling path wiring.

## UI Roles

ReDevPlugin separates trusted host UI from untrusted plugin UI.

Trusted host UI may:

- call management APIs through `PluginPlatformClient`;
- mount plugin surfaces inside product chrome;
- request asset tickets and create sandbox iframes;
- show settings, permissions, retained data, operations, audit, diagnostics, and
  host-mediated intents;
- register product-specific session, origin, CSRF, and policy adapters on the
  Go Host side.

Sandboxed plugin UI may:

- load packaged assets through asset-session routes;
- talk to the trusted parent through exact-origin bridge messages;
- invoke declared plugin methods through Host-mediated bridge/RPC paths;
- render plugin-owned UI state.

Sandboxed plugin UI must not receive host management credentials, parent-only
storage/network grants, raw vault secrets, runtime-control tokens, or unrelated
product session authority.

## Bridge Protocol

The bridge protocol is described by `spec/plugin/bridge-v1.schema.json` and
implemented by the TypeScript package. Contract checks keep these frame names,
the UI protocol version, and forbidden response fields aligned with the schema:

- `redevplugin.bridge.handshake`;
- `redevplugin.bridge.call`;
- `redevplugin.bridge.response`;
- `redevplugin.bridge.lifecycle`;
- `plugin-ui-v1`.

Bridge messaging requires exact target origins. Wildcard `postMessage`
target origins are forbidden. Parent-to-plugin and plugin-to-parent messages
must stay scoped to the sandbox origin and active surface session.

The trusted parent computes `handshake_transcript_sha256` before it asks the Go
Host for a parent-only `plugin_gateway_token`. The transcript is the SHA-256 of
a length-prefixed `redevplugin.bridge.handshake.v1` field list containing the
plugin ID, surface ID, surface instance ID, active fingerprint, bridge nonce,
UI protocol version, and `bridge_channel_id`. The Go Host recomputes the same
hash and refuses to mint a gateway token if the transcript is missing or
mismatched.

## Management Client

`PluginPlatformClient` is for trusted host pages. It wraps platform management
routes exposed by `pkg/httpadapter`, including:

- compatibility manifest read;
- install, update, downgrade, enable, disable, uninstall, and surface open;
- runtime start, health, refresh-enabled, and stop;
- settings schema/read/patch;
- operation list/get/cancel;
- data export/import;
- permission grant/revoke/list;
- secret bind/test/delete;
- retained-data list/delete/bind;
- host-mediated intent list/invoke;
- audit and diagnostic event list.

List helpers preserve the same data wrapper fields returned by the Go HTTP
adapter, such as `operations`, `permissions`, `audit_events`, and
`diagnostic_events`, so host pages can consume the SDK and raw HTTP contract
consistently.

## Surface Bootstrap And Assets

The Host issues asset tickets and asset sessions. Plugin iframes load packaged
HTML assets through sandbox asset routes and path-scoped HttpOnly asset-session
cookies. The browser smoke tests assert that plugin UI does not fall back to
legacy direct static paths.

Asset responses carry CSP, reporting, permissions, referrer, CORP, nosniff, and
service-worker scope headers. Host products provide exact `frame-ancestors`
values when embedding iframes.

## Surface Reload Guard

Trusted host UI may automatically reload a sandbox iframe after a crash or load
failure, but it must not loop forever. `PluginSurfaceReloadLimiter` provides a
small host-side guard for that lifecycle. The default policy allows two reload
attempts within 30 seconds. When `recordCrash()` returns `allowed: false`, the
host should stop automatic reloads and show a host-owned error state with
diagnostics. `recordHealthyLoad()` resets the window after the host has observed
that the reloaded surface is healthy enough to treat the crash loop as cleared.

## Settings And Intents

Settings helpers must preserve manifest validation and secret redaction:

- non-secret settings are validated against the manifest schema;
- secret settings are represented by redacted references and require secret
  lifecycle APIs to bind/test/delete;
- settings archives never restore secret plaintext or bound-secret state.

Host-mediated intents are invoked by trusted host UI, not by giving sandboxed
iframes management credentials. Intent execution still preserves local policy
evaluation, permission grants, audit events, and dangerous-method fail-closed
behavior.

## Browser Demo Coverage

The browser demo under `demo/browser/` exercises the surface SDK in realistic
browser conditions:

- host page and plugin iframe use separate localhost origins;
- bridge handshake, ordinary RPC, lifecycle messages, streams, confirmation, and
  richer plugin surfaces are tested;
- sandbox security probes check media capture policy and site-data cleanup for
  localStorage, IndexedDB, and Cache API;
- generated plugin flows scaffold, package, install, enable, open, disable, and
  uninstall a plugin through the dev lifecycle;
- real runtime smoke uses the Go Host library, HTTP adapter, Rust runtime,
  packaged assets, asset sessions, WASM workers, storage broker, and network
  broker end to end.

These demos are platform conformance checks for ReDevPlugin, not product UI
implementations. Host products still own product navigation, workbench layout,
settings placement, activity bars, and branded UI copy.

## Host Product Integration Guidance

Host products should:

1. import the published `@floegence/redevplugin-ui` package;
2. use the host-side client only from trusted product surfaces;
3. isolate plugin UI in sandboxed iframes with exact-origin bridge setup;
4. map ReDevPlugin state into product navigation and settings without forking
   bridge, token, package, or lifecycle protocols;
5. keep product-specific capability UI outside ReDevPlugin core unless it is a
   reusable platform component.
