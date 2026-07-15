# Plugin Surface SDK

The TypeScript package `@floegence/redevplugin-ui` contains host-neutral UI
surface and SDK helpers for ReDevPlugin. It is published as an npm artifact and
must be consumed by host products through versioned package releases, not local
workspace or sibling path wiring.

## UI Roles

ReDevPlugin separates trusted host UI from untrusted plugin UI.

Trusted host UI may:

- call management APIs through `PluginPlatformClient`;
- mount `PluginSurfaceHost` inside product chrome;
- provide the authenticated parent-side surface transport and confirmation UI;
- show settings, permissions, retained data, operations, audit, diagnostics, and
  host-mediated intents;
- register product-specific session, origin, CSRF, and policy adapters on the
  Go Host side.

Plugin worker UI may:

- receive one opaque surface handle and a private `MessagePort`;
- render through typed virtual nodes and receive typed UI action events;
- invoke declared plugin methods through Host-mediated bridge/RPC paths;
- read parent-owned streams through opaque stream handles.

Sandboxed plugin UI must not receive host management credentials, parent-only
storage/network grants, raw vault secrets, runtime-control tokens, or unrelated
product session authority.

## Bridge Protocol

The bridge protocol is described by `spec/plugin/bridge-v3.schema.json` and
implemented by the TypeScript package. Contract checks keep these frame names,
the UI protocol version, and forbidden response fields aligned with the schema:

- `redevplugin.bridge.call`;
- `redevplugin.bridge.stream.read`;
- `redevplugin.ui.render`;
- `redevplugin.bridge.cancel`;
- `redevplugin.ui.action`;
- `redevplugin.bridge.response`;
- `redevplugin.bridge.lifecycle`;
- `plugin-ui-v3`.

The parent transfers one secret-free bootstrap port to the current iframe
`contentWindow` and frame generation. Because the iframe has an opaque origin,
this one transfer uses `postMessage("*")`; no token, plugin identity, or session
authority is present in that message. The renderer acknowledges the exact frame
generation with `redevplugin.surface.port_ack` over that port before the parent
may mint a gateway lease. All later traffic is port-bound and binds
the asset session, surface instance, bridge nonce, active fingerprint, owner and
session hashes, state version, and revoke epoch. `event.origin` is diagnostic
context, not an authorization input.

The trusted renderer transfers two ordered ports to the worker:
`runtime_control` remains private to the bootstrap runtime, while
`plugin_bridge` is the only port exposed through `PluginBridgeClient`. Request
ids are monotonically increasing per bridge, duplicate/replayed ids are rejected,
timeouts send one `redevplugin.bridge.cancel`, and late responses after cancel or
port close are ignored fail closed.

The trusted-parent SDK computes `handshake_transcript_sha256` before it asks the Go
Host for a parent-only `plugin_gateway_token`. The transcript is the SHA-256 of
a length-prefixed `redevplugin.bridge.handshake.v2` field list containing the
plugin ID, surface ID, surface instance ID, active fingerprint, bridge nonce,
asset-session nonce, plugin state version, revoke epoch, UI protocol version,
and `bridge_channel_id`. The Go Host recomputes the same hash and refuses to
mint a parent-only gateway token if the transcript is missing or mismatched.
This trusted-parent HTTP DTO is defined by OpenAPI, not by the plugin-visible
`bridge-v3.schema.json` contract.

## Management Client

`PluginPlatformClient` is for trusted host pages. It wraps platform management
routes exposed by `pkg/httpadapter`, including:

- compatibility manifest read;
- release-reference install/update for official or registry-backed product
  flows where the host page sends `PluginReleaseRef` rather than package bytes;
- downgrade, enable, disable, uninstall, and surface open;
- authenticated owner/session surface-scope revocation;
- runtime start, health, refresh-enabled, and stop;
- settings schema/read/patch;
- operation list/get/cancel;
- data export/import;
- permission grant/revoke/list;
- secret bind/test/delete;
- retained-data list/delete/bind;
- host-mediated intent list/invoke;
- audit and diagnostic event list.

`cancelOperation` is a trusted host-page command. It records
`cancel_requested` in the Host operation store and signals the live execution
lease that created the operation. That lease may carry a route-local
`OperationCanceler` captured from the capability adapter, core action, or
runtime supervisor. Inactive persisted operations are not looked up through a
global capability registry and are not redispatched; their durable cancel state
remains available through `getOperation` and `listOperations`.

Plugin workers import generated host capability clients from signed artifact
bundles. A generated client wraps `PluginBridgeClient`; it contains typed
request, response, operation, stream, and business-error validation, but no URL,
route, session, ticket, lease token, or host-product type. The matching bundle
pin and compatibility metadata are verified by the Host before installation.
Operation calls expose one opaque operation id. Subscription calls expose that
operation id plus one opaque stream handle; raw stream ids and tickets remain in
the trusted parent. Business-error guards narrow only when capability id,
capability version, details-schema SHA-256, error code, and details payload all
match the signed contract.

List helpers preserve the same data wrapper fields returned by the Go HTTP
adapter, such as `operations`, `permissions`, `audit_events`, and
`diagnostic_events`, so host pages can consume the SDK and raw HTTP contract
consistently.

Trusted product UI should not transport official `.redevplugin` package bytes
through browser state. For official or registry-backed installs, call
`installReleaseRef` or `updateReleaseRef`; the host-side resolver and Host
library perform artifact resolution, hash verification, trust assessment,
staged install/update, and registry mutation server-side.

Raw package import is intentionally not part of `PluginPlatformClient`. Explicit
local or developer import flows must opt into `PluginLocalImportClient` from
`@floegence/redevplugin-ui/local-import`, and hosts must only mount those routes
when local import is allowed for that product surface.

## Opaque Surface Host

`PluginSurfaceHost.create(...)` is the only public construction path. It creates
and owns a fresh iframe, hardens it before returning, and exposes the read-only
`element` only so trusted product chrome can mount it. The public options do not
accept an existing iframe or frame factory. The frame has explicit
`src="about:blank"`, exactly `sandbox="allow-scripts"`, an explicit Permissions
Policy deny-list, and `no-referrer`. The
iframe receives a unique opaque origin. It never navigates to a plugin origin,
Host origin, localhost URL, remote URL, or caller-created blob URL.

```ts
const surfaceHost = PluginSurfaceHost.create({
  bootstrap: toPluginSurfaceHostBootstrap(openedSurface),
  hostTransport: createReDevPluginSurfaceTransport(),
  confirm: showProductConfirmation,
});

surfaceHost.element.title = pluginSurfaceLabel;
surfaceMount.replaceChildren(surfaceHost.element);
await surfaceHost.open();
```

`loadTimeoutMs` is one aggregate opening deadline, not a fresh timeout for each
stage. It covers frame load, prepare, port acknowledgement, initial lease,
first paint, and worker readiness. Expiry returns `PLUGIN_BRIDGE_TIMEOUT`,
revokes the server surface, aborts parent requests, clears the iframe and ports,
and records one attempt in the supplied `PluginSurfaceReloadLimiter`. A new host
instance may retry within that limiter; a healthy open resets its state.

The trusted parent prepares the surface document and reads assets through
same-origin POST transport methods. The document contains validated static HTML,
nonce-bound external CSS content, one classic bundled worker, and opaque lazy
asset bindings. The renderer policy is generated from the bridge schema into
both Go and TypeScript, so package validation and browser rendering accept the
same tags, attributes, input types, and size/depth limits. Lazy image, font, and
media blobs are created inside the opaque frame; executable plugin code runs
only in the hardened Dedicated Worker. Asset sessions, tickets, gateway tokens,
stream tickets, and confirmation tokens never cross into plugin code.

The same policy owns interactive resource budgets. A surface may transfer four
canvases, each dimension is capped at 4096 pixels, aggregate canvas area is
16,777,216 pixels, and pointer movement is capped at 120 events per second.
Raster type and dimensions are read from PNG, JPEG, GIF, or WebP bytes before
decode, regardless of filename or declared MIME. A surface may decode 32 images
and 33,554,432 pixels in total. The plugin worker cannot construct an additional
`OffscreenCanvas` or call `createImageBitmap`.

Canvas plugins open a declared surface with `openCanvas(...)` and publish the
current semantic state with `updateCanvasAccessibility(...)`. The trusted
renderer binds the supplied label and description to the declared canvas only;
the worker cannot select another DOM node or inject markup. Games should keep
the label concise and include their current phase, score, remaining lives, and
FPS so keyboard and assistive-technology users receive the same operational
state that is drawn into the bitmap.

Forms use `data-redevplugin-action` on the form element. The renderer prevents
native sandbox submission, resolves nested content inside the clicked submit
button, and emits one `submit` action whose `form_data` contains at most 128
bounded string fields. Plugin UI should treat the action message as the only
submission path.

ARIA boolean attributes are serialized as explicit `true` or `false` values.
When a render tree contains one active `role="dialog"` with
`aria-modal="true"`, the trusted renderer keeps Tab and Shift+Tab focus within
that dialog. Plugin UI must still disable or remove background controls while
the modal is open and provide an autofocus target plus an Escape action so the
complete keyboard lifecycle remains deliberate.

Each lazy asset has an opaque, package-builder-derived `binding_id` in the
prepared document. The worker may request only that binding. `PluginSurfaceHost`
looks up the corresponding prepared asset and sends the parent-only HTTP request
with `binding_id`; it never forwards a worker-selected package path. The Go Host
resolves the path and digest from its prepared-document cache and rejects
missing, stale, or mismatched bindings before reading package bytes. It then
compares the registry path, size, and content type with adapter metadata, actual
byte length, and a recomputed SHA-256 on every read. Documents are limited to 128 lazy assets
and 32 MiB cumulative lazy bytes, and the renderer dispatches at most four reads
concurrently.

After closed-document validation, the Go Host marks the exact asset session
prepared. After the generation-bound port acknowledgement, the trusted parent
mints and applies the initial gateway and asset
lease before it sends `redevplugin.surface.initialize`. This ordering prevents
renderer asset reads from racing the server-side replacement of the prepared
asset session. Renewal scheduling starts only after first paint and worker
startup make the surface ready.

The Host renews a live surface lease before expiry by rotating both the
parent-held gateway token and asset session on the same bridge channel. Reads
wait for the current renewal, old credentials are revoked by the server, and a
renewal failure closes the surface rather than continuing with stale authority.

`close()` first sends a unique dispose quiesce request. `PluginBridgeClient`
awaits every async lifecycle observer before acknowledging, allowing plugins to
flush bounded persistence work. The trusted parent waits at most 1.5 seconds,
then proceeds with server revocation and local teardown. Separately, the
renderer pings the worker every 10 seconds and requires a pong within 5 seconds;
a missing acknowledgement closes the surface as a worker failure.

## Surface Reload Guard

Trusted host UI may automatically reload a sandbox iframe after a crash or load
failure, but it must not loop forever. `PluginSurfaceReloadLimiter` provides a
small host-side guard for that lifecycle. The default policy allows two reload
attempts within 30 seconds. When `recordCrash()` returns `allowed: false`, the
host should stop automatic reloads and show a host-owned error state with
diagnostics. `recordHealthyLoad()` resets the window after the host has observed
that the reloaded surface is healthy enough to treat the crash loop as cleared.

## Confirmation Plans

`PluginSurfaceHost` passes dangerous-method confirmation intents to the trusted
parent through the configured `confirm` callback. The callback receives the
server-issued confirmation id, request hash, plan hash, and host-redacted plan,
but never receives the raw confirmation token capability.

When the callback rejects, the SDK does not immediately synthesize a plugin
error. It first calls the parent-only, surface-scoped confirmation rejection
route with the current gateway and bridge binding. Only after the Host
atomically consumes the matching pending intent and records audit/diagnostic
evidence does the SDK return `PLUGIN_CONFIRMATION_REJECTED` to plugin code.
Wrong-surface, wrong-session, stale-revision, and replayed rejections fail
closed without dispatching the capability adapter.

When a capability preflight returns the host-neutral typed risk plan contract,
the SDK exposes it as `PluginRiskPlan` with `PluginRiskFlag` entries and the
`redevplugin.capability.risk_plan.v1` schema version. Host pages can use
`isPluginRiskPlan(intent.plan)` before rendering severity, admin requirement,
data-loss risk, destructive-operation markers, and redacted details. Legacy
generic preflight objects are still represented as ordinary records so existing
host pages remain compatible.

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

## Examples And Browser Harness Coverage

The user-facing Showcase under `examples/` exercises complete installable
plugins in realistic browser conditions. Platform-only security and contract
fixtures live separately under `internal/browserharness` and
`testdata/browser-harness`:

- the host page asks the SDK to create a fresh same-host opaque `srcdoc` iframe
  and mounts `surfaceHost.element` without a caller-provided frame, plugin
  server, subdomain, or cookie bootstrap;
- bridge handshake, typed rendering/actions, ordinary RPC, lifecycle messages,
  streams, confirmation, opening progress, and deterministic disposal are
  tested;
- sandbox security probes assert parent DOM/cookie/storage, localStorage,
  sessionStorage, IndexedDB, Cache API, Service Worker, direct fetch, WebSocket,
  nested Worker, dynamic import, eval, and Function constructors are blocked;
- the Examples smoke uses the Go Host library, HTTP adapter, Rust runtime,
  parent-only asset/stream transport, WASM workers, storage broker, and network
  broker end to end for persistent Memos, saved Weather locations and external
  HTTP, plus the Sky Strike canvas, images, input, animation, FPS display, and
  semantic canvas status;
- Memos presents a consumer notebook rather than a platform test surface: a
  grouped library, stale-safe instant search, pinning, a readable full-height
  editor, explicit save status, modal deletion with focus containment and
  failure recovery, and compact list/editor navigation all run through the same
  typed render and lifecycle contracts used by third-party plugins;
- compact-view acceptance rejects memo navigation while an autosave is failing,
  proves retry preserves the draft, verifies Weather retains the previous city
  until a replacement forecast succeeds, and enforces minimum touch targets;
- Memos uses a 24-row UI page and a 30-row worker hard limit. A real compiled
  WASM/ABI regression loads 61 pinned notes as 24, 24, and 13 rows, proving the
  Showcase does not rely on an unbounded library response;
- the opaque browser harness covers platform-only HTTP, WebSocket, TCP, UDP,
  stream, confirmation, lifecycle, and security probes without presenting
  those probes as a user example.

`npm run test:browser-harness:smoke` persists the A2 acceptance report and visual evidence
as `dist/a2-evidence/redevplugin-a2-acceptance.json`,
`redevplugin-a2-supported.png`, and `redevplugin-a2-unsupported.png`. CI uploads
the same files, and tagged releases checksum and sign them alongside runtime and
stress artifacts.

The Showcase is a host-neutral product-quality capability gallery, while the
browser harness is test infrastructure. Host products still own product
navigation, workbench layout, settings placement, activity bars, and branded UI
copy.

## Host Product Integration Guidance

Host products should:

1. import the published `@floegence/redevplugin-ui` package;
2. use the host-side client only from trusted product surfaces;
3. use `PluginSurfaceHost` for opaque iframe construction and bridge setup;
4. map ReDevPlugin state into product navigation and settings without forking
   bridge, token, package, or lifecycle protocols;
5. keep product-specific capability UI outside ReDevPlugin core unless it is a
   reusable platform component.
