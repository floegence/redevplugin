# Plugin Surface SDK

The released npm package @floegence/redevplugin-ui contains the host-neutral
surface container, plugin bridge, generated management client, and author test
helpers. Host products consume exact published versions.

## Ordinary Web Applications

A view is a package-local HTML document and its normal build output. The
manifest declares entry and web.root, with web.spa explicitly selecting an
HTML fallback for application routes. Scripts, styles, images, fonts, modules,
dynamic imports, browser Workers, Canvas, WebGL, and browser WASM use native
Web APIs. Any framework may own the application DOM and events. The platform
has no virtual-node renderer, custom JSX runtime, DOM patch transport, or
legacy rendering mode.

Keep the existing application build. Add a manifest and integrate the bridge
only where the application needs host context, a declared method, capability,
execution, file export, or lifecycle notification. Buttons, text input,
composition, selections, undo, drag, and drawing stay inside the application.
Framework-specific JSX compilers remain the application's own build tools.

The application must ship its executable resources inside the verified package.
The current browser policy permits self-origin requests only; arbitrary remote
fetch, WebSocket, frames, form navigation, and Service Workers are unavailable.
Network capabilities continue through declared platform methods and brokers.
This does not constitute support for authorized browser direct networking.

Native localStorage and IndexedDB belong to the lifetime-specific origin of
one container. They are caches, not the durable plugin data namespace. Data
that must survive reopening, another container, an upgrade, or reinstall must
use the platform storage contract through declared plugin methods. No platform
quota is claimed for native browser storage or GPU allocations.

## Trust And Origin Boundary

Each live container receives a fresh origin with a platform-generated random
hostname prefix. The origin must differ from the parent hostname. The host's
SurfaceOriginAdapter provides DNS/TLS routing and the authenticated parent
origin; the platform validates the allocation and owns the resource session.
Production origins require HTTPS; dedicated .localhost origins support local
development. Mount NewWebSurfaceHandler only on those application origins.
Never mount authenticated management routes on a child origin.

The frame starts as a restricted blank document. The allocated application
navigation enables allow-scripts, allow-same-origin, and allow-forms inside a
sandbox with a Permissions Policy deny-list and no-referrer. Same-origin here
means the application's own isolated origin; it never grants parent DOM access.
The bootstrap exchanges a single-use fragment token for a Secure, HttpOnly,
SameSite=None, Partitioned resource cookie. No management or gateway token
enters application JavaScript.

Before any plugin script executes, the trusted bootstrap performs successful
self requests around a rejected redirect to verify Connection-Allowlist
behavior. Missing browser enforcement fails with a readable unsupported
browser error. CSP alone is not represented as a complete outbound network
boundary. Browser and Desktop support must be verified with real network
receivers as well as this admission check.

The parent checks both event.source and the exact allocated event.origin,
binds the bootstrap document identity, transfers one secret-free MessagePort
to that origin, and waits for the current frame-generation acknowledgement.
Repeated readiness for the same document is ignored; an overlapping unfinished
navigation fails closed with a reopen diagnostic. Authorization also binds the surface, asset
session, bridge nonce, active fingerprint, owner/session hashes, management
revision, and revoke epoch. It never relies on an origin check alone.

## Bridge Contract

PluginBridgeClient from @floegence/redevplugin-ui/plugin claims one private
application port. It provides ready, call, execution observation/cancellation,
context, lifecycle, and file export. Request IDs are monotonically increasing;
replayed IDs fail closed. Timeouts cancel pending calls, and late responses
cannot revive a closed request. The application never receives the trusted
parent transport, gateway token, asset session, or confirmation token.

Plugin methods and generated capability clients retain the platform permission,
confirmation, audit, and Execution/Event pipeline. User actions and Agent
commands should call the application's existing document model and undo stack.
Embedding an application does not automatically expose its document operations
to an Agent; those operations require an explicit integration contract.

Bridge errors retain mutation_outcome. A transport failure after dispatch can
have an unknown outcome: reconcile through an authoritative read before
retrying a destructive write. File export invokes the host's authorization
callback for every request. Interaction observations do not authorize export.

Appearance and locale arrive through onContext. Applications own their theme
mapping, direction, and accessible controls. The examples consume the published
Floe standalone stylesheet, current soft-neumorphic material, and
flat/raised/inset/floating surface roles. They do not import a host shell.

## Management Client

`PluginPlatformClient` is for trusted host pages. It wraps platform management
routes exposed by `pkg/httpadapter`, including:

- platform identity and current plugin inventory read;
- release-reference install/update for official or registry-backed product
  flows where the host page sends `PluginReleaseRef` rather than package bytes;
- downgrade, enable, disable, uninstall, and surface open;
- authenticated owner/session surface-scope revocation;
- runtime start, health, recover-enabled, explicit recovery retry, and stop;
- settings schema/read/patch;
- execution list/get/cancel;
- data export/import;
- permission grant/revoke/list;
- secret bind/test/delete;
- retained-data list/delete/bind;
- host-mediated intent list/invoke;
- owner-scoped diagnostic event list.

`cancelExecution` is a trusted host-page command. It records
`cancel_requested` in the Host control database and signals the live execution
lease. That lease may carry a route-local cancel hook captured from the
capability adapter, core action, or runtime supervisor. Inactive persisted
executions are not looked up through a global capability registry and are not
redispatched; their durable cancel state remains available through
`getExecution` and `listExecutions`.

Plugin applications use clients generated from the closed local capability registry.
A generated client wraps `PluginBridgeClient`; it contains typed request,
response, Execution/Event, and business-error validation, but no URL, route,
session, ticket, runtime lease, or host-product type. The matching contract pin
is verified by the Host before installation. Every asynchronous call exposes
one opaque execution handle and reads ordered events by cursor; raw internal
transport handles remain in the trusted parent. Business-error guards narrow
only when capability id, capability version, details-schema SHA-256, error code,
and details payload all match the registered contract.

List helpers preserve the same data wrapper fields returned by the Go HTTP
adapter, such as `executions`, `permissions`, and `diagnostic_events`, so host
pages can consume the SDK and raw HTTP contract consistently. Audit events stay
behind the host's internal `AuditSink`; the generic HTTP adapter and TypeScript
client do not expose them.

Trusted product UI should not transport official `.redevplugin` package bytes
through browser state. For official or registry-backed installs, review the
market's display-ready install preview and pass its exact release reference and
declaration digests to `startReleaseInstallExecution`. The Host recomputes the
canonical release-reference identity digest, resolves the package once, and
verifies the displayed manifest and permission evidence before mutation. Updates
use `updateReleaseRef`; artifact resolution, hash verification, trust assessment,
staged install/update, and registry mutation stay server-side.

Raw package import is intentionally not part of `PluginPlatformClient`. Explicit
local or developer import flows must opt into `PluginLocalImportClient` from
`@floegence/redevplugin-ui/local-import`, and hosts must only mount those routes
when local import is allowed for that product surface.

## Surface Host And Lifecycle

PluginPlatformClient.openSurfaceInSlot is the only public opening path. Each
PluginSurfaceSlot owns one fresh iframe; simultaneous containers never share or
move a live iframe. Saved host layout and live surface authority have separate
lifetimes. The host may retain placement after invalidation and reconcile
inventory and permissions before opening a fresh surface.

The Go Host prepares a resource session. A trusted host that needs to establish
an authenticated route supplies prepareWebOrigin to openSurfaceInSlot. The SDK
awaits it before any child navigation, under the same aggregate opening deadline.
The frozen request contains only origin, parentOrigin, pluginInstanceId,
surfaceInstanceId, and a surface-lifetime AbortSignal. It exposes no resource
token or bootstrap URL and accepts no replacement URL. Hosts already routing all
allocated origins may omit this adapter.

The adapter must bind its route to the authenticated parent session and exact
allocated surface, using a product-owned authenticated endpoint. A top-level
login redirect or handoff page that forbids embedding is not a child routing
implementation. Keep parent credentials out of the child. Route setup must be
idempotent, bounded, and cancellation-aware; it must expire with its authenticated
session and release the exact route on signal abort. A late route response may
never reauthorize a closed surface. Product routing alone grants no plugin
resource access: the platform resource session and revocation remain decisive.
Adapter rejection, timeout, close, or invalidation leaves the frame blank and
revokes the platform surface. Opening diagnostics identify the origin milestone.
The same route serves in-application reloads; they do not allocate a second route.

After origin admission and the
source-bound port acknowledgement, the trusted parent mints the gateway lease
and sends initialization. The bootstrap fetches the verified HTML, preserves
its application URL, and loads the original document and module graph. Browser
resources use normal same-origin URLs; there is no Base64 asset bridge.
Every server read revalidates the current session and exact package entry,
metadata, byte length, and SHA-256. Missing resources are real errors. SPA
fallback applies only to document requests. Direct HTML resource reads and
Service Worker requests are rejected.

loadTimeoutMs is one aggregate deadline for preparation, entry admission, port
acknowledgement, lease issuance, and app_ready. Opening does not depend on a
paint, visible dimensions, or requestAnimationFrame. onOpeningProgress reports
bounded stage names, pending milestones, and monotonic elapsed times; errors
never include authority tokens or plugin document contents.

Lease renewal atomically rotates the parent gateway and asset session while
retaining the isolated resource-cookie binding. Failure invalidates the surface.
Use slot.requestClose() for a user-initiated close. PluginBridgeClient.onBeforeClose
may save through the same bridge and returns false when work remains unsaved.
The SDK bounds the decision, retains the page on rejection or timeout, and lets
the host confirm discarding work through confirmClose. The host signal aborts a
pending confirmation when authority is revoked. close()/dispose() are teardown
operations, not user-confirmation shortcuts; product close buttons must use
requestClose(). No-handler applications close without extra integration.

Close sends a unique dispose quiesce request; the plugin SDK waits for async
lifecycle observers, including bounded persistence, before acknowledging.
The parent waits at most 1.5 seconds before revocation and local teardown.
Forced security revocation cannot be vetoed by plugin code. An uncertain close
reconciles the exact single surface without revoking siblings.

A same-origin cross-document navigation and hard reload re-enter the trusted
loader, repeat network admission, and bind a fresh MessagePort and frame
generation. The parent cancels old requests, rejects late completions, and renews
the existing authoritative lease before loading the next document. Browser
storage remains available during this container lifetime. SPA fallback requires
web.spa=true; unknown static documents fail visibly. Hash/history navigation
stays native. Reconnection is bounded; expired or revoked surfaces cannot resume.

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
data-loss risk, destructive-operation markers, and redacted details. Preflight
payloads outside that closed contract are rejected before a confirmation intent
is exposed to the host page.

## Settings And Intents

Settings helpers must preserve manifest validation and secret redaction:

- non-secret settings are validated against the manifest schema;
- secret settings are represented by redacted references and require secret
  lifecycle APIs to bind/test/delete;
- PluginData bundles never include secret plaintext or secret binding metadata.

Host-mediated intents are invoked by trusted host UI, not by giving sandboxed
iframes management credentials. Intent execution still preserves local policy
evaluation, permission grants, audit events, and dangerous-method fail-closed
behavior.

## Acceptance And Integration

The real Go Host/HTTP browser fixture covers modules, dynamic imports, Workers,
Canvas pixels, WebGL, WASM, native input/undo/selection, IndexedDB, parent access
denial, HttpOnly cookies, independent containers, bounded asynchronous disposal,
and hidden/zero-size/offscreen/no-animation-frame opening. The unsupported
browser control removes network enforcement and asserts zero plugin execution.

The author workflow and Showcase additionally exercise the real Rust runtime,
WASM methods, storage, failed build retention, fresh-frame replacement, Memos
save/delete reconciliation, Weather persistence, and game input and rendering.
Browser fault fixtures distinguish intentional failures from unexpected errors.

npm run test:browser-harness:smoke writes web-acceptance.json and supported and
unsupported screenshots under dist/web-evidence, or REDEVPLUGIN_WEB_EVIDENCE_DIR.
The exact-main gate uses dist/web-pre-push. Evidence is local acceptance output,
not a published artifact. Do not label a Go/HTTP-only fixture as Rust evidence.

Host products import published Go/npm artifacts, register origin/session/policy
adapters, mount the platform handlers, and supply placement, confirmation, file
integration, Agent orchestration, and product copy. They must not duplicate the
loader, manifest parser, authorization lifecycle, or resource server. Backend
code in a plugin package still executes through the Rust WASM actor/job runtime;
ordinary Web support does not authorize native backend or postinstall execution.

## Deterministic Author Tests

The testing entrypoint exports createPluginTestClock. Pass its clock to
createPluginTestHarness or PluginBridgeClient to advance request deadlines
without sleeping or replacing global timers. The fixture always uses the
production bridge client. Cancelled/completed requests remove timers; time never
moves backward and timer loops are bounded. It does not certify Host policy,
WASM execution, native browser behavior, or security boundaries.

## Open And Save Existing Files

An ordinary application keeps its DOM, document model and undo stack. Use the
bridge files client only where the application accesses host files:

~~~ts
const resource = await bridge.files.select({ kind: "file", writable: true });
if (resource) {
  const file = await bridge.files.open(resource.uri, { read: true });
  try {
    // Consume bounded chunks into the application's existing document model.
    for (;;) {
      const { bytes, eof } = await file.read();
      consumeDocumentBytes(bytes);
      if (eof) break;
    }
  } finally {
    await file.close();
  }
}
~~~

Saving opens the approved URI with write and truncate when replacement is
intended, writes the application's encoded bytes, then syncs and closes. Preserve
the in-memory document until success. A truncate/write sequence is not atomic;
after an uncertain result inspect the file and let the user resolve it rather
than silently retrying. Single-file authority cannot create a sibling temporary
file for atomic rename. That operation requires explicit directory authority.

The trusted parent supplies confirmFileAccess when opening the surface slot.
It presents the verified name, file/directory kind, recursive scope, writable
status and expiry, then returns the user's decision. Without that handler,
selection is unavailable. The platform performs approval or cancellation; the
application never receives the review credential. A canceled selection resolves
to null. Product management uses selectFileResource, approveFileResource,
cancelFileResource, listFileResources and revokeFileResource on the published
PluginPlatformClient; these are authenticated host operations.

files also exposes stat, entries, mkdir, remove, rename and copy. File handles
expose read, write, seek, sync and close. Handles are individual to a surface and
survive the HTTP request that opened them; closing one surface leaves siblings
intact. URI/resource authority can be reused only within its current owner and
plugin binding. Bigint preserves file length and seek precision; wire handles
and offsets are canonical decimal strings. Reads and writes are bounded to
64 KiB chunks. Web directory pages accept at most 256 requested entries (the SDK
requests 128); Worker pages retain their 1000-entry ceiling. Both stop earlier
at 60 KiB encoded payload, retaining the next entry without loss or duplication.
Names and returned URIs use the platform's NFC normalization.

Browser-local imports and downloads remain ordinary Web interactions. They do
not grant access to environment files. The selected-file API and its management
contracts are defined by spec/plugin/file-resources.schema.json and OpenAPI.
