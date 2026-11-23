# Scoped Agent conversations

`pkg/agentconversation` publishes the `agent.conversation` capability and
`@floegence/redevplugin-ui/agent-conversation` provides the generated client and
framework-neutral author API. The host supplies the Agent engine, canonical
history, scoped business metadata and official view. ReDevPlugin supplies the
existing permission, confirmation, execution, stream and sandbox boundaries.
This capability does not depend on a particular model provider or Agent engine.

## Plugin author API

Declare the exact published contract pin and its methods in the plugin manifest,
then use the existing `PluginBridgeClient`:

`pkg/authorguide.Read("agent-conversation")` provides the version-bound guide,
exact binding and generated declaration for every published method. Add the
selected declarations to manifest `methods`; a capability binding, SDK import
or profile alone does not make any method callable. Profile `methods` selects
native Agent callbacks and is separate from manifest capability routes.

Trusted author tools can use `Host.InspectPluginCapabilities` to distinguish
`method_not_declared` from `permission_required`, policy denial and unavailable
adapters. It checks the installation's current canonical authorization snapshot
without creating conversations, dispatching adapters, or mutating grants.
`authoring.Environment.Inspect` binds the result to the exact applied artifact
and serializes it with Apply/Close. Do not turn a failed query into empty grants
or describe no admission blockers as a model/business verification result.

```ts
import { createAgentClient } from "@floegence/redevplugin-ui/agent-conversation";

const agents = createAgentClient(bridge, { capabilityBinding: "agent" });
const agent = await agents.openAgent("assistant"); // Role from agents.json
const conversation = await agent.conversations.open({ key: "main" }); // Typed plugin conversation for mount
const view = await agent.mount(container, conversation);
// Later: view.dispose() detaches presentation without stopping accepted work.
```

Use `bindAgent` with a revision for runtime-edited profiles. A custom UI uses
`conversation.send(text, { requestId })` and `conversation.watch({ signal })`.
Keep the request ID until its final result is resolved. An uncertain response
can be queried with `conversation.findSend(requestId).result()`;
neither the SDK nor the host may invent a replacement request and replay work.
Profiles request methods, skills, host tools and MCP connection slots. They do
not grant any resources. Method schemas come from the installed manifest.
Context methods must be read-only. Inline skill content is untrusted plugin
instruction, never a replacement for host policy. Connection configuration is
handled by the trusted host and returns references/status, never credentials.
`mcp_components` may declare Streamable HTTP connections or host-executed stdio
services with arguments and credential references. The host validates transport
shape, resolves secrets through its vault and requires explicit user admission
before starting a service. This does not introduce a native plugin backend,
install hook or alternative runtime. MCP tools, resources and prompts use the
host's existing connection manager and retain that component's lifecycle.

## Host ownership contract

The host binds each `object_key` and profile to the verified installation, user
and environment. Every returned binding and conversation ID is rechecked against
that owner on every request. Supplied IDs are references, never authority.
Opening a conversation is idempotent and does not launch a model turn. Binding
and conversation revisions use compare-and-set for updates/deletion. Conflicts
and unknown outcomes remain explicit; the SDK does not silently retry writes.
Rebinding an unchanged profile restores the binding; changing it requires
`expected_revision` and must not preserve grants for newly requested resources.

The host uses its existing canonical conversation engine. Plugin conversations,
forks, children, attachments, events and derived indexes must remain scoped to
their business binding. Ordinary chat lists, searches, direct reads and live
feeds cannot expose them. Deleting a binding uses the engine's formal lifecycle;
the host retains recoverable deletion intent before removing its metadata.
Uninstall, disable, upgrade, authorization changes and reconnect must revalidate
the actual plugin instance and current grants. A detached view is not a request
to cancel a turn. Background execution needs an explicit background grant.

`observe` emits public semantic events. `cursor` is an opaque host cursor;
`reset` asks the client to load a fresh snapshot when retention has expired.
Details must exclude credentials, unrelated conversations and private model
reasoning. Subscription cancellation only stops observation.

## Official views and complete host clients

Register `capability.Registration.View` with an immutable `NewViewBundle`.
`view.json` follows `spec/plugin/capability-view.schema.json`. The module exports
`mount({ container, bridge, input, signal })` and returns `{ dispose() }`.
The SDK mounts it in a ShadowRoot with the declared styles. Hosts must route
portals, focus handling and theme context into that root. Loading a view does
not execute a model or confer any method permission.

The platform serves only declared exact-pinned capabilities inside an admitted
plugin origin. Resources use the existing Web asset session and revocation
boundary. No management cookie, alternate gateway, remote module URL or relaxed
CSP is introduced. View bytes contain no user data or credentials.

`bind` negotiates `client_protocol` for the host's complete official UI.
`client.read`, `client.write`, `client.execute` and `client.delete` carry that
versioned protocol's operation name and JSON payload. The host maintains one
closed operation catalog with input/output schemas and an exact effect for each
operation. Unknown protocols, operations, mismatched effects and references
outside the binding are rejected before dispatch. These are not HTTP proxies,
arbitrary internal method dispatch or access to user-global settings. The
official view and the host's ordinary UI consume the same canonical operations.
`client.observe` observes only that binding's live projection. The outer stream
does not become another transcript or execution owner.

Authorization-sensitive operations are separate: `approve` and `configure`
require the platform's trusted, single-use confirmation bound to every request
field. The host confirmation handler displays the authoritative pending request
or configuration panel. A plugin-provided boolean or a generic `client.execute`
operation must never approve an action, grant tools, expose a credential or
change account settings. Configuration cancellation preserves the original
selection and draft. Hosts must publish and test their complete view feature
matrix; empty stubs do not constitute support.

Configuration may identify a conversation within the same binding and include
a host-protocol JSON proposal. This lets an embedded view open the exact model,
permission or computer-control editor without losing its draft. The proposal
is untrusted initial form data, not a grant or approved configuration. Both
optional fields participate in the confirmation hash; the host revalidates the
conversation's ownership and presents the actual choices before committing.

## Calling back into native plugin methods

A trusted capability adapter retains the exact platform-issued
`capability.ExecutionBinding` and calls `Host.InvokeCapabilityMethod` with the
current authenticated session and a selected native method. The adapter must
enforce its profile's method selection. `DescribeCapabilityMethods` resolves
that selection to copied native method schemas from the exact installed
manifest without granting execution. The platform checks the original
binding's expiry and revisions, current session/permissions/local policy,
request/response schemas, exact live surface channel, destination target,
confirmation and normal execution leases. Only worker and surface routes are
allowed; capability recursion and lifecycle-only methods are rejected. Mutating
callbacks require an execute source invocation and a writable session.

`PrepareCapabilityMethodConfirmation` prepares the existing native method
confirmation. Hosts show it in trusted UI and retain the same request, plan,
target and revision evidence for execution. They do not synthesize browser
gateway tokens or auto-approve the method because an Agent requested it. Worker
methods use their published runtime; surface methods require their exact live
receiver and never substitute another window after closure. Dispatched effects
with an uncertain result retain the existing `mutation.OutcomeUnknown` contract.

## Contract compatibility

Temporary conversations belong to the exact authenticated Web surface lifetime
provided on the invocation. This process-only context is not authority: validate
the current source and grants at admission, effects and delayed disclosure. Close
cancels that conversation and retires its opaque ID. `events.read` returns a
bounded page (or an empty heartbeat) before the RPC deadline. Temporary view and
event data must not use durable subscription records. Scope client requests by
conversation when mounting a temporary official view. A lost connection is not
confirmation of closure and must not cause an automatic replacement or replay.

New clients use Agent conversation contract 1.3.0. Hosts register every result of
`agentconversation.SupportedContracts()` with their same adapter and official view.
The 1.0.0 and 1.1.0 artifacts retain their exact published pins. For `agent.conversation.role.open`,
use `Host.ResolveDeclaredAgent` with the admitted Source. Package validation checks the
`agents.json` profiles against the existing profile schema. The role ID and optional
`object_key` identify the existing host binding. Revalidate the source when applying
the declaration; do not allow a retired package to overwrite current state. The host
owns user preferences, scoped permissions and conversation data independently of the package.

## External protocol processes

Trusted host configuration can use `Host.CallInstalledCapability` to dispatch an
exact installed capability method under the current session. The platform derives
its fresh source binding, target, quotas and grants; the product does not synthesize
an `ExecutionBinding` or borrow browser credentials to inspect a component. This
Go-only entry point rejects native routes and mandatory-confirmation methods. Host
products authorize their concrete settings action before using it and never expose
it to plugin JavaScript as an alternate bridge or background-authorization path.

A trusted capability adapter can call `Host.OpenCapabilityProcess` with its
original `ExecutionBinding` and `process.StartRequest`. Admission requires an
execute source, the current authenticated owner, an installed `process`
declaration, an explicit `process.local` grant and current local policy. The
adapter must first validate its selected component; component text is not a grant.
The returned stdin/stdout/stderr streams use the existing process supervisor,
secret resolver and resource ceilings. A byte-stream gap is an error, never
silently dropped protocol data. The platform caps live streams at four per
installation and 32 per Host, namespaces launch keys, retains original expiry,
rechecks authority before reads/writes, and closes processes on cancellation,
source-surface closure, revocation, expiry and Host shutdown. Closing is idempotent;
a lost launch response never authorizes an automatic replacement process.
This Go-only API adds no plugin HTTP route, native backend or Rust hostcall.

For remote components, `Host.OpenCapabilityHTTP` sends a single request through
an explicit installed connector. Agent component profiles can name that connector
with `connector_id`; a URL alone cannot select another plugin's network authority.
The trusted adapter enforces its reviewed component and operation before calling
this API. Admission independently requires `network.client`, the original execute
source and current owner. Fixed destinations and reviewed configurable targets,
HTTP methods, private-network admission, credentials and TLS stay under the existing
connection broker. Redirects are rejected without replay. Idle response bodies
close on source expiry, cancellation, revocation, surface closure and Host shutdown.
No process or network API treats component credentials or a profile declaration
as permission, or places credentials into the plugin's browser context.

`PluginBridgeClient.exportFile` also supports PDF, ZIP, JSON, CSV, Markdown,
HTML, Office files and opaque binary bytes, including empty files, within its
16 MiB transfer limit. Every export still requires a host-selected destination.
The host saves the bytes; a media label never permits execution or inline loading.
